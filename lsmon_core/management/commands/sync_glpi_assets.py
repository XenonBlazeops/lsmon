from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from lsmon_core.glpi_sync import GlpiApiError, GlpiReadOnlyAdapter
from lsmon_core.glpi_sync_secrets import resolve_glpi_sync_credentials
from lsmon_core.models import Asset, AssetExternalIdentity, AssetNetworkInterface, AssetSoftware, InventoryConnector, InventorySyncRun, Tenant, TenantLocation
from lsmon_core.secret_store import SecretUnavailable


class Command(BaseCommand):
    help = "Preview or apply a tenant-scoped, read-only GLPI Computer import."

    def add_arguments(self, parser):
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--apply", action="store_true", help="Create or update LSMON records after a successful preview.")
        parser.add_argument("--limit", type=int, default=None, help="Maximum GLPI computers to read; useful for a controlled pilot.")
        parser.add_argument("--full", action="store_true", help="Also read detailed Computer fields and installed software (GET-only).")

    def handle(self, *args, **options):
        if options["limit"] is not None and options["limit"] < 1:
            raise CommandError("--limit must be at least 1")
        tenant = Tenant.objects.filter(slug=options["tenant_slug"], active=True).first()
        if not tenant:
            raise CommandError("Tenant was not found or is inactive.")
        connector = InventoryConnector.objects.filter(tenant=tenant, provider=InventoryConnector.Provider.GLPI).first()
        if not connector:
            raise CommandError("No GLPI connector is configured for this tenant.")
        run = InventorySyncRun.objects.create(connector=connector, status=InventorySyncRun.Status.FAILED)
        try:
            credentials = resolve_glpi_sync_credentials(connector.credential_reference)
            adapter = GlpiReadOnlyAdapter(connector.base_url, credentials)
            adapter.open()
            try:
                if options["full"]:
                    computers, software_by_computer = adapter.list_computers_full(limit=options["limit"])
                else:
                    computers, software_by_computer = adapter.list_computers(limit=options["limit"]), None
            finally:
                adapter.close()
        except (SecretUnavailable, GlpiApiError) as error:
            run.error_code = "credential_or_connection"
            run.summary = str(error)[:500]
            run.completed_at = timezone.now()
            run.save(update_fields=["error_code", "summary", "completed_at"])
            raise CommandError("GLPI preview could not be completed; review the separate sync-service credential and GLPI API access.") from error

        created = updated = review = 0
        if options["apply"]:
            with transaction.atomic():
                for computer in computers:
                    identity = AssetExternalIdentity.objects.select_related("asset").filter(
                        asset__tenant=tenant, source=AssetExternalIdentity.Source.GLPI, external_id=computer.external_id
                    ).first()
                    if identity:
                        if computer.name != identity.asset.name and Asset.objects.filter(tenant=tenant, name=computer.name).exclude(pk=identity.asset_id).exists():
                            review += 1
                            continue
                        asset, updated = self._update(identity.asset, computer, tenant), updated + 1
                        if software_by_computer is not None:
                            self._replace_software(asset, software_by_computer[computer.external_id])
                            self._replace_network_interfaces(asset, computer.network_interfaces)
                        identity.last_seen_at = timezone.now()
                        identity.reconciliation_state = "matched"
                        identity.save(update_fields=["last_seen_at", "reconciliation_state"])
                        continue
                    if Asset.objects.filter(tenant=tenant, name=computer.name).exists():
                        review += 1
                        continue
                    location = self._location(tenant, computer.location_name)
                    asset = Asset.objects.create(
                        tenant=tenant, name=computer.name, asset_type="Computer", status=computer.status,
                        serial_number=computer.serial_number, manufacturer=computer.manufacturer,
                        model=computer.model, operating_system=computer.operating_system,
                        primary_ip=computer.primary_ip or None, fqdn=computer.fqdn, location=location,
                        collection_method=Asset.CollectionMethod.GLPI_AGENT,
                    )
                    AssetExternalIdentity.objects.create(
                        asset=asset, source=AssetExternalIdentity.Source.GLPI, external_id=computer.external_id,
                        last_seen_at=timezone.now(), reconciliation_state="matched",
                    )
                    if software_by_computer is not None:
                        self._replace_software(asset, software_by_computer[computer.external_id])
                        self._replace_network_interfaces(asset, computer.network_interfaces)
                    created += 1
        else:
            existing_ids = set(AssetExternalIdentity.objects.filter(
                source=AssetExternalIdentity.Source.GLPI, asset__tenant=tenant
            ).values_list("external_id", flat=True))
            existing_names = set(Asset.objects.filter(tenant=tenant).values_list("name", flat=True))
            for computer in computers:
                if computer.external_id in existing_ids:
                    updated += 1
                elif computer.name in existing_names:
                    review += 1
                else:
                    created += 1

        run.status = InventorySyncRun.Status.APPLIED if options["apply"] else InventorySyncRun.Status.PREVIEW
        run.completed_at = timezone.now()
        run.discovered_count, run.created_count, run.updated_count, run.review_count = len(computers), created, updated, review
        run.summary = "Read-only GLPI Computer import" + (" with installed software." if options["full"] else ".") + " GLPI was not modified."
        run.save(update_fields=["status", "completed_at", "discovered_count", "created_count", "updated_count", "review_count", "summary"])
        mode = "APPLIED" if options["apply"] else "PREVIEW"
        self.stdout.write(f"GLPI_SYNC_{mode} tenant={tenant.slug} discovered={len(computers)} create={created} update={updated} review={review}")

    @staticmethod
    def _location(tenant, name):
        if not name:
            return None
        location, _ = TenantLocation.objects.get_or_create(tenant=tenant, name=name)
        return location

    def _update(self, asset, computer, tenant):
        asset.name = computer.name
        asset.asset_type = "Computer"
        asset.status = computer.status or asset.status
        asset.serial_number = computer.serial_number or asset.serial_number
        asset.manufacturer = computer.manufacturer or asset.manufacturer
        asset.model = computer.model or asset.model
        # GLPI omits several optional attributes for this connector.  Never
        # erase a portal value merely because a read-only response is blank.
        asset.operating_system = computer.operating_system or asset.operating_system
        asset.primary_ip = computer.primary_ip or asset.primary_ip
        asset.fqdn = computer.fqdn or asset.fqdn
        if computer.location_name:
            asset.location = self._location(tenant, computer.location_name)
        asset.collection_method = Asset.CollectionMethod.GLPI_AGENT
        asset.save(update_fields=["name", "asset_type", "status", "serial_number", "manufacturer", "model", "operating_system", "primary_ip", "fqdn", "location", "collection_method"])
        return asset

    @staticmethod
    def _replace_software(asset, software):
        # Rebuild only after every full-mode GET completed.  A source/API error
        # aborts the transaction above and retains the last known inventory.
        AssetSoftware.objects.filter(asset=asset, source=AssetSoftware.Source.GLPI).delete()
        AssetSoftware.objects.bulk_create([
            AssetSoftware(asset=asset, source=AssetSoftware.Source.GLPI, name=name, version=version)
            for name, version in software
        ])

    @staticmethod
    def _replace_network_interfaces(asset, interfaces):
        """Replace only completed full-read GLPI NIC observations for one asset."""
        AssetNetworkInterface.objects.filter(asset=asset, source=AssetNetworkInterface.Source.GLPI).delete()
        AssetNetworkInterface.objects.bulk_create([
            AssetNetworkInterface(
                asset=asset,
                source=AssetNetworkInterface.Source.GLPI,
                external_id=interface.external_id,
                name=interface.name,
                mac_address=interface.mac_address,
                network_name=interface.network_name,
                ip_addresses=list(interface.ip_addresses),
            )
            for interface in interfaces
        ])

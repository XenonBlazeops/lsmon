"""Verify one enrolled GLPI Computer reached the expected GLPI entity.

The command is deliberately diagnostic-only: it makes a single GET request to
GLPI and writes no GLPI, LSMON portal, sync-run, or audit record.
"""
from django.core.management.base import BaseCommand, CommandError

from lsmon_core.glpi_sync import GlpiApiError, GlpiReadOnlyAdapter
from lsmon_core.glpi_sync_secrets import resolve_glpi_sync_credentials
from lsmon_core.models import InventoryConnector, Tenant
from lsmon_core.secret_store import SecretUnavailable


class Command(BaseCommand):
    help = "Read-only verification that one GLPI Computer is assigned to the expected entity."

    def add_arguments(self, parser):
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--glpi-computer-id", required=True)
        parser.add_argument("--expected-entity", required=True)

    def handle(self, *args, **options):
        tenant = Tenant.objects.filter(slug=options["tenant_slug"], active=True).first()
        if not tenant:
            raise CommandError("Tenant was not found or is inactive.")
        connector = InventoryConnector.objects.filter(
            tenant=tenant, provider=InventoryConnector.Provider.GLPI,
        ).first()
        if not connector:
            raise CommandError("No GLPI connector is configured for this tenant.")

        computer_id = str(options["glpi_computer_id"]).strip()
        expected_entity = str(options["expected_entity"]).strip()
        if not computer_id or not expected_entity:
            raise CommandError("A GLPI Computer ID and expected entity are required.")

        try:
            adapter = GlpiReadOnlyAdapter(
                connector.base_url,
                resolve_glpi_sync_credentials(connector.credential_reference),
            )
            adapter.open()
            try:
                computer = adapter.get_computer(computer_id)
            finally:
                adapter.close()
        except (SecretUnavailable, GlpiApiError) as error:
            raise CommandError(
                "GLPI routing verification could not be completed; review the separate sync-service credential and GLPI API access."
            ) from error

        observed_entity = computer.entity_name
        if not observed_entity:
            raise CommandError(
                "GLPI did not return an entity label for this Computer; do not infer routing success."
            )
        if observed_entity.casefold() != expected_entity.casefold():
            raise CommandError(
                f"GLPI routing mismatch for Computer {computer.external_id}: expected {expected_entity!r}, observed {observed_entity!r}."
            )

        self.stdout.write(
            "GLPI_ROUTING_VERIFIED "
            f"tenant={tenant.slug} computer_id={computer.external_id} "
            f"computer_name={computer.name!r} entity={observed_entity!r}"
        )

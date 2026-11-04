"""Verify one tenant's worker prerequisites without provisioning an endpoint."""
from django.core.management.base import BaseCommand, CommandError

from lsmon_core.models import Tenant, TenantAgentProvisioning
from lsmon_core.provisioner import ProvisioningError, credential_bundle
from lsmon_core.secret_store import SecretUnavailable, resolve_secret


class Command(BaseCommand):
    help = "Verify a tenant's provisioner configuration and secret-bundle shape without contacting GLPI or processing jobs."

    def add_arguments(self, parser):
        parser.add_argument("--tenant-slug", required=True)

    def handle(self, *args, **options):
        tenant = Tenant.objects.filter(slug=options["tenant_slug"], active=True).first()
        if not tenant:
            raise CommandError("tenant_not_found_or_inactive")
        provisioning = TenantAgentProvisioning.objects.filter(tenant=tenant).first()
        if not provisioning or provisioning.status != TenantAgentProvisioning.Status.CONFIGURED:
            raise CommandError("tenant_not_configured")
        if not all((provisioning.glpi_inventory_url, provisioning.glpi_entity_scope, provisioning.credential_reference)):
            raise CommandError("tenant_provisioning_metadata_incomplete")
        try:
            credential_bundle(resolve_secret(provisioning.credential_reference))
        except (ProvisioningError, SecretUnavailable) as error:
            raise CommandError("credential_bundle_unavailable_or_invalid") from error
        self.stdout.write(f"PROVISIONING_PREREQUISITES_READY tenant={tenant.slug}")
        self.stdout.write("No GLPI request, package download, agent installation, or endpoint enrollment was performed.")

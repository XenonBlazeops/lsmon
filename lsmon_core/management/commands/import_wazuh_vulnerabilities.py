from django.core.management.base import BaseCommand, CommandError

from lsmon_core.models import SecurityConnector
from lsmon_core.wazuh_vulnerability_import import run


class Command(BaseCommand):
    help = "Perform a bounded, tenant-scoped, read-only Wazuh vulnerability import."

    def add_arguments(self, parser):
        parser.add_argument("--tenant-slug", required=True)
        parser.add_argument("--limit", type=int, default=750)

    def handle(self, *args, **options):
        if not 1 <= options["limit"] <= 750:
            raise CommandError("--limit must be between 1 and 750")
        connector = SecurityConnector.objects.filter(tenant__slug=options["tenant_slug"], provider=SecurityConnector.Provider.WAZUH).select_related("tenant").first()
        if connector is None:
            raise CommandError("Tenant Wazuh connector is not configured")
        result = run(connector, options["limit"])
        self.stdout.write(f"WAZUH_CVE_IMPORT status={result.status} created={result.created_count} updated={result.updated_count} skipped={result.skipped_count}")
        if result.status == result.Status.FAILED:
            raise CommandError(f"Wazuh vulnerability import unavailable: {result.error_code}")

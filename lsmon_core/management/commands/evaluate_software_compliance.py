from django.core.management.base import BaseCommand, CommandError

from lsmon_core.compliance import evaluate_tenant
from lsmon_core.models import AssetCompliance, ComplianceAuditEvent, Tenant


class Command(BaseCommand):
    help = "Evaluate tenant-owned software compliance using already imported inventory only."

    def add_arguments(self, parser):
        parser.add_argument("--tenant-slug", required=True)

    def handle(self, *args, **options):
        tenant = Tenant.objects.filter(slug=options["tenant_slug"], active=True).first()
        if not tenant:
            raise CommandError("Tenant was not found or is inactive.")
        results = evaluate_tenant(tenant)
        ComplianceAuditEvent.objects.create(
            tenant=tenant,
            action=ComplianceAuditEvent.Action.EVALUATED,
            summary=(f"{sum(results.values())} assets assessed; "
                     f"{results[AssetCompliance.Status.COMPLIANT]} compliant, "
                     f"{results[AssetCompliance.Status.NON_COMPLIANT]} non-compliant, "
                     f"{results[AssetCompliance.Status.UNKNOWN]} unknown."),
        )
        self.stdout.write(
            "SOFTWARE_COMPLIANCE_EVALUATED "
            f"tenant={tenant.slug} compliant={results['compliant']} "
            f"non_compliant={results['non_compliant']} unknown={results['unknown']}"
        )

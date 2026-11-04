"""Import an offline Greenbone XML report as tenant-scoped normalized findings."""
from pathlib import Path

from django.db import transaction
from django.utils import timezone

from lsmon_core.models import GreenboneAssessmentRun, SecurityFinding, Tenant


def _normalized_rows(xml_text: str, tenant_slug: str):
    from greenbone_report_sandbox_v1 import normalize
    return normalize(xml_text, tenant_slug)


def import_report(tenant_slug: str, report_path: str):
    tenant = Tenant.objects.get(slug=tenant_slug, active=True)
    report = Path(report_path)
    if not report.is_file():
        raise ValueError("report_unavailable")
    if report.stat().st_size > 25 * 1024 * 1024:
        raise ValueError("report_too_large")
    run = GreenboneAssessmentRun.objects.create(tenant=tenant)
    try:
        rows = _normalized_rows(report.read_text(encoding="utf-8"), tenant.slug)
        now = timezone.now()
        created = updated = 0
        with transaction.atomic():
            for row in rows:
                finding, was_created = SecurityFinding.objects.get_or_create(
                    tenant=tenant,
                    source=SecurityFinding.Source.GREENBONE,
                    source_id=row["source_id"],
                    defaults={
                        "title": row["title"], "description": "Normalized Greenbone/OpenVAS report finding.",
                        "cve_id": "", "control_id": row["control_id"], "severity": row["severity"],
                        "asset": None, "owner": "", "remediation_url": "",
                        "evidence_reference": "greenbone-report:" + row["control_id"],
                        "first_observed_at": now, "last_observed_at": now,
                    },
                )
                if was_created:
                    created += 1
                    continue
                finding.title = row["title"]
                finding.control_id = row["control_id"]
                finding.severity = row["severity"]
                finding.last_observed_at = now
                finding.save(update_fields=["title", "control_id", "severity", "last_observed_at", "updated_at"])
                updated += 1
            run.status = GreenboneAssessmentRun.Status.SUCCEEDED
            run.completed_at = timezone.now()
            run.finding_count = len(rows)
            run.created_count = created
            run.updated_count = updated
            run.save(update_fields=["status", "completed_at", "finding_count", "created_count", "updated_count"])
    except Exception:
        run.status = GreenboneAssessmentRun.Status.FAILED
        run.completed_at = timezone.now()
        run.error_code = "normalization_or_import_failed"
        run.save(update_fields=["status", "completed_at", "error_code"])
        raise
    return created, updated, len(rows)

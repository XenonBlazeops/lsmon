"""Tenant-scoped, source-read-only software compliance calculation."""
from django.db import transaction
from django.utils import timezone

from .models import Asset, AssetCompliance, SoftwareComplianceRule


def _patterns(value):
    return [part.strip().lower() for part in value.replace("\n", ",").split(",") if part.strip()]


def _applies(rule, asset):
    if rule.location_id and rule.location_id != asset.location_id:
        return False
    if rule.department_id and rule.department_id != asset.department_id:
        return False
    if rule.platform == SoftwareComplianceRule.Platform.ALL:
        return True
    os_name = (asset.operating_system or "").lower()
    if rule.platform == SoftwareComplianceRule.Platform.WINDOWS:
        return "windows" in os_name
    if rule.platform == SoftwareComplianceRule.Platform.MACOS:
        return "macos" in os_name or "mac os" in os_name or "os x" in os_name
    return any(token in os_name for token in ("linux", "ubuntu", "debian", "rocky", "alma", "red hat", "rhel"))


def evaluate_asset(asset, rules):
    software = list(asset.software.values_list("name", flat=True))
    if not rules or not software:
        return AssetCompliance.Status.UNKNOWN, [], [], []
    lowered = [(name, name.lower()) for name in software]
    missing, prohibited, unapproved = [], [], []
    for rule in rules:
        if not _applies(rule, asset):
            continue
        patterns = _patterns(rule.patterns)
        if not patterns:
            continue
        matches = [name for name, folded in lowered if any(pattern in folded for pattern in patterns)]
        if rule.rule_type == SoftwareComplianceRule.RuleType.REQUIRED and not matches:
            missing.append(rule.name)
        elif rule.rule_type == SoftwareComplianceRule.RuleType.PROHIBITED:
            prohibited.extend(f"{rule.name}: {name}" for name in matches)
        elif rule.rule_type == SoftwareComplianceRule.RuleType.ALLOWLIST:
            unapproved.extend(name for name, folded in lowered if not any(pattern in folded for pattern in patterns))
    status = AssetCompliance.Status.COMPLIANT if not (missing or prohibited or unapproved) else AssetCompliance.Status.NON_COMPLIANT
    return status, missing, prohibited, sorted(set(unapproved), key=str.lower)


@transaction.atomic
def evaluate_tenant(tenant):
    rules = list(SoftwareComplianceRule.objects.filter(tenant=tenant, active=True).select_related("location", "department"))
    results = {status: 0 for status in AssetCompliance.Status.values}
    for asset in Asset.objects.filter(tenant=tenant).select_related("location", "department"):
        status, missing, prohibited, unapproved = evaluate_asset(asset, rules)
        compliance, _ = AssetCompliance.objects.update_or_create(
            asset=asset,
            defaults={
                "status": status,
                "missing": ", ".join(missing),
                "prohibited": ", ".join(prohibited),
                "unapproved": ", ".join(unapproved),
                "checked_at": timezone.now(),
            },
        )
        results[compliance.status] += 1
    return results

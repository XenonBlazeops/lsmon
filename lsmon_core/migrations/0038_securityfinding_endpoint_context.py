from django.db import migrations, models


def backfill_endpoint_context(apps, schema_editor):
    Finding = apps.get_model("lsmon_core", "SecurityFinding")
    Asset = apps.get_model("lsmon_core", "Asset")
    for finding in Finding.objects.filter(source="wazuh"):
        host = ""
        if " on " in finding.title:
            host = finding.title.rsplit(" on ", 1)[1].strip()[:255]
        changed = []
        if host and not finding.observed_hostname:
            finding.observed_hostname = host
            changed.append("observed_hostname")
        if host and not finding.asset_id:
            asset = Asset.objects.filter(tenant_id=finding.tenant_id, name__iexact=host).only("id").first()
            if asset:
                finding.asset_id = asset.id
                changed.append("asset")
        if changed:
            finding.save(update_fields=changed)


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0036_greenbone_assessment_run")]

    operations = [
        migrations.AddField(
            model_name="securityfinding", name="observed_hostname",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="securityfinding", name="observed_ip",
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.RunPython(backfill_endpoint_context, migrations.RunPython.noop),
    ]

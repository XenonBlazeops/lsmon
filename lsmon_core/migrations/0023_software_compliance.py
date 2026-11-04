from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0022_asset_software")]

    operations = [
        migrations.CreateModel(
            name="AssetCompliance",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("status", models.CharField(choices=[("unknown", "Unknown"), ("compliant", "Compliant"), ("non_compliant", "Non-compliant")], default="unknown", max_length=20)),
                ("missing", models.TextField(blank=True)), ("prohibited", models.TextField(blank=True)),
                ("unapproved", models.TextField(blank=True)), ("checked_at", models.DateTimeField(blank=True, null=True)),
                ("asset", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="compliance", to="lsmon_core.asset")),
            ],
        ),
        migrations.CreateModel(
            name="SoftwareComplianceRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=160)),
                ("rule_type", models.CharField(choices=[("required", "Required software"), ("prohibited", "Prohibited software"), ("allowlist", "Allowed software only")], max_length=16)),
                ("patterns", models.TextField(help_text="Comma- or line-separated case-insensitive software-name matches.")),
                ("platform", models.CharField(choices=[("all", "Any platform"), ("windows", "Windows"), ("linux", "Linux"), ("macos", "macOS")], default="all", max_length=16)),
                ("active", models.BooleanField(default=True)), ("created_at", models.DateTimeField(auto_now_add=True)), ("updated_at", models.DateTimeField(auto_now=True)),
                ("department", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="lsmon_core.department")),
                ("location", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="lsmon_core.tenantlocation")),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="lsmon_core.tenant")),
            ],
            options={"ordering": ("name",)},
        ),
        migrations.AddConstraint(model_name="softwarecompliancerule", constraint=models.UniqueConstraint(fields=("tenant", "name"), name="unique_tenant_software_compliance_rule")),
    ]

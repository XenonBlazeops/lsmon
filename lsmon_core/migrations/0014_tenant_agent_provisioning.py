import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def create_existing_tenant_provisioning(apps, schema_editor):
    Tenant = apps.get_model("lsmon_core", "Tenant")
    TenantAgentProvisioning = apps.get_model("lsmon_core", "TenantAgentProvisioning")
    for tenant in Tenant.objects.all().iterator():
        TenantAgentProvisioning.objects.get_or_create(tenant=tenant, defaults={"inventory_tag": tenant.slug})


class Migration(migrations.Migration):
    dependencies = [
        ("lsmon_core", "0013_agent_registration_validation"),
    ]

    operations = [
        migrations.CreateModel(
            name="TenantAgentProvisioning",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("inventory_tag", models.SlugField(max_length=80)),
                ("glpi_inventory_url", models.URLField(blank=True, max_length=500)),
                ("glpi_entity_scope", models.CharField(blank=True, max_length=160)),
                ("credential_reference", models.CharField(blank=True, max_length=128)),
                ("status", models.CharField(choices=[("pending", "Pending provider provisioning"), ("configured", "Configuration references recorded"), ("active", "Active"), ("failed", "Failed")], default="pending", max_length=16)),
                ("configured_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("configured_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ("tenant", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to="lsmon_core.tenant")),
            ],
        ),
        migrations.RunPython(create_existing_tenant_provisioning, migrations.RunPython.noop),
    ]

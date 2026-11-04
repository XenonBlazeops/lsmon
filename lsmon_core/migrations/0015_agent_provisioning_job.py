import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("lsmon_core", "0014_tenant_agent_provisioning"),
    ]

    operations = [
        migrations.CreateModel(
            name="AgentProvisioningJob",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("status", models.CharField(choices=[("queued", "Queued for privileged provisioning"), ("running", "Privileged provisioning in progress"), ("delivered", "Configuration delivered"), ("failed", "Provisioning failed"), ("revoked", "Revoked before delivery")], default="queued", max_length=16)),
                ("attempt_count", models.PositiveSmallIntegerField(default=0)),
                ("last_error_code", models.CharField(blank=True, max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("delivered_at", models.DateTimeField(blank=True, null=True)),
                ("enrollment", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="provisioning_job", to="lsmon_core.agentenrollment")),
            ],
            options={"ordering": ("created_at",)},
        ),
    ]

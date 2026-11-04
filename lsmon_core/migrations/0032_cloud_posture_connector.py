from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0031_security_connector_vulnerability_reader")]

    operations = [
        migrations.CreateModel(
            name="CloudPostureConnector",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("provider", models.CharField(choices=[("aws", "AWS"), ("azure", "Microsoft Azure"), ("gcp", "Google Cloud"), ("third_party", "Third-party cloud")], max_length=16)),
                ("account_scope", models.CharField(max_length=160)),
                ("credential_reference", models.CharField(max_length=128)),
                ("read_only", models.BooleanField(default=True)),
                ("status", models.CharField(choices=[("draft", "Draft / secret not provisioned"), ("ready", "Read-only scope approved")], default="draft", max_length=16)),
                ("configured_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="cloud_posture_connectors", to="lsmon_core.tenant")),
            ],
            options={"ordering": ("provider", "account_scope")},
        ),
        migrations.AddConstraint(model_name="cloudpostureconnector", constraint=models.UniqueConstraint(fields=("tenant", "provider", "account_scope"), name="unique_tenant_cloud_posture_scope")),
    ]

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("lsmon_core", "0038_securityfinding_endpoint_context"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [
        migrations.CreateModel(
            name="WazuhEndpointAssetLink",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("hostname", models.CharField(max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("asset", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="wazuh_endpoint_links", to="lsmon_core.asset")),
                ("created_by", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="wazuh_endpoint_links_created", to=settings.AUTH_USER_MODEL)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="wazuh_endpoint_links", to="lsmon_core.tenant")),
            ],
            options={"ordering": ("hostname",)},
        ),
        migrations.AddConstraint(
            model_name="wazuhendpointassetlink",
            constraint=models.UniqueConstraint(fields=("tenant", "hostname"), name="unique_tenant_wazuh_endpoint_link"),
        ),
    ]

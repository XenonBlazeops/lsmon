from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0006_tenant_slug")]

    operations = [
        migrations.CreateModel(
            name="InventoryConnector",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("provider", models.CharField(choices=[("glpi", "Glpi")], max_length=16)),
                ("base_url", models.URLField(max_length=500)),
                ("credential_reference", models.CharField(max_length=128)),
                ("scope", models.CharField(blank=True, max_length=160)),
                ("configured_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="lsmon_core.tenant")),
            ],
        ),
        migrations.AddConstraint(
            model_name="inventoryconnector",
            constraint=models.UniqueConstraint(fields=("tenant", "provider"), name="unique_tenant_inventory_connector"),
        ),
    ]

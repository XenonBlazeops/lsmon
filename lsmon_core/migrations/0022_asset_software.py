# Generated for read-only GLPI installed-software inventory.
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0021_inventory_sync_run")]

    operations = [
        migrations.CreateModel(
            name="AssetSoftware",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source", models.CharField(choices=[("glpi", "GLPI")], max_length=16)),
                ("name", models.CharField(max_length=255)),
                ("version", models.CharField(blank=True, max_length=160)),
                ("observed_at", models.DateTimeField(auto_now=True)),
                ("asset", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="software", to="lsmon_core.asset")),
            ],
            options={"ordering": ("name", "version")},
        ),
        migrations.AddConstraint(
            model_name="assetsoftware",
            constraint=models.UniqueConstraint(fields=("asset", "source", "name", "version"), name="unique_asset_software_observation"),
        ),
    ]

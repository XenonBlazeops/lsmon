# Generated manually for the read-only GLPI Computer import audit trail.
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0020_asset_hierarchy")]

    operations = [
        migrations.RemoveConstraint(model_name="assetexternalidentity", name="unique_engine_identity"),
        migrations.AddConstraint(
            model_name="assetexternalidentity",
            constraint=models.UniqueConstraint(fields=("asset", "source", "external_id"), name="unique_asset_engine_identity"),
        ),
        migrations.CreateModel(
            name="InventorySyncRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("status", models.CharField(choices=[("preview", "Preview completed"), ("applied", "Import applied"), ("failed", "Failed")], max_length=16)),
                ("started_at", models.DateTimeField(auto_now_add=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("discovered_count", models.PositiveIntegerField(default=0)),
                ("created_count", models.PositiveIntegerField(default=0)),
                ("updated_count", models.PositiveIntegerField(default=0)),
                ("review_count", models.PositiveIntegerField(default=0)),
                ("error_code", models.CharField(blank=True, max_length=64)),
                ("summary", models.CharField(blank=True, max_length=500)),
                ("connector", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="lsmon_core.inventoryconnector")),
            ],
            options={"ordering": ("-started_at",)},
        ),
    ]

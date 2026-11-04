from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("lsmon_core", "0040_oidc_identity"),
    ]

    operations = [
        migrations.AlterField(
            model_name="membership",
            name="role",
            field=models.CharField(
                choices=[
                    ("global_admin", "Global Admin"),
                    ("tenant_admin", "Tenant Admin"),
                    ("noc_soc", "Noc Soc"),
                    ("viewer", "Viewer"),
                    ("platform_operations", "Platform Operations"),
                ],
                max_length=32,
            ),
        ),
    ]

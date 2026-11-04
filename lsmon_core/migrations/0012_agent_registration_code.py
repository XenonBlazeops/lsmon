from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("lsmon_core", "0011_agent_bootstrap_metadata"),
    ]

    operations = [
        migrations.AddField(
            model_name="agentenrollment",
            name="registration_code_hash",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="agentenrollment",
            name="registration_code_issued_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="agentenrollment",
            name="registration_code_used_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="agentenrollmentevent",
            name="event_type",
            field=models.CharField(choices=[("requested", "Requested"), ("approved", "Approved for provisioning"), ("bootstrap_ready", "Non-secret bootstrap prepared"), ("downloaded", "Bootstrap downloaded"), ("code_issued", "Registration code issued"), ("revoked", "Revoked")], max_length=16),
        ),
    ]

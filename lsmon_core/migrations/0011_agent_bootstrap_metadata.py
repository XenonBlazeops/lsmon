from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("lsmon_core", "0010_agent_enrollment_event"),
    ]

    operations = [
        migrations.AddField(
            model_name="agentenrollment",
            name="downloaded_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="agentenrollment",
            name="package_ready_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="agentenrollmentevent",
            name="event_type",
            field=models.CharField(choices=[("requested", "Requested"), ("approved", "Approved for provisioning"), ("bootstrap_ready", "Non-secret bootstrap prepared"), ("downloaded", "Bootstrap downloaded"), ("revoked", "Revoked")], max_length=16),
        ),
    ]

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("lsmon_core", "0012_agent_registration_code"),
    ]

    operations = [
        migrations.AddField(
            model_name="agentenrollment",
            name="registration_code_attempts",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="agentenrollment",
            name="registration_code_locked_until",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="agentenrollment",
            name="status",
            field=models.CharField(choices=[("requested", "Requested"), ("provisioning", "Provisioning"), ("ready", "Ready for download"), ("activating", "Registration validated"), ("enrolled", "First inventory received"), ("revoked", "Revoked"), ("expired", "Expired"), ("failed", "Failed")], default="requested", max_length=16),
        ),
        migrations.AlterField(
            model_name="agentenrollmentevent",
            name="event_type",
            field=models.CharField(choices=[("requested", "Requested"), ("approved", "Approved for provisioning"), ("bootstrap_ready", "Non-secret bootstrap prepared"), ("downloaded", "Bootstrap downloaded"), ("code_issued", "Registration code issued"), ("code_validated", "Registration code validated"), ("revoked", "Revoked")], max_length=16),
        ),
        migrations.CreateModel(
            name="AgentRegistrationValidation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("accepted", models.BooleanField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("enrollment", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="registration_validations", to="lsmon_core.agentenrollment")),
            ],
            options={"ordering": ("created_at",)},
        ),
    ]

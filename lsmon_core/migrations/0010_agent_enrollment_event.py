import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("lsmon_core", "0009_agent_enrollment"),
    ]

    operations = [
        migrations.CreateModel(
            name="AgentEnrollmentEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("event_type", models.CharField(choices=[("requested", "Requested"), ("approved", "Approved for provisioning"), ("revoked", "Revoked")], max_length=16)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("actor", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
                ("enrollment", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="events", to="lsmon_core.agentenrollment")),
            ],
            options={"ordering": ("created_at",)},
        ),
    ]

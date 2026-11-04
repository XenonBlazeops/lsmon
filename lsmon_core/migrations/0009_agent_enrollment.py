import uuid

import django.db.models.deletion
import lsmon_core.models
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("lsmon_core", "0008_asset_inventory_metadata"),
    ]

    operations = [
        migrations.CreateModel(
            name="AgentEnrollment",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("operating_system", models.CharField(choices=[("windows", "Windows"), ("linux", "Linux"), ("macos", "macOS")], max_length=16)),
                ("status", models.CharField(choices=[("requested", "Requested"), ("provisioning", "Provisioning"), ("ready", "Ready for download"), ("enrolled", "First inventory received"), ("revoked", "Revoked"), ("expired", "Expired"), ("failed", "Failed")], default="requested", max_length=16)),
                ("expires_at", models.DateTimeField(default=lsmon_core.models.default_enrollment_expiry)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("requested_by", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="lsmon_core.tenant")),
            ],
            options={"ordering": ("-created_at",)},
        ),
    ]

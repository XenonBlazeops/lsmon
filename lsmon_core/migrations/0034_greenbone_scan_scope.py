from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0033_cloud_posture_assessment_run"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [migrations.CreateModel(
        name="GreenboneScanScope",
        fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("target_reference", models.CharField(max_length=255)),
            ("authorization_reference", models.CharField(max_length=160)),
            ("maintenance_window_start", models.DateTimeField()),
            ("maintenance_window_end", models.DateTimeField()),
            ("status", models.CharField(choices=[("requested", "Requested"), ("approved", "Approved"), ("cancelled", "Cancelled")], default="requested", max_length=16)),
            ("created_at", models.DateTimeField(auto_now_add=True)),
            ("updated_at", models.DateTimeField(auto_now=True)),
            ("requested_by", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="greenbone_scan_scope_requests", to=settings.AUTH_USER_MODEL)),
            ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="greenbone_scan_scopes", to="lsmon_core.tenant")),
        ],
        options={"ordering": ("-created_at",)},
    )]

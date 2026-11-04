from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0035_greenbone_scan_scope_review")]
    operations = [migrations.CreateModel(
        name="GreenboneAssessmentRun",
        fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("status", models.CharField(choices=[("running", "Running"), ("succeeded", "Succeeded"), ("failed", "Failed")], default="running", max_length=16)),
            ("source_label", models.CharField(default="operator_report", max_length=32)),
            ("started_at", models.DateTimeField(auto_now_add=True)),
            ("completed_at", models.DateTimeField(blank=True, null=True)),
            ("finding_count", models.PositiveIntegerField(default=0)),
            ("created_count", models.PositiveIntegerField(default=0)),
            ("updated_count", models.PositiveIntegerField(default=0)),
            ("error_code", models.CharField(blank=True, max_length=64)),
            ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="greenbone_assessment_runs", to="lsmon_core.tenant")),
        ],
        options={"ordering": ("-started_at",)},
    )]

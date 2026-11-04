from django.db import migrations, models
import django.db.models.deletion

class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0032_cloud_posture_connector")]
    operations = [migrations.CreateModel(
        name="CloudPostureAssessmentRun",
        fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("status", models.CharField(choices=[("queued", "Queued"), ("running", "Running"), ("succeeded", "Succeeded"), ("failed", "Failed")], default="queued", max_length=16)),
            ("started_at", models.DateTimeField(auto_now_add=True)),
            ("completed_at", models.DateTimeField(blank=True, null=True)),
            ("finding_count", models.PositiveIntegerField(default=0)),
            ("error_code", models.CharField(blank=True, max_length=64)),
            ("connector", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="assessment_runs", to="lsmon_core.cloudpostureconnector")),
        ],
        options={"ordering": ("-started_at",)},
    )]

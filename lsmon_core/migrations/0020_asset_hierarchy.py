# Generated manually for tenant asset hierarchy.
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0019_windows_bootstrap_key")]

    operations = [
        migrations.CreateModel(
            name="Department",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=160)),
                ("code", models.CharField(blank=True, max_length=48)),
                ("active", models.BooleanField(default=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="lsmon_core.tenant")),
            ],
            options={"ordering": ("name",)},
        ),
        migrations.CreateModel(
            name="TenantLocation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=160)),
                ("code", models.CharField(blank=True, max_length=48)),
                ("active", models.BooleanField(default=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="lsmon_core.tenant")),
            ],
            options={"ordering": ("name",)},
        ),
        migrations.AddConstraint(model_name="department", constraint=models.UniqueConstraint(fields=("tenant", "name"), name="unique_tenant_department_name")),
        migrations.AddConstraint(model_name="tenantlocation", constraint=models.UniqueConstraint(fields=("tenant", "name"), name="unique_tenant_location_name")),
        migrations.AddField(model_name="asset", name="assigned_to", field=models.CharField(blank=True, max_length=160)),
        migrations.AddField(model_name="asset", name="manufacturer", field=models.CharField(blank=True, max_length=160)),
        migrations.AddField(model_name="asset", name="model", field=models.CharField(blank=True, max_length=160)),
        migrations.AddField(model_name="asset", name="serial_number", field=models.CharField(blank=True, max_length=160)),
        migrations.AddField(model_name="asset", name="department", field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="lsmon_core.department")),
        migrations.AddField(model_name="asset", name="location", field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="lsmon_core.tenantlocation")),
    ]

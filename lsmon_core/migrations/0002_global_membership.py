from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0001_initial")]

    operations = [
        migrations.RemoveConstraint(
            model_name="membership", name="unique_tenant_membership"
        ),
        migrations.AlterField(
            model_name="membership",
            name="tenant",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to="lsmon_core.tenant"),
        ),
        migrations.AddConstraint(
            model_name="membership",
            constraint=models.UniqueConstraint(condition=models.Q(("tenant__isnull", False)), fields=("tenant", "user"), name="unique_tenant_membership"),
        ),
        migrations.AddConstraint(
            model_name="membership",
            constraint=models.UniqueConstraint(condition=models.Q(("role", "global_admin"), ("tenant__isnull", True)), fields=("user", "role"), name="unique_global_admin_membership"),
        ),
    ]

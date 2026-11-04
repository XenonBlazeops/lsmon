from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0016_agent_provisioning_delivery_binding")]

    operations = [
        migrations.AddField(
            model_name="agentprovisioningjob",
            name="sealed_configuration",
            field=models.TextField(blank=True),
        ),
    ]

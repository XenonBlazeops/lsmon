from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("lsmon_core", "0015_agent_provisioning_job"),
    ]

    operations = [
        migrations.AddField(
            model_name="agentprovisioningjob",
            name="delivery_expires_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="agentprovisioningjob",
            name="delivery_token_hash",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="agentprovisioningjob",
            name="endpoint_public_key",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="agentprovisioningjob",
            name="endpoint_public_key_fingerprint",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="agentprovisioningjob",
            name="downloaded_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]

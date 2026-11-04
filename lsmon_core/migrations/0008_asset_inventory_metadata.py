from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0007_inventory_connector")]

    operations = [
        migrations.AddField(model_name="asset", name="collection_method", field=models.CharField(choices=[("manual", "Manual register"), ("glpi_agent", "GLPI Agent"), ("glpi_snmp", "GLPI SNMP discovery"), ("zabbix", "Zabbix"), ("wazuh", "Wazuh")], default="manual", max_length=32)),
        migrations.AddField(model_name="asset", name="fqdn", field=models.CharField(blank=True, max_length=255)),
        migrations.AddField(model_name="asset", name="operating_system", field=models.CharField(blank=True, max_length=160)),
        migrations.AddField(model_name="asset", name="primary_ip", field=models.GenericIPAddressField(blank=True, null=True)),
        migrations.AddField(model_name="asset", name="site", field=models.CharField(blank=True, max_length=160)),
    ]

from django.db import migrations, models
from django.utils.text import slugify


def populate_slugs(apps, schema_editor):
    Tenant = apps.get_model("lsmon_core", "Tenant")
    used = set()
    for tenant in Tenant.objects.order_by("name"):
        base = slugify(tenant.name)[:72] or "tenant"
        candidate, suffix = base, 2
        while candidate in used or Tenant.objects.exclude(pk=tenant.pk).filter(slug=candidate).exists():
            candidate = f"{base[:72-len(str(suffix))]}-{suffix}"
            suffix += 1
        tenant.slug = candidate
        tenant.save(update_fields=["slug"])
        used.add(candidate)


class Migration(migrations.Migration):
    dependencies = [("lsmon_core", "0005_invitation_delivery")]
    operations = [
        # SlugField creates a PostgreSQL pattern-operations index.  Starting
        # with a plain CharField avoids creating that index twice when the
        # later AlterField adds the final unique SlugField.
        migrations.AddField(model_name="tenant", name="slug", field=models.CharField(blank=True, max_length=80, null=True)),
        migrations.RunPython(populate_slugs, migrations.RunPython.noop),
        migrations.AlterField(model_name="tenant", name="slug", field=models.SlugField(max_length=80, unique=True)),
    ]

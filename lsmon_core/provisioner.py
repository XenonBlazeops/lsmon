"""Privileged queue processing helpers. Never call from a portal view."""
import json
from django.utils import timezone

from .envelope import seal_configuration
from .models import AgentProvisioningJob, TenantAgentProvisioning
from .secret_store import resolve_secret
from .zabbix_api import ZabbixProvisioningError, provision_active_agent


class ProvisioningError(Exception):
    pass


def credential_bundle(value):
    try:
        bundle = json.loads(value)
    except (TypeError, ValueError) as error:
        raise ProvisioningError("credential_bundle_invalid") from error
    if set(bundle) != {"client_id", "client_secret"} or not all(isinstance(bundle[key], str) and bundle[key] for key in bundle):
        raise ProvisioningError("credential_bundle_invalid")
    return bundle


def provision_job(job):
    """Seal tenant-scoped agent settings for one queued job; returns no plaintext."""
    if job.status != AgentProvisioningJob.Status.QUEUED:
        raise ProvisioningError("job_not_queued")
    if not job.delivery_expires_at or job.delivery_expires_at <= timezone.now():
        raise ProvisioningError("delivery_expired")
    if job.enrollment.package.vendor == "zabbix":
        try:
            configuration = provision_active_agent(job.enrollment)
        except ZabbixProvisioningError as error:
            raise ProvisioningError(str(error)) from error
        job.sealed_configuration = seal_configuration(job.endpoint_public_key, configuration, context=str(job.enrollment_id), algorithm=job.endpoint_key_algorithm)
        job.status = AgentProvisioningJob.Status.DELIVERED
        job.attempt_count += 1
        job.delivered_at = timezone.now()
        job.last_error_code = ""
        job.save(update_fields=["sealed_configuration", "status", "attempt_count", "delivered_at", "last_error_code", "updated_at"])
        return job
    provisioning = TenantAgentProvisioning.objects.get(tenant=job.enrollment.tenant)
    if provisioning.status != TenantAgentProvisioning.Status.CONFIGURED or not all((
        provisioning.glpi_inventory_url, provisioning.glpi_entity_scope, provisioning.credential_reference,
    )):
        raise ProvisioningError("tenant_not_configured")
    bundle = credential_bundle(resolve_secret(provisioning.credential_reference))
    configuration = {
        "server": provisioning.glpi_inventory_url,
        "tag": provisioning.inventory_tag,
        "tasks": ["Inventory"],
        "no_httpd": True,
        "no_p2p": True,
        "oauth_client_id": bundle["client_id"],
        "oauth_client_secret": bundle["client_secret"],
    }
    job.sealed_configuration = seal_configuration(job.endpoint_public_key, configuration, context=str(job.enrollment_id), algorithm=job.endpoint_key_algorithm)
    job.status = AgentProvisioningJob.Status.DELIVERED
    job.attempt_count += 1
    job.delivered_at = timezone.now()
    job.last_error_code = ""
    job.save(update_fields=["sealed_configuration", "status", "attempt_count", "delivered_at", "last_error_code", "updated_at"])
    return job

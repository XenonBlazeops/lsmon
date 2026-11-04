import uuid
from datetime import timedelta
from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.text import slugify


def default_invitation_expiry():
    return timezone.now() + timedelta(days=7)


def default_enrollment_expiry():
    return timezone.now() + timedelta(hours=24)

class Tenant(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=160, unique=True)
    slug = models.SlugField(max_length=80, unique=True)
    active = models.BooleanField(default=True)


class TenantLocation(models.Model):
    """A customer-owned physical or logical location for asset reporting."""
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    name = models.CharField(max_length=160)
    code = models.CharField(max_length=48, blank=True)
    active = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("tenant", "name"), name="unique_tenant_location_name")]
        ordering = ("name",)

    def __str__(self):
        return self.name


class Department(models.Model):
    """A customer-owned department for asset ownership and policy scope."""
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    name = models.CharField(max_length=160)
    code = models.CharField(max_length=48, blank=True)
    active = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("tenant", "name"), name="unique_tenant_department_name")]
        ordering = ("name",)

    def __str__(self):
        return self.name


def unique_tenant_slug(name):
    base = slugify(name)[:72] or "tenant"
    candidate, suffix = base, 2
    while Tenant.objects.filter(slug=candidate).exists():
        candidate = f"{base[:72-len(str(suffix))]}-{suffix}"
        suffix += 1
    return candidate

class Membership(models.Model):
    class Role(models.TextChoices):
        GLOBAL_ADMIN = "global_admin"
        TENANT_ADMIN = "tenant_admin"
        NOC_SOC = "noc_soc"
        VIEWER = "viewer"
        PLATFORM_OPERATIONS = "platform_operations"
    # A Global Admin membership is platform-wide and therefore has no tenant.
    # Every other role must be tied to precisely one tenant.
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, null=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=32, choices=Role.choices)

    def clean(self):
        from django.core.exceptions import ValidationError
        # platform-admin-rbac-v1
        platform_roles = (self.Role.GLOBAL_ADMIN, self.Role.PLATFORM_OPERATIONS)
        if self.role in platform_roles and self.tenant_id is not None:
            raise ValidationError("Platform-wide roles cannot be tenant-scoped.")
        if self.role not in platform_roles and self.tenant_id is None:
            raise ValidationError("Tenant roles require a tenant.")

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("tenant", "user"),
                condition=models.Q(tenant__isnull=False),
                name="unique_tenant_membership",
            ),
            models.UniqueConstraint(
                fields=("user", "role"),
                condition=models.Q(tenant__isnull=True, role="global_admin"),
                name="unique_global_admin_membership",
            ),
        ]

class Asset(models.Model):
    class CollectionMethod(models.TextChoices):
        MANUAL = "manual", "Manual register"
        GLPI_AGENT = "glpi_agent", "GLPI Agent"
        GLPI_SNMP = "glpi_snmp", "GLPI SNMP discovery"
        ZABBIX = "zabbix", "Zabbix"
        WAZUH = "wazuh", "Wazuh"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT)
    name = models.CharField(max_length=160)
    asset_type = models.CharField(max_length=48)
    status = models.CharField(max_length=32, default="unknown")
    primary_ip = models.GenericIPAddressField(null=True, blank=True)
    fqdn = models.CharField(max_length=255, blank=True)
    operating_system = models.CharField(max_length=160, blank=True)
    site = models.CharField(max_length=160, blank=True)
    location = models.ForeignKey(TenantLocation, on_delete=models.SET_NULL, null=True, blank=True)
    assigned_location = models.ForeignKey(TenantLocation, on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_assets")
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True)
    business_unit = models.CharField(max_length=160, blank=True)
    assigned_to = models.CharField(max_length=160, blank=True)
    local_ip = models.GenericIPAddressField(null=True, blank=True)
    serial_number = models.CharField(max_length=160, blank=True)
    manufacturer = models.CharField(max_length=160, blank=True)
    model = models.CharField(max_length=160, blank=True)
    collection_method = models.CharField(max_length=32, choices=CollectionMethod.choices, default=CollectionMethod.MANUAL)
    class Meta:
        constraints = [models.UniqueConstraint(fields=("tenant", "name"), name="unique_tenant_asset_name")]

class AssetExternalIdentity(models.Model):
    class Source(models.TextChoices):
        GLPI = "glpi"
        ZABBIX = "zabbix"
        WAZUH = "wazuh"
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE)
    source = models.CharField(max_length=16, choices=Source.choices)
    external_id = models.CharField(max_length=255)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    reconciliation_state = models.CharField(max_length=32, default="pending")
    class Meta:
        # External numeric IDs are only meaningful within a customer's source
        # system.  They must never be used to reconcile across tenants.
        constraints = [models.UniqueConstraint(fields=("asset", "source", "external_id"), name="unique_asset_engine_identity")]


class AssetNetworkInterface(models.Model):
    """Read-only network-interface observations from an inventory source."""
    class Source(models.TextChoices):
        GLPI = "glpi", "GLPI"

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="network_interfaces")
    source = models.CharField(max_length=16, choices=Source.choices)
    external_id = models.CharField(max_length=255)
    name = models.CharField(max_length=255, blank=True)
    mac_address = models.CharField(max_length=32, blank=True)
    network_name = models.CharField(max_length=255, blank=True)
    ip_addresses = models.JSONField(default=list)
    observed_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("asset", "source", "external_id"),
                name="unique_asset_network_interface_observation",
            ),
        ]
        ordering = ("name", "mac_address")


class AssetSoftware(models.Model):
    """Software observed by a read-only inventory source for one asset."""
    class Source(models.TextChoices):
        GLPI = "glpi", "GLPI"

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="software")
    source = models.CharField(max_length=16, choices=Source.choices)
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=160, blank=True)
    observed_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("asset", "source", "name", "version"),
                name="unique_asset_software_observation",
            ),
        ]
        ordering = ("name", "version")


class SoftwareComplianceRule(models.Model):
    """A tenant-owned software criterion; it never changes endpoint software."""
    class RuleType(models.TextChoices):
        REQUIRED = "required", "Required software"
        PROHIBITED = "prohibited", "Prohibited software"
        ALLOWLIST = "allowlist", "Allowed software only"

    class Platform(models.TextChoices):
        ALL = "all", "Any platform"
        WINDOWS = "windows", "Windows"
        LINUX = "linux", "Linux"
        MACOS = "macos", "macOS"

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    name = models.CharField(max_length=160)
    rule_type = models.CharField(max_length=16, choices=RuleType.choices)
    patterns = models.TextField(help_text="Comma- or line-separated case-insensitive software-name matches.")
    platform = models.CharField(max_length=16, choices=Platform.choices, default=Platform.ALL)
    location = models.ForeignKey(TenantLocation, on_delete=models.SET_NULL, null=True, blank=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("tenant", "name"), name="unique_tenant_software_compliance_rule")]
        ordering = ("name",)

    def __str__(self):
        return self.name


class AssetCompliance(models.Model):
    class Status(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        COMPLIANT = "compliant", "Compliant"
        NON_COMPLIANT = "non_compliant", "Non-compliant"

    asset = models.OneToOneField(Asset, on_delete=models.CASCADE, related_name="compliance")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.UNKNOWN)
    missing = models.TextField(blank=True)
    prohibited = models.TextField(blank=True)
    unapproved = models.TextField(blank=True)
    checked_at = models.DateTimeField(null=True, blank=True)


class ComplianceAuditEvent(models.Model):
    """Tenant-scoped, secret-free record of portal compliance policy activity."""
    class Action(models.TextChoices):
        CREATED = "created", "Criterion created"
        UPDATED = "updated", "Criterion updated"
        DELETED = "deleted", "Criterion deleted"
        EVALUATED = "evaluated", "Compliance recalculated"

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=16, choices=Action.choices)
    criterion_name = models.CharField(max_length=160, blank=True)
    summary = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)


class InventoryConnector(models.Model):
    """Tenant inventory source configuration; credentials remain outside the database."""
    class Provider(models.TextChoices):
        GLPI = "glpi"

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    provider = models.CharField(max_length=16, choices=Provider.choices)
    base_url = models.URLField(max_length=500)
    credential_reference = models.CharField(max_length=128)
    scope = models.CharField(max_length=160, blank=True)
    configured_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("tenant", "provider"), name="unique_tenant_inventory_connector"),
        ]


class SecurityConnector(models.Model):
    """Tenant security-source configuration; credentials remain outside Django."""
    class Provider(models.TextChoices):
        WAZUH = "wazuh", "Wazuh"

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    provider = models.CharField(max_length=16, choices=Provider.choices, default=Provider.WAZUH)
    base_url = models.URLField(max_length=500)
    credential_reference = models.CharField(max_length=128)
    scope = models.CharField(max_length=160, blank=True)
    # These are provider-managed only. A tenant administrator can configure the
    # Wazuh API group scope but cannot supply an indexer location or credential.
    # The indexer identity must itself enforce document-level tenant isolation.
    findings_base_url = models.URLField(max_length=500, blank=True)
    findings_credential_reference = models.CharField(max_length=128, blank=True)
    # Vulnerability data is deliberately isolated from the alert-count reader.
    # Its Indexer identity is expected to enforce tenant agent-ID DLS.
    vulnerability_base_url = models.URLField(max_length=500, blank=True)
    vulnerability_credential_reference = models.CharField(max_length=128, blank=True)
    configured_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("tenant", "provider"), name="unique_tenant_security_connector"),
        ]


class SecurityFinding(models.Model):
    """A normalized, tenant-owned risk record; never a raw scanner event."""
    class Source(models.TextChoices):
        WAZUH = "wazuh", "Wazuh"
        PROWLER = "prowler", "Prowler"
        GREENBONE = "greenbone", "Greenbone"
        TRIVY = "trivy", "Trivy"
        MANUAL = "manual", "Provider review"

    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        INFORMATIONAL = "informational", "Informational"

    class Status(models.TextChoices):
        DETECTED = "detected", "Detected"
        TRIAGED = "triaged", "Triaged"
        APPROVED = "approved", "Approved"
        SCHEDULED = "scheduled", "Scheduled"
        REMEDIATED = "remediated", "Remediated"
        AWAITING_VERIFICATION = "awaiting_verification", "Awaiting verification"
        VERIFIED_CLOSED = "verified_closed", "Verified closed"
        ACCEPTED_EXCEPTION = "accepted_exception", "Accepted exception"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="security_findings")
    asset = models.ForeignKey(Asset, on_delete=models.SET_NULL, null=True, blank=True, related_name="security_findings")
    source = models.CharField(max_length=16, choices=Source.choices)
    source_id = models.CharField(max_length=255)
    title = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    cve_id = models.CharField(max_length=32, blank=True)
    control_id = models.CharField(max_length=160, blank=True)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.DETECTED)
    owner = models.CharField(max_length=160, blank=True)
    remediation_url = models.URLField(max_length=500, blank=True)
    evidence_reference = models.CharField(max_length=500, blank=True)
    observed_hostname = models.CharField(max_length=255, blank=True)
    observed_ip = models.GenericIPAddressField(null=True, blank=True)
    first_observed_at = models.DateTimeField()
    last_observed_at = models.DateTimeField()
    due_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("tenant", "source", "source_id"), name="unique_tenant_security_finding_source"),
        ]
        ordering = ("severity", "due_at", "-last_observed_at")

    def clean(self):
        from django.core.exceptions import ValidationError
        if self.asset_id and self.asset.tenant_id != self.tenant_id:
            raise ValidationError("A finding asset must belong to the same tenant.")
        if self.status == self.Status.VERIFIED_CLOSED and not self.evidence_reference:
            raise ValidationError("Verified closure requires a safe evidence reference.")

class VulnerabilityImportRun(models.Model):
    """Safe audit status for a bounded, read-only vulnerability import."""
    class Status(models.TextChoices):
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="vulnerability_import_runs")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.SUCCEEDED)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_count = models.PositiveIntegerField(default=0)
    updated_count = models.PositiveIntegerField(default=0)
    skipped_count = models.PositiveIntegerField(default=0)
    error_code = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ("-started_at",)


class FindingRemediation(models.Model):
    """Approval and execution metadata only; automation secrets and commands stay elsewhere."""
    class Status(models.TextChoices):
        PROPOSED = "proposed", "Proposed"
        APPROVED = "approved", "Approved"
        SCHEDULED = "scheduled", "Scheduled"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    finding = models.ForeignKey(SecurityFinding, on_delete=models.CASCADE, related_name="remediations")
    summary = models.CharField(max_length=500)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PROPOSED)
    requested_by = models.CharField(max_length=160, blank=True)
    approved_by = models.CharField(max_length=160, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    maintenance_window = models.CharField(max_length=255, blank=True)
    execution_reference = models.CharField(max_length=500, blank=True)
    rollback_reference = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)


class FindingException(models.Model):
    """A time-bounded risk acceptance; it is not a closure outcome."""
    finding = models.OneToOneField(SecurityFinding, on_delete=models.CASCADE, related_name="exception")
    justification = models.TextField()
    compensating_control = models.TextField()
    owner = models.CharField(max_length=160)
    expires_at = models.DateTimeField()
    approved_by = models.CharField(max_length=160)
    approved_at = models.DateTimeField(auto_now_add=True)


class FindingAuditEvent(models.Model):
    """Tenant-scoped, secret-free event history for the customer-safe workflow."""
    class Action(models.TextChoices):
        CREATED = "created", "Finding created"
        UPDATED = "updated", "Finding updated"
        REMEDIATION_RECORDED = "remediation_recorded", "Remediation recorded"
        EXCEPTION_RECORDED = "exception_recorded", "Exception recorded"
        VERIFIED_CLOSED = "verified_closed", "Verified closed"

    finding = models.ForeignKey(SecurityFinding, on_delete=models.CASCADE, related_name="audit_events")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=32, choices=Action.choices)
    summary = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)


class InventorySyncRun(models.Model):
    """Auditable, read-only-source import attempt; it never stores credentials."""
    class Status(models.TextChoices):
        PREVIEW = "preview", "Preview completed"
        APPLIED = "applied", "Import applied"
        FAILED = "failed", "Failed"

    connector = models.ForeignKey(InventoryConnector, on_delete=models.CASCADE)
    status = models.CharField(max_length=16, choices=Status.choices)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    discovered_count = models.PositiveIntegerField(default=0)
    created_count = models.PositiveIntegerField(default=0)
    updated_count = models.PositiveIntegerField(default=0)
    review_count = models.PositiveIntegerField(default=0)
    error_code = models.CharField(max_length=64, blank=True)
    # A brief operator-safe summary only; never a response body or a credential.
    summary = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ("-started_at",)


class TenantAgentProvisioning(models.Model):
    """Provider-managed, non-secret prerequisites for tenant agent enrollment."""
    class Status(models.TextChoices):
        PENDING = "pending", "Pending provider provisioning"
        CONFIGURED = "configured", "Configuration references recorded"
        ACTIVE = "active", "Active"
        FAILED = "failed", "Failed"

    tenant = models.OneToOneField(Tenant, on_delete=models.CASCADE)
    inventory_tag = models.SlugField(max_length=80)
    glpi_inventory_url = models.URLField(max_length=500, blank=True)
    glpi_entity_scope = models.CharField(max_length=160, blank=True)
    credential_reference = models.CharField(max_length=128, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    configured_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    configured_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)


class AgentPackage(models.Model):
    """Provider-approved vendor package metadata; the binary is never stored in the portal."""
    class Vendor(models.TextChoices):
        GLPI = "glpi", "GLPI Agent"
        WAZUH = "wazuh", "Wazuh Agent"
        ZABBIX = "zabbix", "Zabbix Agent"

    class OperatingSystem(models.TextChoices):
        WINDOWS = "windows", "Windows"
        LINUX = "linux", "Linux"
        MACOS = "macos", "macOS"

    class Status(models.TextChoices):
        DRAFT = "draft", "Draft / lab validation"
        APPROVED = "approved", "Approved for tenant download"
        RETIRED = "retired", "Retired"

    vendor = models.CharField(max_length=16, choices=Vendor.choices)
    operating_system = models.CharField(max_length=16, choices=OperatingSystem.choices)
    version = models.CharField(max_length=80)
    source_url = models.URLField(max_length=500)
    filename = models.CharField(max_length=255)
    sha256 = models.CharField(max_length=64)
    expected_publisher = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.DRAFT)
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=("vendor", "operating_system", "version"), name="unique_agent_package_release"),
        ]
        ordering = ("vendor", "operating_system", "-created_at")

    def __str__(self):
        return f"{self.get_vendor_display()} — {self.get_operating_system_display()} — {self.version}"


class MFAProfile(models.Model):
    """Encrypted, per-user TOTP enrollment state; never expose this value in APIs."""
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    secret_ciphertext = models.TextField(blank=True)
    enrolled_at = models.DateTimeField(null=True, blank=True)
    last_verified_at = models.DateTimeField(null=True, blank=True)

    @property
    def is_enrolled(self):
        return bool(self.secret_ciphertext and self.enrolled_at)


class TenantAdminInvitation(models.Model):
    """Email delivery is deliberately separate from creation of an invitation."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    email = models.EmailField()
    # Assigned only at verified-delivery time. A pending invitation has no usable link.
    token_hash = models.CharField(max_length=128, unique=True, blank=True, null=True)
    expires_at = models.DateTimeField(default=default_invitation_expiry)
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("tenant", "email"),
                condition=models.Q(accepted_at__isnull=True, revoked_at__isnull=True),
                name="one_active_tenant_admin_invitation",
            )
        ]


class AgentEnrollment(models.Model):
    """Tenant-scoped enrollment request only; this foundation creates no package or secret."""
    class OperatingSystem(models.TextChoices):
        WINDOWS = "windows", "Windows"
        LINUX = "linux", "Linux"
        MACOS = "macos", "macOS"

    class Status(models.TextChoices):
        REQUESTED = "requested", "Requested"
        PROVISIONING = "provisioning", "Provisioning"
        READY = "ready", "Ready for download"
        ACTIVATING = "activating", "Registration validated"
        ENROLLED = "enrolled", "First inventory received"
        REVOKED = "revoked", "Revoked"
        EXPIRED = "expired", "Expired"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    package = models.ForeignKey(AgentPackage, on_delete=models.PROTECT, null=True, blank=True)
    operating_system = models.CharField(max_length=16, choices=OperatingSystem.choices)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.REQUESTED)
    expires_at = models.DateTimeField(default=default_enrollment_expiry)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    package_ready_at = models.DateTimeField(null=True, blank=True)
    downloaded_at = models.DateTimeField(null=True, blank=True)
    registration_code_hash = models.CharField(max_length=64, blank=True)
    registration_code_issued_at = models.DateTimeField(null=True, blank=True)
    registration_code_used_at = models.DateTimeField(null=True, blank=True)
    registration_code_attempts = models.PositiveSmallIntegerField(default=0)
    registration_code_locked_until = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)


class AgentEnrollmentEvent(models.Model):
    """Append-only, secret-safe lifecycle evidence for an enrollment request."""
    class EventType(models.TextChoices):
        REQUESTED = "requested", "Requested"
        APPROVED = "approved", "Approved for provisioning"
        BOOTSTRAP_READY = "bootstrap_ready", "Non-secret bootstrap prepared"
        DOWNLOADED = "downloaded", "Bootstrap downloaded"
        CODE_ISSUED = "code_issued", "Registration code issued"
        CODE_VALIDATED = "code_validated", "Registration code validated"
        REVOKED = "revoked", "Revoked"

    enrollment = models.ForeignKey(AgentEnrollment, on_delete=models.CASCADE, related_name="events")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    event_type = models.CharField(max_length=16, choices=EventType.choices)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("created_at",)


class AgentRegistrationValidation(models.Model):
    """Secret-free record of installer registration-code validation attempts."""
    enrollment = models.ForeignKey(AgentEnrollment, on_delete=models.CASCADE, related_name="registration_validations")
    accepted = models.BooleanField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("created_at",)


class AgentProvisioningJob(models.Model):
    """A secret-free hand-off from the public registration endpoint to a future privileged worker."""
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued for privileged provisioning"
        RUNNING = "running", "Privileged provisioning in progress"
        DELIVERED = "delivered", "Configuration delivered"
        FAILED = "failed", "Provisioning failed"
        REVOKED = "revoked", "Revoked before delivery"

    enrollment = models.OneToOneField(AgentEnrollment, on_delete=models.CASCADE, related_name="provisioning_job")
    endpoint_public_key = models.CharField(max_length=2048, blank=True)
    endpoint_key_algorithm = models.CharField(max_length=32, default="x25519")
    endpoint_public_key_fingerprint = models.CharField(max_length=64, blank=True)
    delivery_token_hash = models.CharField(max_length=64, blank=True)
    delivery_expires_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    attempt_count = models.PositiveSmallIntegerField(default=0)
    last_error_code = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    downloaded_at = models.DateTimeField(null=True, blank=True)
    sealed_configuration = models.TextField(blank=True)

    class Meta:
        ordering = ("created_at",)


class CloudPostureConnector(models.Model):
    """Tenant-scoped, read-only cloud posture configuration; secrets stay outside Django."""
    class Provider(models.TextChoices):
        AWS = "aws", "AWS"
        AZURE = "azure", "Microsoft Azure"
        GCP = "gcp", "Google Cloud"
        THIRD_PARTY = "third_party", "Third-party cloud"

    class Status(models.TextChoices):
        DRAFT = "draft", "Draft / secret not provisioned"
        READY = "ready", "Read-only scope approved"

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="cloud_posture_connectors")
    provider = models.CharField(max_length=16, choices=Provider.choices)
    account_scope = models.CharField(max_length=160)
    credential_reference = models.CharField(max_length=128)
    read_only = models.BooleanField(default=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.DRAFT)
    configured_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("tenant", "provider", "account_scope"), name="unique_tenant_cloud_posture_scope")]
        ordering = ("provider", "account_scope")


class CloudPostureAssessmentRun(models.Model):
    """Safe audit record for a tenant cloud-posture assessment; never stores cloud responses or secrets."""
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    connector = models.ForeignKey(CloudPostureConnector, on_delete=models.CASCADE, related_name="assessment_runs")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    finding_count = models.PositiveIntegerField(default=0)
    error_code = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ("-started_at",)


class GreenboneScanScope(models.Model):
    """An approved-scope request; it never creates or executes a scanner job."""
    class Status(models.TextChoices):
        REQUESTED = "requested", "Requested"
        APPROVED = "approved", "Approved"
        CANCELLED = "cancelled", "Cancelled"

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="greenbone_scan_scopes")
    target_reference = models.CharField(max_length=255)
    authorization_reference = models.CharField(max_length=160)
    maintenance_window_start = models.DateTimeField()
    maintenance_window_end = models.DateTimeField()
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.REQUESTED)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="greenbone_scan_scope_requests")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="greenbone_scan_scope_reviews", null=True, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def clean(self):
        from django.core.exceptions import ValidationError
        if self.maintenance_window_end <= self.maintenance_window_start:
            raise ValidationError("Maintenance-window end must be after its start.")

class GreenboneAssessmentRun(models.Model):
    """Audit metadata for an offline, operator-supplied Greenbone report."""
    class Status(models.TextChoices):
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="greenbone_assessment_runs")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.RUNNING)
    source_label = models.CharField(max_length=32, default="operator_report")
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    finding_count = models.PositiveIntegerField(default=0)
    created_count = models.PositiveIntegerField(default=0)
    updated_count = models.PositiveIntegerField(default=0)
    error_code = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ("-started_at",)


class WazuhEndpointAssetLink(models.Model):
    """Provider-verified correlation between one tenant Wazuh hostname and one portal asset."""
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="wazuh_endpoint_links")
    hostname = models.CharField(max_length=255)
    asset = models.ForeignKey(Asset, on_delete=models.PROTECT, related_name="wazuh_endpoint_links")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="wazuh_endpoint_links_created")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("tenant", "hostname"), name="unique_tenant_wazuh_endpoint_link")]
        ordering = ("hostname",)

    def clean(self):
        from django.core.exceptions import ValidationError
        if self.asset_id and self.asset.tenant_id != self.tenant_id:
            raise ValidationError("A Wazuh endpoint can be linked only to an asset in the same tenant.")


class OIDCIdentity(models.Model):
    """Stable, verified Keycloak subject linked to one pre-provisioned Portal user."""
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="oidc_identity")
    issuer = models.CharField(max_length=500)
    subject = models.CharField(max_length=255)
    linked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("issuer", "subject"), name="unique_oidc_issuer_subject")]

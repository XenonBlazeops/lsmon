from django import forms
from django.core.validators import RegexValidator
from .models import AgentEnrollment, AgentPackage, Asset, Department, FindingException, FindingRemediation, InventoryConnector, SecurityConnector, SecurityFinding, SoftwareComplianceRule, TenantAgentProvisioning, TenantLocation


class TOTPCodeForm(forms.Form):
    code = forms.CharField(label="Authentication code", max_length=8, widget=forms.TextInput(attrs={"autocomplete": "one-time-code", "inputmode": "numeric"}))


class TenantCreateForm(forms.Form):
    name = forms.CharField(label="Customer or tenant name", max_length=160)
    tenant_admin_email = forms.EmailField(label="First Tenant Administrator email")

    def clean_name(self):
        from .models import Tenant
        name = self.cleaned_data["name"].strip()
        if not name:
            raise forms.ValidationError("Enter a tenant name.")
        if Tenant.objects.filter(name__iexact=name).exists():
            raise forms.ValidationError("A tenant with this name already exists.")
        return name


class InvitationAcceptForm(forms.Form):
    password = forms.CharField(label="Choose a portal password", widget=forms.PasswordInput)
    confirm_password = forms.CharField(label="Confirm portal password", widget=forms.PasswordInput)

    def clean(self):
        cleaned = super().clean()
        password = cleaned.get("password", "")
        if len(password) < 16:
            self.add_error("password", "Use at least 16 characters.")
        if password != cleaned.get("confirm_password"):
            self.add_error("confirm_password", "Passwords do not match.")
        return cleaned


class AssetCreateForm(forms.ModelForm):
    def __init__(self, *args, tenant=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["location"].queryset = TenantLocation.objects.filter(tenant=tenant, active=True) if tenant else TenantLocation.objects.none()
        self.fields["department"].queryset = Department.objects.filter(tenant=tenant, active=True) if tenant else Department.objects.none()

    class Meta:
        model = Asset
        fields = ("name", "asset_type", "manufacturer", "model", "serial_number", "assigned_to", "location", "department", "primary_ip", "fqdn", "operating_system", "site", "collection_method", "status")
        labels = {
            "name": "Asset name",
            "asset_type": "Asset type",
            "manufacturer": "Manufacturer",
            "model": "Model",
            "serial_number": "Serial number",
            "assigned_to": "Assigned user or owner",
            "location": "Location",
            "department": "Department",
            "primary_ip": "Primary IP address",
            "fqdn": "FQDN / DNS name",
            "operating_system": "Operating system or firmware",
            "site": "Site / location",
            "collection_method": "Inventory or monitoring method",
            "status": "Current status",
        }
        help_texts = {
            "primary_ip": "IPv4 or IPv6. Leave empty for assets without a management address.",
            "collection_method": "This records the intended source; it does not install or contact an agent.",
        }

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        if not name:
            raise forms.ValidationError("Enter an asset name.")
        return name


class AssetPlacementForm(forms.ModelForm):
    def __init__(self, *args, tenant=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["assigned_location"].queryset = TenantLocation.objects.filter(tenant=tenant, active=True) if tenant else TenantLocation.objects.none()
        self.fields["department"].queryset = Department.objects.filter(tenant=tenant, active=True) if tenant else Department.objects.none()

    class Meta:
        model = Asset
        fields = ("assigned_location", "department", "business_unit", "local_ip")
        labels = {
            "assigned_location": "Customer-assigned location",
            "department": "Department",
            "business_unit": "Business unit (optional)",
            "local_ip": "Customer-recorded local or management IP (optional)",
        }
        help_texts = {
            "assigned_location": "This portal assignment is retained during later GLPI imports.",
            "local_ip": "Use a verified management address. A local IP alone does not prove a physical location.",
        }


class TenantLocationForm(forms.ModelForm):
    class Meta:
        model = TenantLocation
        fields = ("name", "code")
        labels = {"name": "Location name", "code": "Optional location code"}


class DepartmentForm(forms.ModelForm):
    class Meta:
        model = Department
        fields = ("name", "code")
        labels = {"name": "Department name", "code": "Optional department code"}


class SoftwareComplianceRuleForm(forms.ModelForm):
    def __init__(self, *args, tenant=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["location"].queryset = TenantLocation.objects.filter(tenant=tenant, active=True) if tenant else TenantLocation.objects.none()
        self.fields["department"].queryset = Department.objects.filter(tenant=tenant, active=True) if tenant else Department.objects.none()

    class Meta:
        model = SoftwareComplianceRule
        fields = ("name", "rule_type", "patterns", "platform", "location", "department", "active")
        widgets = {"patterns": forms.Textarea(attrs={"rows": 3, "placeholder": "Example: Microsoft Defender, Windows Defender"})}
        labels = {
            "name": "Criterion name", "rule_type": "Rule type", "patterns": "Software name patterns",
            "platform": "Operating-system scope", "location": "Location scope (optional)",
            "department": "Department scope (optional)", "active": "Use this criterion in compliance checks",
        }

    def clean_patterns(self):
        value = self.cleaned_data["patterns"].strip()
        if not any(part.strip() for part in value.replace("\n", ",").split(",")):
            raise forms.ValidationError("Enter at least one software name pattern.")
        return value


class GlpiConnectorForm(forms.ModelForm):
    credential_reference = forms.CharField(
        label="Server-side credential reference",
        max_length=128,
        validators=[RegexValidator(r"^[A-Z][A-Z0-9_]{2,127}$", "Use an uppercase reference name, not an API token.")],
        help_text="Example: LSMON_GLPI_TECSTAQ_TOKEN. Do not paste a GLPI token here.",
    )

    class Meta:
        model = InventoryConnector
        fields = ("base_url", "credential_reference", "scope")
        labels = {
            "base_url": "GLPI HTTPS base URL",
            "scope": "Approved GLPI entity or site scope",
        }
        help_texts = {
            "base_url": "Configuration only: this stage will not contact the URL.",
            "scope": "Example: Tecstaq / India / Entity 12.",
        }

    def clean_base_url(self):
        value = self.cleaned_data["base_url"].strip().rstrip("/")
        if not value.startswith("https://"):
            raise forms.ValidationError("Use an HTTPS GLPI URL.")
        return value


class AgentPackageForm(forms.ModelForm):
    sha256 = forms.CharField(
        label="SHA-256",
        min_length=64,
        max_length=64,
        validators=[RegexValidator(r"^[A-Fa-f0-9]{64}$", "Enter a 64-character SHA-256 checksum.")],
    )

    class Meta:
        model = AgentPackage
        fields = ("vendor", "operating_system", "version", "source_url", "filename", "sha256", "expected_publisher", "status")

    def clean_source_url(self):
        value = self.cleaned_data["source_url"].strip()
        if not value.startswith("https://"):
            raise forms.ValidationError("Use an HTTPS vendor source URL.")
        return value

    def clean_sha256(self):
        return self.cleaned_data["sha256"].upper()


class AgentEnrollmentForm(forms.ModelForm):
    package = forms.ModelChoiceField(queryset=AgentPackage.objects.none(), label="Approved agent package")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["package"].queryset = AgentPackage.objects.filter(status=AgentPackage.Status.APPROVED)

    class Meta:
        model = AgentEnrollment
        fields = ("operating_system", "package")
        labels = {"operating_system": "Endpoint operating system"}
        help_texts = {
            "operating_system": "This creates a tenant-scoped enrollment request only. No installer, credential, or GLPI change is created at this stage.",
        }

    def clean(self):
        cleaned = super().clean()
        package = cleaned.get("package")
        operating_system = cleaned.get("operating_system")
        if package and operating_system and package.operating_system != operating_system:
            self.add_error("package", "Choose a package approved for the selected operating system.")
        return cleaned


class TenantAgentProvisioningForm(forms.ModelForm):
    credential_reference = forms.CharField(
        label="Server-side credential reference",
        max_length=128,
        validators=[RegexValidator(r"^[A-Z][A-Z0-9_]{2,127}$", "Use an uppercase reference name, never a credential value.")],
        help_text="Reference only. The value remains in the server-side secret store and is never shown here.",
    )

    class Meta:
        model = TenantAgentProvisioning
        fields = ("glpi_inventory_url", "glpi_entity_scope", "inventory_tag", "credential_reference")
        labels = {
            "glpi_inventory_url": "GLPI inventory HTTPS URL",
            "glpi_entity_scope": "GLPI entity scope",
            "inventory_tag": "Inventory tag",
        }

    def clean_glpi_inventory_url(self):
        value = self.cleaned_data["glpi_inventory_url"].strip().rstrip("/")
        if not value.startswith("https://"):
            raise forms.ValidationError("Use an HTTPS inventory URL.")
        return value


class SecurityConnectorForm(forms.ModelForm):
    credential_reference = forms.CharField(
        label="Server-side read-only credential reference",
        max_length=128,
        validators=[RegexValidator(r"^[A-Z][A-Z0-9_]{2,127}$", "Use an uppercase reference name, never a credential value.")],
        help_text="Reference only. The credential remains in the server-side secret store and is never shown here.",
    )

    class Meta:
        model = SecurityConnector
        fields = ("base_url", "credential_reference", "scope")
        labels = {
            "base_url": "Wazuh HTTPS API base URL",
            "scope": "Approved Wazuh agent-group scope",
        }
        help_texts = {
            "base_url": "Configuration only: saving this form does not contact Wazuh.",
            "scope": "Example: tecstaq. This scope will later limit which agents and alerts this tenant can see.",
        }

    def clean_base_url(self):
        value = self.cleaned_data["base_url"].strip().rstrip("/")
        if not value.startswith("https://"):
            raise forms.ValidationError("Use an HTTPS Wazuh API URL.")
        return value


class SecurityFindingForm(forms.ModelForm):
    def __init__(self, *args, tenant=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["asset"].queryset = Asset.objects.filter(tenant=tenant).order_by("name") if tenant else Asset.objects.none()

    class Meta:
        model = SecurityFinding
        fields = (
            "asset", "source", "source_id", "title", "description", "cve_id", "control_id", "severity",
            "status", "owner", "remediation_url", "evidence_reference", "first_observed_at", "last_observed_at", "due_at",
        )
        widgets = {
            "description": forms.Textarea(attrs={"rows": 4}),
            "first_observed_at": forms.DateTimeInput(attrs={"type": "datetime-local"}),
            "last_observed_at": forms.DateTimeInput(attrs={"type": "datetime-local"}),
            "due_at": forms.DateTimeInput(attrs={"type": "datetime-local"}),
        }
        help_texts = {
            "source_id": "Source record identifier only; never paste a raw event body or credential.",
            "remediation_url": "Optional vendor or internal guidance URL. It is a reference, not an executable command.",
            "evidence_reference": "Required before Verified closed. Use a safe reference, not raw scanner output or a credential.",
        }


class FindingRemediationForm(forms.ModelForm):
    class Meta:
        model = FindingRemediation
        fields = ("summary", "status", "requested_by", "approved_by", "approved_at", "maintenance_window", "execution_reference", "rollback_reference")
        widgets = {"approved_at": forms.DateTimeInput(attrs={"type": "datetime-local"})}
        help_texts = {
            "execution_reference": "Safe job/change reference only. Commands and credentials never belong in TecstaqOps.",
            "rollback_reference": "Safe rollback or change-record reference only.",
        }


class FindingExceptionForm(forms.ModelForm):
    class Meta:
        model = FindingException
        fields = ("justification", "compensating_control", "owner", "expires_at", "approved_by")
        widgets = {
            "justification": forms.Textarea(attrs={"rows": 3}),
            "compensating_control": forms.Textarea(attrs={"rows": 3}),
            "expires_at": forms.DateTimeInput(attrs={"type": "datetime-local"}),
        }

from functools import wraps
import base64
import os
import csv
import hmac
import json
from pathlib import Path
from datetime import timedelta, timezone as datetime_timezone
from urllib.parse import quote, urlparse

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Max, Q
from django.db import IntegrityError, transaction
from django.http import HttpResponseBadRequest, JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from . import oidc
from .authorization import AuthorizationDenied, can_view_operations, is_global_admin, require_tenant_role, visible_tenants
from .forms import WazuhEndpointCorrelationForm, AgentEnrollmentForm, AgentPackageForm, AssetCreateForm, AssetPlacementForm, DepartmentForm, FindingExceptionForm, FindingRemediationForm, GlpiConnectorForm, InvitationAcceptForm, SecurityConnectorForm, SecurityFindingForm, SoftwareComplianceRuleForm, TenantAgentProvisioningForm, TenantLocationForm, TOTPCodeForm, TenantCreateForm
from .invitations import invitation_token_hash
from .mfa import decrypt_secret, encrypt_secret, generate_secret, provisioning_uri, verify_code
from .models import WazuhEndpointAssetLink, AgentEnrollment, AgentEnrollmentEvent, AgentPackage, AgentProvisioningJob, AgentRegistrationValidation, Asset, AssetCompliance, AssetExternalIdentity, AssetNetworkInterface, AssetSoftware, ComplianceAuditEvent, Department, FindingAuditEvent, FindingException, FindingRemediation, InventoryConnector, InventorySyncRun, MFAProfile, Membership, SecurityConnector, SecurityFinding, SoftwareComplianceRule, Tenant, TenantAdminInvitation, TenantAgentProvisioning, TenantLocation, VulnerabilityImportRun, unique_tenant_slug
from .compliance import evaluate_tenant
from .registration import generate_registration_code, hash_registration_code, registration_code_matches
from .envelope import decode_public_key, generate_delivery_token, hash_delivery_token, public_key_fingerprint
from .zabbix_dashboard import summary_for_enrollments
from .wazuh_dashboard import (
    provider_summary_for_connectors as provider_wazuh_summary_for_connectors,
    summary_for_connector as wazuh_summary_for_connector,
)
from .wazuh_findings import (
    attention_for_summary,
    provider_summary_for_connectors,
    summary_for_connector as wazuh_findings_for_connector,
)
from .wazuh_scan_state import (
    provider_summary_for_connectors as provider_wazuh_scan_state_for_connectors,
    summary_for_connector as wazuh_scan_state_for_connector,
)


GLPI_INVENTORY_FRESHNESS_HOURS = 26


def _safe_console_url(value):
    """Return only an HTTPS console URL; never expose API-only loopback URLs."""
    if not value:
        return None
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    return value.rstrip("/")


def _inventory_freshness(last_seen_at):
    """Classify stored GLPI observation time; never infer endpoint health."""
    if last_seen_at is None:
        return "not_reported"
    if timezone.now() - last_seen_at <= timedelta(hours=GLPI_INVENTORY_FRESHNESS_HOURS):
        return "current"
    return "stale"


def _provider_inventory_summary(tenants):
    """Aggregate portal-stored GLPI observation freshness without calling GLPI."""
    expected_assets = Asset.objects.filter(tenant__in=tenants).count()
    observations = list(
        AssetExternalIdentity.objects.filter(
            asset__tenant__in=tenants, source=AssetExternalIdentity.Source.GLPI,
        ).values("asset_id").annotate(last_seen=Max("last_seen_at"))
    )
    current = sum(_inventory_freshness(item["last_seen"]) == "current" for item in observations)
    stale = sum(_inventory_freshness(item["last_seen"]) == "stale" for item in observations)
    return {
        "expected_assets": expected_assets,
        "current": current,
        "stale": stale,
        "not_reported": max(expected_assets - current - stale, 0),
    }


def mfa_required(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect(f"{reverse('login')}?next={quote(request.get_full_path())}")
        profile = MFAProfile.objects.filter(user=request.user).first()
        if not profile or not profile.is_enrolled:
            return redirect("mfa_enroll")
        if request.session.get("mfa_verified_user_id") != str(request.user.pk):
            return redirect("mfa_challenge")
        return view(request, *args, **kwargs)
    return wrapped


class PortalLoginView(LoginView):
    template_name = "login.html"

    def dispatch(self, request, *args, **kwargs):
        if settings.LSMON_OIDC_ENABLED:
            next_url = request.GET.get("next", "")
            suffix = f"?next={quote(next_url)}" if next_url else ""
            return redirect(reverse("oidc_start") + suffix)
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        response = super().form_valid(form)
        self.request.session.pop("mfa_verified_user_id", None)
        self.request.session["mfa_password_user_id"] = str(self.request.user.pk)
        return response


def oidc_start(request):
    return oidc.start(request)


def oidc_callback(request):
    try:
        return oidc.callback(request)
    except oidc.OIDCAuthenticationError as error:
        messages.error(request, str(error))
        return redirect("login")


@login_required
def mfa_enroll(request):
    profile, _ = MFAProfile.objects.get_or_create(user=request.user)
    if profile.is_enrolled:
        return redirect("mfa_challenge")
    if not profile.secret_ciphertext:
        profile.secret_ciphertext = encrypt_secret(generate_secret())
        profile.save(update_fields=["secret_ciphertext"])
    secret_uri = provisioning_uri(
        decrypt_secret(profile.secret_ciphertext),
        request.user.email or request.user.get_username(),
    )
    form = TOTPCodeForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        if verify_code(profile.secret_ciphertext, form.cleaned_data["code"]):
            profile.enrolled_at = timezone.now()
            profile.last_verified_at = timezone.now()
            profile.save(update_fields=["enrolled_at", "last_verified_at"])
            request.session["mfa_verified_user_id"] = str(request.user.pk)
            request.session.pop("mfa_password_user_id", None)
            return redirect("dashboard")
        form.add_error("code", "That code was not accepted. Check your device time and try again.")
    return render(request, "mfa_enroll.html", {
        "form": form,
        "provisioning_uri": secret_uri,
        "manual_secret": decrypt_secret(profile.secret_ciphertext),
    })


@login_required
def mfa_challenge(request):
    profile = MFAProfile.objects.filter(user=request.user).first()
    if not profile or not profile.is_enrolled:
        return redirect("mfa_enroll")
    form = TOTPCodeForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        if verify_code(profile.secret_ciphertext, form.cleaned_data["code"]):
            profile.last_verified_at = timezone.now()
            profile.save(update_fields=["last_verified_at"])
            request.session["mfa_verified_user_id"] = str(request.user.pk)
            request.session.pop("mfa_password_user_id", None)
            return redirect(request.POST.get("next") or "dashboard")
        form.add_error("code", "That code was not accepted. Check your device time and try again.")
    return render(request, "mfa_challenge.html", {"form": form, "next": request.GET.get("next", "")})

@mfa_required
def dashboard(request):
    tenants = visible_tenants(request.user)
    if not is_global_admin(request.user) and tenants.count() == 1:
        return redirect("tenant_home", slug=tenants.first().slug)
    zabbix_enrollments = AgentEnrollment.objects.filter(
        tenant__in=tenants, package__vendor=AgentPackage.Vendor.ZABBIX,
    ).select_related("tenant")
    security_connectors = SecurityConnector.objects.filter(
        tenant__in=tenants, tenant__active=True, provider=SecurityConnector.Provider.WAZUH,
    ).select_related("tenant").order_by("tenant__name")
    zabbix_summary = summary_for_enrollments(zabbix_enrollments)
    inventory_summary = _provider_inventory_summary(tenants)
    security_findings = provider_summary_for_connectors(security_connectors)
    # provider-cloud-summary-v1
    from .models import CloudPostureConnector
    cloud_connectors = CloudPostureConnector.objects.filter(tenant__in=tenants)
    cloud_ready = cloud_connectors.filter(status=CloudPostureConnector.Status.READY).count()
    operational_attention = {
        "zabbix_problems": zabbix_summary.get("problem_count", len(zabbix_summary["problems"])) if zabbix_summary.get("state") == "ready" else 0,
        "wazuh_critical": security_findings["critical"],
        "wazuh_high": security_findings["high"],
        "wazuh_medium": security_findings["medium"],
        "inventory_stale": inventory_summary["stale"],
        "inventory_not_reported": inventory_summary["not_reported"],
    }
    return render(request, "dashboard.html", {
        "tenant_count": tenants.count(),
        "cloud_connector_count": cloud_connectors.count(),
        "cloud_ready_count": cloud_ready,
        "tenants": tenants[:5],
        "zabbix_summary": zabbix_summary,
        "security_summary": provider_wazuh_summary_for_connectors(security_connectors),
        "inventory_summary": inventory_summary,
        "operational_attention": operational_attention,
        "is_provider": True,
    })

@mfa_required
def tenants(request):
    visible = visible_tenants(request.user)
    if not is_global_admin(request.user) and visible.count() == 1:
        return redirect("tenant_home", slug=visible.first().slug)
    return render(request, "tenants.html", {
        "tenants": visible.annotate(asset_count=Count("asset")).order_by("name"),
        "can_manage_tenants": is_global_admin(request.user),
        "is_provider": True,
    })

@mfa_required
def operations(request):
    if not can_view_operations(request.user):
        raise PermissionDenied("NOC / SOC access is required.")
    connectors = SecurityConnector.objects.filter(
        tenant__active=True,
        provider=SecurityConnector.Provider.WAZUH,
    ).select_related("tenant").order_by("tenant__name")
    return render(request, "operations.html", {
        "is_provider": True,
        "security_findings": provider_summary_for_connectors(connectors),
        "security_freshness": provider_wazuh_scan_state_for_connectors(connectors),
    })


@mfa_required
def enrollment_queue(request):
    if not is_global_admin(request.user):
        raise PermissionDenied("Global Administrator access is required.")
    return render(request, "enrollment_queue.html", {
        "enrollments": AgentEnrollment.objects.select_related("tenant", "requested_by").all(),
        "is_provider": True,
    })


@mfa_required
def agent_catalog(request):
    if not is_global_admin(request.user):
        raise PermissionDenied("Global Administrator access is required.")
    form = AgentPackageForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        package = form.save(commit=False)
        if package.status == AgentPackage.Status.APPROVED:
            package.approved_by = request.user
            package.approved_at = timezone.now()
        package.save()
        return redirect("agent_catalog")
    return render(request, "agent_catalog.html", {
        "form": form,
        "packages": AgentPackage.objects.all(),
        "is_provider": True,
    })


@mfa_required
def tenant_agent_provisioning(request, slug):
    if not is_global_admin(request.user):
        raise PermissionDenied("Global Administrator access is required.")
    tenant = get_object_or_404(Tenant, slug=slug, active=True)
    provisioning, _ = TenantAgentProvisioning.objects.get_or_create(tenant=tenant, defaults={"inventory_tag": tenant.slug})
    form = TenantAgentProvisioningForm(request.POST or None, instance=provisioning)
    if request.method == "POST" and form.is_valid():
        configured = form.save(commit=False)
        configured.status = TenantAgentProvisioning.Status.CONFIGURED
        configured.configured_by = request.user
        configured.configured_at = timezone.now()
        configured.save()
        return redirect("enrollment_queue")
    return render(request, "tenant_agent_provisioning.html", {
        "tenant": tenant,
        "provisioning": provisioning,
        "form": form,
        "is_provider": True,
    })


@mfa_required
def enrollment_action(request, enrollment_id, action):
    if request.method != "POST":
        raise PermissionDenied("Enrollment actions require a POST request.")
    if not is_global_admin(request.user):
        raise PermissionDenied("Global Administrator access is required.")
    enrollment = get_object_or_404(AgentEnrollment, pk=enrollment_id)
    if action == "approve" and enrollment.status == AgentEnrollment.Status.REQUESTED:
        enrollment.status = AgentEnrollment.Status.PROVISIONING
        enrollment.save(update_fields=["status", "updated_at"])
        AgentEnrollmentEvent.objects.create(
            enrollment=enrollment, actor=request.user, event_type=AgentEnrollmentEvent.EventType.APPROVED
        )
    elif action == "prepare" and enrollment.status == AgentEnrollment.Status.PROVISIONING:
        if not enrollment.package or enrollment.package.status != AgentPackage.Status.APPROVED:
            raise PermissionDenied("An approved agent package is required before a bootstrap can be prepared.")
        if enrollment.package.vendor != AgentPackage.Vendor.ZABBIX:
            provisioning = TenantAgentProvisioning.objects.filter(tenant=enrollment.tenant).first()
            if not provisioning or provisioning.status != TenantAgentProvisioning.Status.CONFIGURED or not all((
                provisioning.glpi_inventory_url,
                provisioning.glpi_entity_scope,
                provisioning.credential_reference,
            )):
                raise PermissionDenied("Tenant provisioning references must be configured before a bootstrap can be prepared.")
        enrollment.status = AgentEnrollment.Status.READY
        enrollment.package_ready_at = timezone.now()
        enrollment.save(update_fields=["status", "package_ready_at", "updated_at"])
        AgentEnrollmentEvent.objects.create(
            enrollment=enrollment, actor=request.user, event_type=AgentEnrollmentEvent.EventType.BOOTSTRAP_READY
        )
    elif action == "revoke" and enrollment.status not in (AgentEnrollment.Status.REVOKED, AgentEnrollment.Status.ENROLLED, AgentEnrollment.Status.EXPIRED):
        enrollment.status = AgentEnrollment.Status.REVOKED
        enrollment.revoked_at = timezone.now()
        enrollment.save(update_fields=["status", "revoked_at", "updated_at"])
        AgentEnrollmentEvent.objects.create(
            enrollment=enrollment, actor=request.user, event_type=AgentEnrollmentEvent.EventType.REVOKED
        )
    else:
        raise PermissionDenied("This enrollment cannot take that action in its current state.")
    return redirect("enrollment_queue")


@mfa_required
def download_enrollment_bootstrap(request, slug, enrollment_id):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    enrollment = get_object_or_404(AgentEnrollment, pk=enrollment_id, tenant=tenant)
    _require_ready_catalog_enrollment(enrollment)
    if enrollment.downloaded_at is None:
        enrollment.downloaded_at = timezone.now()
        enrollment.save(update_fields=["downloaded_at", "updated_at"])
        AgentEnrollmentEvent.objects.create(
            enrollment=enrollment, actor=request.user, event_type=AgentEnrollmentEvent.EventType.DOWNLOADED
        )
    response = JsonResponse(_bootstrap_manifest(request, enrollment))
    response["Content-Disposition"] = f'attachment; filename="lsmon-bootstrap-{enrollment.operating_system}-{enrollment.id}.json"'
    return response


@mfa_required
def download_windows_bootstrap(request, slug, enrollment_id):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    enrollment = get_object_or_404(AgentEnrollment, pk=enrollment_id, tenant=tenant)
    _require_ready_catalog_enrollment(enrollment, windows_only=True)
    source = Path(__file__).resolve().parent.parent / "bootstrap" / "Install-LsmonWindowsAgent.ps1"
    if not source.is_file():
        raise PermissionDenied("Windows bootstrap source is unavailable.")
    response = HttpResponse(source.read_bytes(), content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="Install-LsmonWindowsAgent-{enrollment.id}.ps1"'
    return response


def _require_ready_catalog_enrollment(enrollment, windows_only=False):
    if (
        (windows_only and enrollment.operating_system != AgentEnrollment.OperatingSystem.WINDOWS)
        or enrollment.status != AgentEnrollment.Status.READY
        or enrollment.expires_at <= timezone.now()
        or not enrollment.package_id
        or enrollment.package.status != AgentPackage.Status.APPROVED
        or enrollment.package.operating_system != enrollment.operating_system
    ):
        raise PermissionDenied("This enrollment is not available for bootstrap download.")


def _bootstrap_manifest(request, enrollment):
    """Build only the non-secret manifest consumed by an endpoint bootstrap."""
    return {
        "schema_version": 2,
        "kind": "lsmon-agent-bootstrap-manifest",
        "installable": True,
        "tenant": enrollment.tenant.slug,
        "enrollment_id": str(enrollment.id),
        "operating_system": enrollment.operating_system,
        "validation_url": request.build_absolute_uri(reverse("validate_registration_code")),
        "configuration_url": request.build_absolute_uri(reverse("retrieve_sealed_configuration", kwargs={"enrollment_id": enrollment.id})),
        "package": {
            "vendor": enrollment.package.vendor,
            "version": enrollment.package.version,
            "source_url": enrollment.package.source_url,
            "filename": enrollment.package.filename,
            "sha256": enrollment.package.sha256,
            "expected_publisher": enrollment.package.expected_publisher,
        },
        "expires_at": enrollment.expires_at.isoformat(),
        "message": "This manifest contains no OAuth credential or tenant secret. The endpoint receives its encrypted configuration only after one-time registration.",
    }


def _bootstrap_source_for(enrollment):
    """Return the audited bootstrap appropriate to the approved vendor package."""
    if enrollment.package.vendor == AgentPackage.Vendor.ZABBIX:
        filename = (
            "Install-LsmonZabbixAgentWindows.ps1"
            if enrollment.operating_system == AgentEnrollment.OperatingSystem.WINDOWS
            else "Install-LsmonZabbixAgentLinux.sh"
        )
    else:
        filename = (
            "Install-LsmonWindowsAgent.ps1"
            if enrollment.operating_system == AgentEnrollment.OperatingSystem.WINDOWS
            else "Install-LsmonLinuxAgent.sh"
        )
    source = Path(__file__).resolve().parent.parent / "bootstrap" / filename
    if not source.is_file():
        raise PermissionDenied("The approved agent bootstrap source is unavailable.")
    return source


def _issue_registration_code(enrollment, actor, *, replace=False):
    """Persist only a hash; the one-time plaintext is returned in the installer once."""
    if enrollment.registration_code_hash and enrollment.registration_code_used_at is None and not replace:
        raise PermissionDenied("A registration code was already issued for this enrollment.")
    # A replacement installer rotates an unused code. This lets an administrator
    # recover from a lost download without retaining or revealing the old code.
    code = generate_registration_code()
    enrollment.registration_code_hash = hash_registration_code(code)
    enrollment.registration_code_issued_at = timezone.now()
    enrollment.registration_code_attempts = 0
    enrollment.registration_code_locked_until = None
    enrollment.save(update_fields=[
        "registration_code_hash", "registration_code_issued_at",
        "registration_code_attempts", "registration_code_locked_until", "updated_at",
    ])
    AgentEnrollmentEvent.objects.create(
        enrollment=enrollment, actor=actor, event_type=AgentEnrollmentEvent.EventType.CODE_ISSUED
    )
    return code


def _render_single_file_windows_installer(manifest, registration_code, enrollment_id, bootstrap_source):
    manifest_b64 = base64.b64encode(json.dumps(manifest, separators=(",", ":")).encode("utf-8")).decode("ascii")
    bootstrap_b64 = base64.b64encode(bootstrap_source).decode("ascii")
    return f'''# LSMON single-use Windows enrollment installer.
# Keep this file private: it contains a short-lived registration code for one endpoint.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'))
  exit
}}
$work = Join-Path $env:TEMP 'lsmon-single-{enrollment_id}'
$manifestPath = Join-Path $work 'lsmon-bootstrap-windows-{enrollment_id}.json'
$bootstrapPath = Join-Path $work 'Install-LsmonWindowsAgent-{enrollment_id}.ps1'
$registrationCode = '{registration_code}'
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {{
  [IO.File]::WriteAllBytes($manifestPath, [Convert]::FromBase64String('{manifest_b64}'))
  [IO.File]::WriteAllBytes($bootstrapPath, [Convert]::FromBase64String('{bootstrap_b64}'))
  & $bootstrapPath -ManifestPath $manifestPath -RegistrationCode $registrationCode
  if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}
}}
finally {{
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}}
'''


def _render_single_file_linux_installer(manifest, registration_code, enrollment_id, bootstrap_source, bootstrap_filename="Install-LsmonLinuxAgent.sh"):
    """Return a root-elevating, one-file Linux installer with no persistent secret.

    The returned shell script contains the short-lived registration code once.  It
    embeds only the non-secret manifest and the audited bootstrap source; the
    OAuth configuration remains unavailable until the endpoint key is validated.
    """
    manifest_b64 = base64.b64encode(json.dumps(manifest, separators=(",", ":")).encode("utf-8")).decode("ascii")
    bootstrap_b64 = base64.b64encode(bootstrap_source).decode("ascii")
    code_b64 = base64.b64encode(registration_code.encode("utf-8")).decode("ascii")
    return f'''#!/usr/bin/env bash
# LSMON single-use Linux enrollment installer.
# Keep this file private: it contains a short-lived registration code for one endpoint.
set -euo pipefail
if [[ "${{EUID}}" -ne 0 ]]; then
  exec sudo --preserve-env=LSMON_DELIVERY_WAIT_SECONDS bash "$0" "$@"
fi
command -v base64 >/dev/null || {{ printf '%s\\n' 'LSMON bootstrap stopped: base64 is required.' >&2; exit 1; }}
work_dir="$(mktemp -d "/tmp/lsmon-single-{enrollment_id}.XXXXXX")"
chmod 700 "$work_dir"
trap 'rm -rf -- "$work_dir"' EXIT
manifest_path="$work_dir/lsmon-bootstrap-linux-{enrollment_id}.json"
bootstrap_path="$work_dir/{bootstrap_filename}"
printf '%s' '{manifest_b64}' | base64 -d > "$manifest_path"
printf '%s' '{bootstrap_b64}' | base64 -d > "$bootstrap_path"
chmod 700 "$bootstrap_path"
registration_code="$(printf '%s' '{code_b64}' | base64 -d)"
"$bootstrap_path" "$manifest_path" "$registration_code"
'''


@csrf_exempt
def retrieve_windows_exe_bootstrap(request):
    """Return a one-time Windows bootstrap to the signed pilot executable.

    The executable supplies the enrollment id and plaintext code over TLS.  This
    endpoint deliberately does not consume the code: the established bootstrap
    validates and consumes it while registering the endpoint public key.
    """
    if request.method != "POST":
        return HttpResponseBadRequest("POST required.")
    enrollment_id = request.POST.get("enrollment_id", "").strip()
    code = request.POST.get("registration_code", "").strip().upper()
    source = Path(__file__).resolve().parent.parent / "bootstrap" / "Install-LsmonWindowsAgent.ps1"
    enrollment = AgentEnrollment.objects.filter(pk=enrollment_id).select_related("package", "tenant").first()
    if not source.is_file() or not enrollment or not code:
        return JsonResponse({"available": False}, status=403)
    try:
        _require_ready_catalog_enrollment(enrollment, windows_only=True)
    except PermissionDenied:
        return JsonResponse({"available": False}, status=403)
    now = timezone.now()
    if enrollment.registration_code_locked_until and enrollment.registration_code_locked_until > now:
        AgentRegistrationValidation.objects.create(enrollment=enrollment, accepted=False)
        return JsonResponse({"available": False}, status=429)
    if not enrollment.registration_code_hash or not registration_code_matches(code, enrollment.registration_code_hash):
        enrollment.registration_code_attempts += 1
        update_fields = ["registration_code_attempts", "updated_at"]
        if enrollment.registration_code_attempts >= 5:
            enrollment.registration_code_locked_until = now + timedelta(minutes=15)
            update_fields.append("registration_code_locked_until")
        enrollment.save(update_fields=update_fields)
        AgentRegistrationValidation.objects.create(enrollment=enrollment, accepted=False)
        return JsonResponse({"available": False}, status=403)
    response = HttpResponse(
        _render_single_file_windows_installer(
            _bootstrap_manifest(request, enrollment), code, enrollment.id, source.read_bytes()
        ),
        content_type="text/plain; charset=utf-8",
    )
    response["Cache-Control"] = "no-store, private"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    return response


def _pilot_artifact(filename):
    artifact = Path(__file__).resolve().parent.parent / "bootstrapper" / filename
    if not artifact.is_file():
        raise PermissionDenied("The pilot Windows installer is not available.")
    return artifact


@mfa_required
def download_pilot_windows_bootstrapper(request, slug):
    """Download the lab-only signed executable; no tenant secret is included."""
    tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    artifact = _pilot_artifact("LSMON Endpoint Setup.exe")
    response = HttpResponse(artifact.read_bytes(), content_type="application/vnd.microsoft.portable-executable")
    response["Content-Disposition"] = 'attachment; filename="LSMON-Endpoint-Setup-Pilot.exe"'
    response["Cache-Control"] = "no-store, private"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@mfa_required
def download_pilot_windows_certificate(request, slug):
    """Download only the public pilot signing certificate for controlled test devices."""
    tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    artifact = _pilot_artifact("Tecstaq-LSMON-Test-Signing.cer")
    response = HttpResponse(artifact.read_bytes(), content_type="application/pkix-cert")
    response["Content-Disposition"] = 'attachment; filename="Tecstaq-LSMON-Test-Signing.cer"'
    response["Cache-Control"] = "no-store, private"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@mfa_required
def download_single_file_windows_installer(request, slug, enrollment_id):
    """Issue a single-use one-file Windows installer without storing its plaintext code."""
    if request.method != "POST":
        raise PermissionDenied("Single-file installer issuance requires a POST request.")
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    with transaction.atomic():
        enrollment = get_object_or_404(
            # PostgreSQL rejects FOR UPDATE on the nullable package outer join.
            # Lock only the enrollment row; package and tenant are read separately.
            AgentEnrollment.objects.select_for_update(),
            pk=enrollment_id,
            tenant=tenant,
        )
        _require_ready_catalog_enrollment(enrollment, windows_only=True)
        source = _bootstrap_source_for(enrollment)
        registration_code = _issue_registration_code(enrollment, request.user, replace=True)
        if enrollment.downloaded_at is None:
            enrollment.downloaded_at = timezone.now()
            enrollment.save(update_fields=["downloaded_at", "updated_at"])
            AgentEnrollmentEvent.objects.create(
                enrollment=enrollment, actor=request.user, event_type=AgentEnrollmentEvent.EventType.DOWNLOADED
            )
        installer = _render_single_file_windows_installer(
            _bootstrap_manifest(request, enrollment), registration_code, enrollment.id, source.read_bytes()
        )
    response = HttpResponse(installer, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="Install-LsmonWindowsAgent-{enrollment.id}.ps1"'
    response["Cache-Control"] = "no-store, private"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@mfa_required
def download_single_file_linux_installer(request, slug, enrollment_id):
    """Issue a one-file Linux installer for an approved, ready Linux enrollment."""
    if request.method != "POST":
        raise PermissionDenied("Single-file installer issuance requires a POST request.")
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    with transaction.atomic():
        enrollment = get_object_or_404(AgentEnrollment.objects.select_for_update(), pk=enrollment_id, tenant=tenant)
        _require_ready_catalog_enrollment(enrollment)
        if enrollment.operating_system != AgentEnrollment.OperatingSystem.LINUX:
            raise PermissionDenied("This enrollment is not available for Linux installer download.")
        source = _bootstrap_source_for(enrollment)
        registration_code = _issue_registration_code(enrollment, request.user, replace=True)
        if enrollment.downloaded_at is None:
            enrollment.downloaded_at = timezone.now()
            enrollment.save(update_fields=["downloaded_at", "updated_at"])
            AgentEnrollmentEvent.objects.create(
                enrollment=enrollment, actor=request.user, event_type=AgentEnrollmentEvent.EventType.DOWNLOADED
            )
        installer = _render_single_file_linux_installer(
            _bootstrap_manifest(request, enrollment), registration_code, enrollment.id, source.read_bytes(), source.name
        )
    response = HttpResponse(installer, content_type="text/x-shellscript; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="Install-LsmonLinuxAgent-{enrollment.id}.sh"'
    response["Cache-Control"] = "no-store, private"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    return response


@mfa_required
def issue_registration_code(request, slug, enrollment_id):
    if request.method != "POST":
        raise PermissionDenied("Registration-code issuance requires a POST request.")
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    enrollment = get_object_or_404(AgentEnrollment, pk=enrollment_id, tenant=tenant)
    if (
        enrollment.status != AgentEnrollment.Status.READY
        or enrollment.expires_at <= timezone.now()
        or not enrollment.package_id
        or enrollment.package.status != AgentPackage.Status.APPROVED
        or enrollment.package.operating_system != enrollment.operating_system
    ):
        raise PermissionDenied("This enrollment is not ready for a registration code.")
    code = _issue_registration_code(enrollment, request.user)
    return render(request, "registration_code_issued.html", {
        "tenant": tenant,
        "enrollment": enrollment,
        "registration_code": code,
        "is_provider": is_global_admin(request.user),
    })


@csrf_exempt
def validate_registration_code(request):
    """Installer-facing validation foundation; returns no configuration or credential."""
    if request.method != "POST":
        return HttpResponseBadRequest("POST required.")
    enrollment_id = request.POST.get("enrollment_id", "")
    code = request.POST.get("registration_code", "").strip().upper()
    endpoint_public_key = request.POST.get("endpoint_public_key", "").strip()
    endpoint_key_algorithm = request.POST.get("endpoint_key_algorithm", "x25519").strip()
    enrollment = AgentEnrollment.objects.filter(pk=enrollment_id).select_related("tenant").first()
    now = timezone.now()
    if (
        not enrollment
        or not code
        or enrollment.status != AgentEnrollment.Status.READY
        or enrollment.expires_at <= now
        or not enrollment.package_id
        or enrollment.package.status != AgentPackage.Status.APPROVED
        or enrollment.package.operating_system != enrollment.operating_system
    ):
        return JsonResponse({"valid": False}, status=403)
    if enrollment.registration_code_locked_until and enrollment.registration_code_locked_until > now:
        AgentRegistrationValidation.objects.create(enrollment=enrollment, accepted=False)
        return JsonResponse({"valid": False}, status=429)
    if not enrollment.registration_code_hash or not registration_code_matches(code, enrollment.registration_code_hash):
        enrollment.registration_code_attempts += 1
        update_fields = ["registration_code_attempts", "updated_at"]
        if enrollment.registration_code_attempts >= 5:
            enrollment.registration_code_locked_until = now + timedelta(minutes=15)
            update_fields.append("registration_code_locked_until")
        enrollment.save(update_fields=update_fields)
        AgentRegistrationValidation.objects.create(enrollment=enrollment, accepted=False)
        return JsonResponse({"valid": False}, status=403)
    try:
        decode_public_key(endpoint_public_key, endpoint_key_algorithm)
    except ValueError:
        return JsonResponse({"valid": False}, status=400)
    enrollment.registration_code_used_at = now
    enrollment.status = AgentEnrollment.Status.ACTIVATING
    enrollment.save(update_fields=["registration_code_used_at", "status", "updated_at"])
    AgentRegistrationValidation.objects.create(enrollment=enrollment, accepted=True)
    delivery_token = generate_delivery_token()
    AgentProvisioningJob.objects.create(
        enrollment=enrollment,
        endpoint_public_key=endpoint_public_key,
        endpoint_key_algorithm=endpoint_key_algorithm,
        endpoint_public_key_fingerprint=public_key_fingerprint(endpoint_public_key, endpoint_key_algorithm),
        delivery_token_hash=hash_delivery_token(delivery_token),
        delivery_expires_at=enrollment.expires_at,
    )
    # A separate privileged worker will later consume this job. Never return a
    # credential or configuration from the public registration endpoint.
    return JsonResponse({
        "valid": True,
        "enrollment_id": str(enrollment.id),
        "tenant": enrollment.tenant.slug,
        "operating_system": enrollment.operating_system,
        "configuration_available": False,
        "delivery_token": delivery_token,
    })


@csrf_exempt
def retrieve_sealed_configuration(request, enrollment_id):
    """Return one encrypted envelope only to the endpoint holding its delivery token."""
    if request.method != "POST":
        return HttpResponseBadRequest("POST required.")
    token = request.POST.get("delivery_token", "")
    job = AgentProvisioningJob.objects.select_related("enrollment").filter(enrollment_id=enrollment_id).first()
    now = timezone.now()
    if not job or not token or not job.delivery_token_hash or not hmac.compare_digest(
        hash_delivery_token(token), job.delivery_token_hash
    ):
        return JsonResponse({"available": False}, status=403)
    if not job.delivery_expires_at or job.delivery_expires_at <= now:
        return JsonResponse({"available": False}, status=403)
    if job.status in (AgentProvisioningJob.Status.QUEUED, AgentProvisioningJob.Status.RUNNING):
        return JsonResponse({"available": False, "pending": True}, status=202)
    if job.status != AgentProvisioningJob.Status.DELIVERED or not job.sealed_configuration:
        return JsonResponse({"available": False}, status=403)
    if job.downloaded_at is not None:
        return JsonResponse({"available": False}, status=410)
    try:
        envelope = json.loads(job.sealed_configuration)
    except (TypeError, ValueError):
        return JsonResponse({"available": False}, status=500)
    job.downloaded_at = now
    job.save(update_fields=["downloaded_at", "updated_at"])
    return JsonResponse({
        "available": True,
        "enrollment_id": str(job.enrollment_id),
        "envelope": envelope,
    })


@mfa_required
def create_tenant(request):
    if not is_global_admin(request.user):
        raise PermissionDenied("Only a Global Administrator can create a tenant.")
    form = TenantCreateForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        tenant = Tenant.objects.create(name=form.cleaned_data["name"].strip(), slug=unique_tenant_slug(form.cleaned_data["name"]))
        TenantAgentProvisioning.objects.create(tenant=tenant, inventory_tag=tenant.slug)
        TenantAdminInvitation.objects.create(
            tenant=tenant,
            email=form.cleaned_data["tenant_admin_email"].lower(),
        )
        # No token is rendered, logged, or even generated until a signed email
        # delivery path exists and has been verified.
        return redirect("tenants")
    return render(request, "tenant_create.html", {"form": form, "is_provider": True})


@mfa_required
def tenant_home(request, slug):
    tenant = Tenant.objects.filter(slug=slug, active=True).first()
    if tenant is None:
        raise PermissionDenied("Tenant workspace is unavailable.")
    try:
        require_tenant_role(request.user, tenant.id, [Membership.Role.TENANT_ADMIN, Membership.Role.VIEWER, Membership.Role.NOC_SOC])
    except AuthorizationDenied as error:
        raise PermissionDenied("Tenant workspace access denied.") from error
    zabbix_enrollments = AgentEnrollment.objects.filter(
        tenant=tenant, package__vendor=AgentPackage.Vendor.ZABBIX,
    ).select_related("tenant")
    asset_count = Asset.objects.filter(tenant=tenant).count()
    assessed = AssetCompliance.objects.filter(asset__tenant=tenant)
    compliance_counts = assessed.aggregate(
        compliant=Count("id", filter=Q(status=AssetCompliance.Status.COMPLIANT)),
        non_compliant=Count("id", filter=Q(status=AssetCompliance.Status.NON_COMPLIANT)),
    )
    last_assessed = assessed.aggregate(last_checked=Max("checked_at"))["last_checked"]
    if last_assessed is None:
        compliance_freshness = "not_assessed"
    elif timezone.now() - last_assessed <= timedelta(hours=26):
        compliance_freshness = "current"
    else:
        compliance_freshness = "stale"
    compliance_summary = {
        "assessed": assessed.count(),
        "compliant": compliance_counts["compliant"],
        "non_compliant": compliance_counts["non_compliant"],
        "unknown": asset_count - compliance_counts["compliant"] - compliance_counts["non_compliant"],
        "last_assessed": last_assessed,
        "freshness": compliance_freshness,
    }
    glpi_observations = list(
        AssetExternalIdentity.objects.filter(
            asset__tenant=tenant, source=AssetExternalIdentity.Source.GLPI,
        ).values("asset_id").annotate(last_seen=Max("last_seen_at"))
    )
    inventory_current = sum(
        _inventory_freshness(observation["last_seen"]) == "current"
        for observation in glpi_observations
    )
    inventory_stale = sum(
        _inventory_freshness(observation["last_seen"]) == "stale"
        for observation in glpi_observations
    )
    inventory_summary = {
        "current": inventory_current,
        "stale": inventory_stale,
        "not_reported": asset_count - inventory_current - inventory_stale,
        "last_observed": max((item["last_seen"] for item in glpi_observations if item["last_seen"]), default=None),
    }
    security_connector = SecurityConnector.objects.filter(
        tenant=tenant, provider=SecurityConnector.Provider.WAZUH,
    ).first()
    security_findings = wazuh_findings_for_connector(security_connector)
    security_freshness = wazuh_scan_state_for_connector(security_connector)
    # tenant-home-cloud-summary-v1
    from .models import CloudPostureConnector
    cloud_connectors = CloudPostureConnector.objects.filter(tenant=tenant)
    cloud_ready = cloud_connectors.filter(status=CloudPostureConnector.Status.READY).count()
    return render(request, "tenant_home.html", {
        "tenant": tenant,
        "asset_count": asset_count,
        "compliance_summary": compliance_summary,
        "inventory_summary": inventory_summary,
        "glpi_connector": InventoryConnector.objects.filter(tenant=tenant, provider=InventoryConnector.Provider.GLPI).first(),
        "glpi_console_url": _safe_console_url(InventoryConnector.objects.filter(tenant=tenant, provider=InventoryConnector.Provider.GLPI).values_list("base_url", flat=True).first()),
        "zabbix_console_url": _safe_console_url(os.environ.get("ZABBIX_DASHBOARD_WEB_URL")),
        "wazuh_console_url": _safe_console_url(os.environ.get("WAZUH_DASHBOARD_WEB_URL")),
        "glpi_sync_run": InventorySyncRun.objects.filter(connector__tenant=tenant, connector__provider=InventoryConnector.Provider.GLPI).first(),
        "agent_provisioning": TenantAgentProvisioning.objects.filter(tenant=tenant).first(),
        "zabbix_summary": summary_for_enrollments(zabbix_enrollments),
        "security_summary": wazuh_summary_for_connector(security_connector, asset_count),
        "security_findings": security_findings,
        "security_attention": attention_for_summary(security_findings),
        "security_freshness": security_freshness,
        "security_connector": security_connector,
        "cloud_connector_count": cloud_connectors.count(),
        "cloud_ready_count": cloud_ready,
        "is_provider": is_global_admin(request.user),
    })


def tenant_for_request(request, slug, roles):
    tenant = Tenant.objects.filter(slug=slug, active=True).first()
    if tenant is None:
        raise PermissionDenied("Tenant workspace is unavailable.")
    try:
        require_tenant_role(request.user, tenant.id, roles)
    except AuthorizationDenied as error:
        raise PermissionDenied("Tenant workspace access denied.") from error
    return tenant


def allowed_finding_status_values(finding):
    """Return the only portal workflow states reachable without an exception."""
    next_status = {
        SecurityFinding.Status.DETECTED: SecurityFinding.Status.TRIAGED,
        SecurityFinding.Status.TRIAGED: SecurityFinding.Status.APPROVED,
        SecurityFinding.Status.APPROVED: SecurityFinding.Status.SCHEDULED,
        SecurityFinding.Status.SCHEDULED: SecurityFinding.Status.REMEDIATED,
        SecurityFinding.Status.REMEDIATED: SecurityFinding.Status.AWAITING_VERIFICATION,
        SecurityFinding.Status.AWAITING_VERIFICATION: SecurityFinding.Status.VERIFIED_CLOSED,
    }.get(finding.status)
    return [finding.status, *([next_status] if next_status else [])]


@mfa_required
def security_findings(request, slug):
    """Tenant-scoped finding, severity, and reported-endpoint drill-down view."""
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.VIEWER, Membership.Role.NOC_SOC])
    all_findings = SecurityFinding.objects.filter(tenant=tenant)
    open_findings = all_findings.exclude(status=SecurityFinding.Status.VERIFIED_CLOSED)
    selected_severity = request.GET.get("severity", "").lower()
    filters = {
        "critical": (SecurityFinding.Severity.CRITICAL,), "high": (SecurityFinding.Severity.HIGH,),
        "medium": (SecurityFinding.Severity.MEDIUM,), "low": (SecurityFinding.Severity.LOW, SecurityFinding.Severity.INFORMATIONAL),
    }
    if selected_severity not in filters:
        selected_severity = ""
    selected_endpoint = request.GET.get("endpoint", "").strip()[:255]
    reported_only = request.GET.get("reported") == "1"
    findings = open_findings.select_related("asset")
    if selected_severity:
        findings = findings.filter(severity__in=filters[selected_severity])
    if selected_endpoint:
        findings = findings.filter(observed_hostname=selected_endpoint)
    elif reported_only:
        findings = findings.exclude(observed_hostname="")
    findings = findings.order_by("severity", "due_at", "-last_observed_at")
    latest_import = VulnerabilityImportRun.objects.filter(tenant=tenant).first()
    now = timezone.now()
    open_critical = open_findings.filter(severity=SecurityFinding.Severity.CRITICAL)
    severity_counts = {
        "critical": open_findings.filter(severity=SecurityFinding.Severity.CRITICAL).count(),
        "high": open_findings.filter(severity=SecurityFinding.Severity.HIGH).count(),
        "medium": open_findings.filter(severity=SecurityFinding.Severity.MEDIUM).count(),
        "low": open_findings.filter(severity__in=filters["low"]).count(),
    }
    top_endpoints = {
        name: list(open_findings.filter(severity__in=levels).exclude(observed_hostname="").values("observed_hostname").annotate(finding_count=Count("id")).order_by("-finding_count", "observed_hostname")[:5])
        for name, levels in filters.items()
    }
    total_by_severity = sum(severity_counts.values())
    percent = lambda name: round(100 * severity_counts[name] / total_by_severity, 2) if total_by_severity else 0
    critical_end = percent("critical")
    high_end = critical_end + percent("high")
    medium_end = high_end + percent("medium")
    import_current = bool(latest_import and latest_import.status == VulnerabilityImportRun.Status.SUCCEEDED and latest_import.completed_at and latest_import.completed_at >= now - timedelta(hours=26))
    reported_endpoint_count = open_findings.exclude(observed_hostname="").values("observed_hostname").distinct().count()
    asset_count = Asset.objects.filter(tenant=tenant).count()
    matched_asset_count = open_findings.filter(asset__isnull=False).values("asset_id").distinct().count()
    unmatched_endpoint_count = open_findings.filter(asset__isnull=True).exclude(observed_hostname="").values("observed_hostname").distinct().count()
    coverage_percent = round(100 * min(reported_endpoint_count, asset_count) / asset_count) if asset_count else 0
    return render(request, "security_findings.html", {
        "tenant": tenant, "findings": findings, "selected_severity": selected_severity,
        "selected_endpoint": selected_endpoint, "reported_only": reported_only,
        "can_manage_findings": is_global_admin(request.user), "is_provider": is_global_admin(request.user),
        "latest_vulnerability_import": latest_import,
        "latest_vulnerability_import_completed_utc": timezone.localtime(latest_import.completed_at, datetime_timezone.utc) if latest_import and latest_import.completed_at else None,
        "security_measurement": {"import_current": import_current, "open_findings": open_findings.count(), "critical_open": open_critical.count(), "critical_overdue": open_critical.filter(due_at__lt=now).count(), "critical_without_due": open_critical.filter(due_at__isnull=True).count(), "verified_closed": all_findings.filter(status=SecurityFinding.Status.VERIFIED_CLOSED).count(), "normalized_total": all_findings.count()},
        "security_dashboard": {**severity_counts, "top_endpoints": top_endpoints, "total_by_severity": total_by_severity, "open_findings": open_findings.count(), "import_current": import_current, "reported_endpoint_count": reported_endpoint_count, "asset_count": asset_count, "matched_asset_count": matched_asset_count, "unmatched_endpoint_count": unmatched_endpoint_count, "coverage_percent": coverage_percent, "critical_end": critical_end, "high_end": high_end, "medium_end": medium_end, "low_end": 100 if total_by_severity else 0, "critical_percent": percent("critical"), "high_percent": percent("high"), "medium_percent": percent("medium"), "low_percent": percent("low")},
    })

@mfa_required
def security_finding_create(request, slug):
    if not is_global_admin(request.user):
        raise PermissionDenied("Provider administrator access is required to create findings.")
    tenant = get_object_or_404(Tenant, slug=slug, active=True)
    form = SecurityFindingForm(request.POST or None, tenant=tenant)
    if request.method == "POST" and form.is_valid():
        finding = form.save(commit=False)
        finding.tenant = tenant
        finding.full_clean()
        finding.save()
        FindingAuditEvent.objects.create(
            finding=finding, actor=request.user, action=FindingAuditEvent.Action.CREATED,
            summary="Normalized finding created in the portal. No source system was changed.",
        )
        messages.success(request, "Finding created. No scanner, endpoint, or remediation job was run.")
        return redirect("security_finding_detail", slug=tenant.slug, finding_id=finding.id)
    return render(request, "security_finding_form.html", {
        "tenant": tenant, "form": form, "is_provider": True,
    })


@mfa_required
def security_finding_detail(request, slug, finding_id):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.VIEWER, Membership.Role.NOC_SOC])
    finding = get_object_or_404(SecurityFinding.objects.select_related("asset"), tenant=tenant, id=finding_id)
    can_manage = is_global_admin(request.user)
    remediation_form = FindingRemediationForm()
    exception_form = FindingExceptionForm()
    if request.method == "POST":
        if not can_manage:
            raise PermissionDenied("Provider administrator access is required to update remediation workflow.")
        action = request.POST.get("action")
        if action == "remediation":
            remediation_form = FindingRemediationForm(request.POST)
            if remediation_form.is_valid():
                remediation = remediation_form.save(commit=False)
                remediation.finding = finding
                remediation.save()
                FindingAuditEvent.objects.create(
                    finding=finding, actor=request.user, action=FindingAuditEvent.Action.REMEDIATION_RECORDED,
                    summary=f"Remediation record added: {remediation.get_status_display()}.",
                )
                messages.success(request, "Remediation record saved. Completion still requires independent verification.")
                return redirect("security_finding_detail", slug=tenant.slug, finding_id=finding.id)
        elif action == "exception":
            exception_form = FindingExceptionForm(request.POST, instance=getattr(finding, "exception", None))
            if exception_form.is_valid():
                exception = exception_form.save(commit=False)
                exception.finding = finding
                exception.save()
                finding.status = SecurityFinding.Status.ACCEPTED_EXCEPTION
                finding.save(update_fields=["status", "updated_at"])
                FindingAuditEvent.objects.create(
                    finding=finding, actor=request.user, action=FindingAuditEvent.Action.EXCEPTION_RECORDED,
                    summary="Time-bounded accepted exception recorded.",
                )
                messages.success(request, "Exception recorded with an expiry. The finding is not closed.")
                return redirect("security_finding_detail", slug=tenant.slug, finding_id=finding.id)
        elif action == "status":
            requested_status = request.POST.get("status")
            if requested_status not in SecurityFinding.Status.values:
                raise PermissionDenied("Invalid finding status.")
            if requested_status not in allowed_finding_status_values(finding):
                messages.error(request, "Use the defined remediation lifecycle; a finding cannot skip its required approval and verification stages.")
            elif requested_status == SecurityFinding.Status.REMEDIATED and not finding.remediations.filter(
                status=FindingRemediation.Status.COMPLETED,
                execution_reference__gt="",
            ).exists():
                messages.error(request, "Record a completed remediation with a safe execution reference before marking a finding remediated.")
            elif requested_status == SecurityFinding.Status.VERIFIED_CLOSED and not finding.evidence_reference:
                messages.error(request, "Add a safe independent evidence reference before marking a finding verified closed.")
            else:
                finding.status = requested_status
                finding.full_clean()
                finding.save()
                FindingAuditEvent.objects.create(
                    finding=finding, actor=request.user,
                    action=FindingAuditEvent.Action.VERIFIED_CLOSED if requested_status == SecurityFinding.Status.VERIFIED_CLOSED else FindingAuditEvent.Action.UPDATED,
                    summary=f"Finding status set to {finding.get_status_display()}.",
                )
                messages.success(request, "Finding status updated.")
                return redirect("security_finding_detail", slug=tenant.slug, finding_id=finding.id)
    return render(request, "security_finding_detail.html", {
        "tenant": tenant, "finding": finding,
        "remediations": finding.remediations.all(),
        "events": finding.audit_events.select_related("actor")[:50],
        "exception": getattr(finding, "exception", None),
        "remediation_form": remediation_form, "exception_form": exception_form,
        "allowed_status_values": allowed_finding_status_values(finding),
        "can_manage_findings": can_manage, "is_provider": is_global_admin(request.user),
    })


@mfa_required
def asset_list(request, slug):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.VIEWER, Membership.Role.NOC_SOC])
    can_manage_assets = is_global_admin(request.user) or Membership.objects.filter(
        tenant=tenant, user=request.user, role=Membership.Role.TENANT_ADMIN,
    ).exists()
    assets = list(Asset.objects.filter(tenant=tenant).select_related("location", "assigned_location", "department", "compliance").annotate(
        software_count=Count("software"),
        glpi_last_seen=Max(
            "assetexternalidentity__last_seen_at",
            filter=Q(assetexternalidentity__source=AssetExternalIdentity.Source.GLPI),
        ),
    ).order_by("name"))
    for asset in assets:
        asset.inventory_freshness = _inventory_freshness(asset.glpi_last_seen)
    return render(request, "asset_list.html", {
        "tenant": tenant,
        "assets": assets,
        "can_manage_assets": can_manage_assets,
        "placement_pending_count": Asset.objects.filter(tenant=tenant).filter(
            Q(assigned_location__isnull=True) | Q(department__isnull=True),
        ).count() if can_manage_assets else 0,
        "is_provider": is_global_admin(request.user),
    })


@mfa_required
def asset_detail(request, slug, asset_id):
    """Display source-derived inventory without allowing source mutation."""
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.VIEWER, Membership.Role.NOC_SOC])
    asset = get_object_or_404(
        Asset.objects.select_related("location", "assigned_location", "department"), pk=asset_id, tenant=tenant
    )
    glpi_last_seen = AssetExternalIdentity.objects.filter(
        asset=asset, source=AssetExternalIdentity.Source.GLPI,
    ).aggregate(last_seen=Max("last_seen_at"))["last_seen"]
    return render(request, "asset_detail.html", {
        "tenant": tenant,
        "asset": asset,
        "software": AssetSoftware.objects.filter(asset=asset).order_by("name", "version"),
        "network_interfaces": AssetNetworkInterface.objects.filter(asset=asset).order_by("name", "mac_address"),
        "compliance": AssetCompliance.objects.filter(asset=asset).first(),
        "glpi_last_seen": glpi_last_seen,
        "inventory_freshness": _inventory_freshness(glpi_last_seen),
        "can_manage_assets": is_global_admin(request.user) or Membership.objects.filter(tenant=tenant, user=request.user, role=Membership.Role.TENANT_ADMIN).exists(),
        "is_provider": is_global_admin(request.user),
    })


@mfa_required
def asset_placement(request, slug, asset_id):
    """Set customer-owned placement metadata without writing back to GLPI."""
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    asset = get_object_or_404(Asset.objects.select_related("location", "assigned_location", "department"), pk=asset_id, tenant=tenant)
    form = AssetPlacementForm(request.POST or None, instance=asset, tenant=tenant)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Asset placement updated in the portal. GLPI was not changed.")
        return redirect("asset_detail", slug=tenant.slug, asset_id=asset.id)
    return render(request, "asset_placement.html", {
        "tenant": tenant, "asset": asset, "form": form, "is_provider": is_global_admin(request.user),
    })


@mfa_required
def asset_placement_queue(request, slug):
    """List only assets that still need a customer placement assignment."""
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    locations = list(TenantLocation.objects.filter(tenant=tenant, active=True))
    departments = list(Department.objects.filter(tenant=tenant, active=True))
    locations_by_id = {str(location.id): location for location in locations}
    departments_by_id = {str(department.id): department for department in departments}
    assets = list(Asset.objects.filter(tenant=tenant).filter(
        Q(assigned_location__isnull=True) | Q(department__isnull=True),
    ).select_related("assigned_location", "department").order_by("name"))
    if request.method == "POST":
        updates = []
        errors = []
        for asset in assets:
            location_id = request.POST.get(f"location_{asset.id}", "")
            department_id = request.POST.get(f"department_{asset.id}", "")
            if location_id and location_id not in locations_by_id:
                errors.append(f"Invalid location selected for {asset.name}.")
            if department_id and department_id not in departments_by_id:
                errors.append(f"Invalid department selected for {asset.name}.")
            if not errors:
                updates.append((asset.id, locations_by_id.get(location_id), departments_by_id.get(department_id)))
        if errors:
            messages.error(request, " ".join(errors))
        else:
            updated_count = 0
            with transaction.atomic():
                locked_assets = {
                    asset.id: asset for asset in Asset.objects.select_for_update().filter(
                        tenant=tenant, id__in=[item[0] for item in updates],
                    ).filter(Q(assigned_location__isnull=True) | Q(department__isnull=True))
                }
                for asset_id, location, department in updates:
                    asset = locked_assets.get(asset_id)
                    if asset is None:
                        continue
                    changed = False
                    if location and asset.assigned_location_id != location.id:
                        asset.assigned_location = location
                        changed = True
                    if department and asset.department_id != department.id:
                        asset.department = department
                        changed = True
                    if changed:
                        asset.save(update_fields=["assigned_location", "department"])
                        updated_count += 1
            if updated_count:
                messages.success(request, f"Placement saved for {updated_count} asset{'s' if updated_count != 1 else ''}. GLPI was not changed.")
            else:
                messages.info(request, "No placement changes were selected.")
            return redirect("asset_placement_queue", slug=tenant.slug)
    return render(request, "asset_placement_queue.html", {
        "tenant": tenant, "assets": assets, "locations": locations, "departments": departments,
        "is_provider": is_global_admin(request.user),
    })


@mfa_required
def inventory_activity(request, slug):
    """Show the tenant's safe, stored GLPI import history without rerunning it."""
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.VIEWER, Membership.Role.NOC_SOC])
    return render(request, "inventory_activity.html", {
        "tenant": tenant,
        "runs": InventorySyncRun.objects.filter(
            connector__tenant=tenant,
            connector__provider=InventoryConnector.Provider.GLPI,
        ).select_related("connector")[:30],
        "is_provider": is_global_admin(request.user),
    })


@mfa_required
def compliance_rules(request, slug):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.VIEWER, Membership.Role.NOC_SOC])
    can_manage = is_global_admin(request.user) or Membership.objects.filter(
        tenant=tenant, user=request.user, role=Membership.Role.TENANT_ADMIN
    ).exists()
    form = SoftwareComplianceRuleForm(tenant=tenant)
    if request.method == "POST":
        if not can_manage:
            raise PermissionDenied("Tenant Administrator access is required to change compliance criteria.")
        if request.POST.get("action") == "evaluate":
            results = evaluate_tenant(tenant)
            ComplianceAuditEvent.objects.create(
                tenant=tenant, actor=request.user, action=ComplianceAuditEvent.Action.EVALUATED,
                summary=(f"{sum(results.values())} assets assessed; "
                         f"{results[AssetCompliance.Status.COMPLIANT]} compliant, "
                         f"{results[AssetCompliance.Status.NON_COMPLIANT]} non-compliant, "
                         f"{results[AssetCompliance.Status.UNKNOWN]} unknown."),
            )
            messages.success(request, f"Compliance recalculated: {sum(results.values())} assets assessed; {results[AssetCompliance.Status.COMPLIANT]} compliant, {results[AssetCompliance.Status.NON_COMPLIANT]} non-compliant, {results[AssetCompliance.Status.UNKNOWN]} unknown.")
            return redirect("compliance_rules", slug=tenant.slug)
        if request.POST.get("action") == "delete":
            rule = get_object_or_404(SoftwareComplianceRule, pk=request.POST.get("rule_id"), tenant=tenant)
            rule_name = rule.name
            rule.delete()
            ComplianceAuditEvent.objects.create(
                tenant=tenant, actor=request.user, action=ComplianceAuditEvent.Action.DELETED,
                criterion_name=rule_name, summary="Criterion deleted.",
            )
            messages.success(request, f"Criterion '{rule_name}' was deleted. Recalculate compliance to apply the change.")
            return redirect("compliance_rules", slug=tenant.slug)
        form = SoftwareComplianceRuleForm(request.POST, tenant=tenant)
        if form.is_valid():
            rule = form.save(commit=False)
            rule.tenant = tenant
            try:
                rule.save()
            except IntegrityError:
                form.add_error("name", "A criterion with this name already exists for this customer.")
            else:
                ComplianceAuditEvent.objects.create(
                    tenant=tenant, actor=request.user, action=ComplianceAuditEvent.Action.CREATED,
                    criterion_name=rule.name, summary="Criterion created.",
                )
                messages.success(request, "Criterion created. Recalculate compliance to apply it to imported software.")
                return redirect("compliance_rules", slug=tenant.slug)
    return render(request, "compliance_rules.html", {
        "tenant": tenant, "form": form,
        "rules": SoftwareComplianceRule.objects.filter(tenant=tenant).select_related("location", "department"),
        "can_manage_compliance": can_manage, "is_provider": is_global_admin(request.user),
    })


@mfa_required
def compliance_rule_edit(request, slug, rule_id):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.VIEWER, Membership.Role.NOC_SOC])
    can_manage = is_global_admin(request.user) or Membership.objects.filter(
        tenant=tenant, user=request.user, role=Membership.Role.TENANT_ADMIN
    ).exists()
    if not can_manage:
        raise PermissionDenied("Tenant Administrator access is required to change compliance criteria.")
    rule = get_object_or_404(SoftwareComplianceRule, pk=rule_id, tenant=tenant)
    form = SoftwareComplianceRuleForm(request.POST or None, instance=rule, tenant=tenant)
    if request.method == "POST" and form.is_valid():
        form.save()
        ComplianceAuditEvent.objects.create(
            tenant=tenant, actor=request.user, action=ComplianceAuditEvent.Action.UPDATED,
            criterion_name=rule.name, summary="Criterion updated.",
        )
        messages.success(request, "Criterion updated. Recalculate compliance to apply the change.")
        return redirect("compliance_rules", slug=tenant.slug)
    return render(request, "compliance_rule_edit.html", {
        "tenant": tenant, "rule": rule, "form": form,
        "is_provider": is_global_admin(request.user),
    })


@mfa_required
def compliance_audit(request, slug):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.VIEWER, Membership.Role.NOC_SOC])
    return render(request, "compliance_audit.html", {
        "tenant": tenant,
        "events": ComplianceAuditEvent.objects.filter(tenant=tenant).select_related("actor")[:100],
        "is_provider": is_global_admin(request.user),
    })


@mfa_required
def compliance_exceptions(request, slug):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.VIEWER, Membership.Role.NOC_SOC])
    return render(request, "compliance_exceptions.html", {
        "tenant": tenant,
        "exceptions": AssetCompliance.objects.filter(
            asset__tenant=tenant, status=AssetCompliance.Status.NON_COMPLIANT,
        ).select_related("asset", "asset__location", "asset__department").order_by("asset__name"),
        "is_provider": is_global_admin(request.user),
    })


def _csv_safe(value):
    value = "" if value is None else str(value)
    return f"'{value}" if value.startswith(("=", "+", "-", "@", "\t", "\r")) else value


@mfa_required
def compliance_export(request, slug):
    """Export only the requester's tenant-scoped, portal-held compliance data."""
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.VIEWER, Membership.Role.NOC_SOC])
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{tenant.slug}-compliance.csv"'
    response.write("\ufeff")
    writer = csv.writer(response)
    writer.writerow(["Asset", "Operating system", "Compliance status", "Last assessed", "Missing required", "Prohibited", "Unapproved", "Inventory method"])
    for asset in Asset.objects.filter(tenant=tenant).select_related("compliance").order_by("name"):
        compliance = getattr(asset, "compliance", None)
        writer.writerow([
            _csv_safe(asset.name), _csv_safe(asset.operating_system),
            _csv_safe(compliance.get_status_display() if compliance else "Not assessed"),
            _csv_safe(compliance.checked_at.isoformat() if compliance and compliance.checked_at else ""),
            _csv_safe(compliance.missing if compliance else ""),
            _csv_safe(compliance.prohibited if compliance else ""),
            _csv_safe(compliance.unapproved if compliance else ""),
            _csv_safe(asset.get_collection_method_display()),
        ])
    return response


@mfa_required
def asset_inventory_export(request, slug):
    """Export only the requester's tenant-scoped, portal-held inventory data."""
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.VIEWER, Membership.Role.NOC_SOC])
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{tenant.slug}-asset-inventory.csv"'
    response.write("\ufeff")
    writer = csv.writer(response)
    writer.writerow([
        "Asset", "Type", "Status", "Manufacturer", "Model", "Serial number",
        "Location", "Department", "IP address", "FQDN", "Operating system",
        "Inventory freshness", "Last GLPI observation", "Observed software", "Inventory method",
    ])
    assets = Asset.objects.filter(tenant=tenant).select_related("location", "department").annotate(
        software_count=Count("software"),
        glpi_last_seen=Max(
            "assetexternalidentity__last_seen_at",
            filter=Q(assetexternalidentity__source=AssetExternalIdentity.Source.GLPI),
        ),
    ).order_by("name")
    for asset in assets:
        writer.writerow([
            _csv_safe(asset.name), _csv_safe(asset.asset_type), _csv_safe(asset.status),
            _csv_safe(asset.manufacturer), _csv_safe(asset.model), _csv_safe(asset.serial_number),
            _csv_safe(asset.location.name if asset.location else asset.site),
            _csv_safe(asset.department.name if asset.department else ""),
            _csv_safe(asset.primary_ip), _csv_safe(asset.fqdn), _csv_safe(asset.operating_system),
            _csv_safe(_inventory_freshness(asset.glpi_last_seen).replace("_", " ").title()),
            _csv_safe(asset.glpi_last_seen.isoformat() if asset.glpi_last_seen else ""),
            _csv_safe(asset.software_count), _csv_safe(asset.get_collection_method_display()),
        ])
    return response


@mfa_required
def asset_create(request, slug):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    form = AssetCreateForm(request.POST or None, tenant=tenant)
    if request.method == "POST" and form.is_valid():
        asset = form.save(commit=False)
        asset.tenant = tenant
        try:
            asset.save()
        except IntegrityError:
            form.add_error("name", "An asset with this name already exists in this tenant.")
        else:
            return redirect("asset_list", slug=tenant.slug)
    return render(request, "asset_create.html", {"tenant": tenant, "form": form, "is_provider": is_global_admin(request.user)})


@mfa_required
def asset_structure(request, slug):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    location_form = TenantLocationForm(prefix="location")
    department_form = DepartmentForm(prefix="department")
    if request.method == "POST":
        kind = request.POST.get("kind")
        if kind == "location":
            location_form = TenantLocationForm(request.POST, prefix="location")
            if location_form.is_valid():
                location = location_form.save(commit=False)
                location.tenant = tenant
                try:
                    location.save()
                except IntegrityError:
                    location_form.add_error("name", "This location already exists for this customer.")
                else:
                    return redirect("asset_structure", slug=tenant.slug)
        elif kind == "department":
            department_form = DepartmentForm(request.POST, prefix="department")
            if department_form.is_valid():
                department = department_form.save(commit=False)
                department.tenant = tenant
                try:
                    department.save()
                except IntegrityError:
                    department_form.add_error("name", "This department already exists for this customer.")
                else:
                    return redirect("asset_structure", slug=tenant.slug)
        else:
            raise PermissionDenied("Unknown asset-structure request.")
    return render(request, "asset_structure.html", {
        "tenant": tenant,
        "locations": TenantLocation.objects.filter(tenant=tenant),
        "departments": Department.objects.filter(tenant=tenant),
        "location_form": location_form,
        "department_form": department_form,
        "is_provider": is_global_admin(request.user),
    })


@mfa_required
def glpi_connector(request, slug):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    connector = InventoryConnector.objects.filter(tenant=tenant, provider=InventoryConnector.Provider.GLPI).first()
    form = GlpiConnectorForm(request.POST or None, instance=connector)
    if request.method == "POST" and form.is_valid():
        configured = form.save(commit=False)
        configured.tenant = tenant
        configured.provider = InventoryConnector.Provider.GLPI
        configured.save()
        return redirect("tenant_home", slug=tenant.slug)
    return render(request, "glpi_connector.html", {"tenant": tenant, "form": form, "connector": connector, "is_provider": is_global_admin(request.user)})


@mfa_required
def security_connector(request, slug):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    connector = SecurityConnector.objects.filter(tenant=tenant, provider=SecurityConnector.Provider.WAZUH).first()
    form = SecurityConnectorForm(request.POST or None, instance=connector)
    if request.method == "POST" and form.is_valid():
        configured = form.save(commit=False)
        configured.tenant = tenant
        configured.provider = SecurityConnector.Provider.WAZUH
        configured.save()
        messages.success(request, "Wazuh configuration reference saved. No Wazuh connection was made.")
        return redirect("security_connector", slug=tenant.slug)
    return render(request, "security_connector.html", {
        "tenant": tenant,
        "form": form,
        "connector": connector,
        "is_provider": is_global_admin(request.user),
    })


@mfa_required
def agent_enrollments(request, slug):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    form = AgentEnrollmentForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        enrollment = form.save(commit=False)
        enrollment.tenant = tenant
        enrollment.requested_by = request.user
        # A tenant may self-serve only after a provider has configured its
        # non-secret provisioning references and approved the chosen package.
        # This removes the per-endpoint provider "Prepare bootstrap" action
        # without allowing an unconfigured tenant to create a usable package.
        provisioning = TenantAgentProvisioning.objects.filter(tenant=tenant).first()
        zabbix_ready = enrollment.package and enrollment.package.vendor == AgentPackage.Vendor.ZABBIX
        glpi_ready = provisioning and provisioning.status == TenantAgentProvisioning.Status.CONFIGURED and all((
            provisioning.glpi_inventory_url,
            provisioning.glpi_entity_scope,
            provisioning.inventory_tag,
            provisioning.credential_reference,
        ))
        if (
            enrollment.package
            and enrollment.package.status == AgentPackage.Status.APPROVED
            and enrollment.package.operating_system == enrollment.operating_system
            and (zabbix_ready or glpi_ready)
        ):
            enrollment.status = AgentEnrollment.Status.READY
            enrollment.package_ready_at = timezone.now()
        enrollment.save()
        AgentEnrollmentEvent.objects.create(
            enrollment=enrollment, actor=request.user, event_type=AgentEnrollmentEvent.EventType.REQUESTED
        )
        if enrollment.status == AgentEnrollment.Status.READY:
            AgentEnrollmentEvent.objects.create(
                enrollment=enrollment, actor=request.user, event_type=AgentEnrollmentEvent.EventType.BOOTSTRAP_READY
            )
        return redirect("agent_enrollments", slug=tenant.slug)
    return render(request, "agent_enrollments.html", {
        "tenant": tenant,
        "form": form,
        "enrollments": AgentEnrollment.objects.filter(tenant=tenant),
        "is_provider": is_global_admin(request.user),
    })


def accept_invitation(request, token):
    invitation = TenantAdminInvitation.objects.filter(token_hash=invitation_token_hash(token)).select_related("tenant").first()
    if not invitation or invitation.accepted_at or invitation.revoked_at or invitation.expires_at <= timezone.now():
        raise PermissionDenied("This invitation is invalid, expired, or has already been used.")
    form = InvitationAcceptForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        from django.contrib.auth import get_user_model
        user_model = get_user_model()
        if user_model.objects.filter(username__iexact=invitation.email).exists():
            form.add_error(None, "An account with this email already exists. Ask the provider administrator to grant access.")
        else:
            user = user_model.objects.create_user(
                username=invitation.email, email=invitation.email, password=form.cleaned_data["password"]
            )
            Membership.objects.create(tenant=invitation.tenant, user=user, role=Membership.Role.TENANT_ADMIN)
            MFAProfile.objects.create(user=user)
            invitation.accepted_at = timezone.now()
            invitation.save(update_fields=["accepted_at"])
            login(request, user)
            request.session["mfa_password_user_id"] = str(user.pk)
            return redirect("mfa_enroll")
    return render(request, "invitation_accept.html", {"form": form, "tenant": invitation.tenant})


@mfa_required
def cloud_posture_connector(request, slug):
    """Configure non-secret cloud posture references only; no provider call occurs here."""
    from .forms import CloudPostureConnectorForm
    from .models import CloudPostureConnector
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    can_manage = is_global_admin(request.user) or Membership.objects.filter(
        tenant=tenant, user=request.user, role=Membership.Role.TENANT_ADMIN,
    ).exists()
    if not can_manage:
        raise PermissionDenied("Tenant Administrator access is required.")
    form = CloudPostureConnectorForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        connector = form.save(commit=False)
        connector.tenant = tenant
        connector.read_only = True
        try:
            connector.save()
        except IntegrityError:
            form.add_error("account_scope", "This provider and scope already exist for this tenant.")
        else:
            messages.success(request, "Read-only cloud connector saved. No cloud login, scan, assessment, or remediation was run.")
            return redirect("cloud_posture_connector", slug=tenant.slug)
    return render(request, "cloud_posture_connector.html", {
        "tenant": tenant,
        "form": form,
        "connectors": CloudPostureConnector.objects.filter(tenant=tenant),
        "is_provider": is_global_admin(request.user),
    })


@mfa_required
def cloud_posture_dashboard(request, slug):
    """Tenant-safe cloud posture summary from portal-owned normalized records only."""
    from .models import CloudPostureAssessmentRun, CloudPostureConnector
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.NOC_SOC, Membership.Role.VIEWER])
    connectors = CloudPostureConnector.objects.filter(tenant=tenant)
    findings = SecurityFinding.objects.filter(tenant=tenant, source=SecurityFinding.Source.PROWLER)
    open_findings = findings.exclude(status__in=[SecurityFinding.Status.VERIFIED_CLOSED, SecurityFinding.Status.ACCEPTED_EXCEPTION])
    severity_counts = {row["severity"]: row["total"] for row in open_findings.values("severity").annotate(total=Count("id"))}
    return render(request, "cloud_posture_dashboard.html", {
        "tenant": tenant,
        "is_provider": is_global_admin(request.user),
        "connectors": connectors,
        "recent_runs": CloudPostureAssessmentRun.objects.filter(connector__tenant=tenant).select_related("connector")[:10],
        "open_total": open_findings.count(),
        "critical_total": severity_counts.get(SecurityFinding.Severity.CRITICAL, 0),
        "high_total": severity_counts.get(SecurityFinding.Severity.HIGH, 0),
        "latest_finding_at": findings.order_by("-last_observed_at").values_list("last_observed_at", flat=True).first(),
    })


@mfa_required
def cloud_posture_export(request, slug):
    """Download a safe tenant-owned cloud posture CSV; excludes secrets and raw provider payloads."""
    from .models import CloudPostureAssessmentRun, CloudPostureConnector
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.NOC_SOC, Membership.Role.VIEWER])
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{tenant.slug}-cloud-posture.csv"'
    writer = csv.writer(response)
    writer.writerow(["record_type", "provider", "scope", "severity", "control", "finding_status", "assessment_status", "observed_or_started_at"])
    for connector in CloudPostureConnector.objects.filter(tenant=tenant):
        writer.writerow(["connector", connector.provider, connector.account_scope, "", "", connector.get_status_display(), "", connector.configured_at.isoformat()])
    for finding in SecurityFinding.objects.filter(tenant=tenant, source=SecurityFinding.Source.PROWLER):
        writer.writerow(["finding", "", "", finding.severity, finding.control_id, finding.status, "", finding.last_observed_at.isoformat()])
    for run in CloudPostureAssessmentRun.objects.filter(connector__tenant=tenant).select_related("connector"):
        writer.writerow(["assessment_run", run.connector.provider, run.connector.account_scope, "", "", "", run.status, run.started_at.isoformat()])
    return response

from django.contrib import messages
from django.shortcuts import redirect, render
from .forms import GreenboneScanScopeForm
from .models import GreenboneScanScope, Membership


@mfa_required
def greenbone_scan_scopes(request, slug):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN])
    form = GreenboneScanScopeForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        scope = form.save(commit=False)
        scope.tenant = tenant
        scope.requested_by = request.user
        scope.save()
        messages.success(request, "Greenbone scan-scope request recorded. It does not create a Greenbone target or start a scan.")
        return redirect("greenbone_scan_scopes", slug=tenant.slug)
    return render(request, "greenbone_scan_scopes.html", {
        "tenant": tenant,
        "form": form,
        "scopes": GreenboneScanScope.objects.filter(tenant=tenant),
        "is_provider": is_global_admin(request.user),
    })

import ipaddress

from django.core.exceptions import PermissionDenied
from django.utils import timezone


_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def _greenbone_scope_review_blocker(scope):
    if scope.maintenance_window_end <= timezone.now():
        return "The recorded maintenance window has already ended. Record a new approved window before review."
    try:
        candidate = ipaddress.ip_network(scope.target_reference.strip(), strict=False)
    except ValueError:
        return None
    if any(candidate.subnet_of(network) for network in _DOCUMENTATION_NETWORKS):
        return "Documentation-only IP ranges cannot be approved as Greenbone scan targets."
    return None


@mfa_required
def greenbone_scan_scope_queue(request):
    if not is_global_admin(request.user):
        raise PermissionDenied("Global Administrator access is required.")
    return render(request, "greenbone_scan_scope_queue.html", {
        "scopes": GreenboneScanScope.objects.select_related("tenant", "requested_by", "reviewed_by").all(),
        "is_provider": True,
    })


@mfa_required
def greenbone_scan_scope_action(request, scope_id, action):
    if request.method != "POST":
        raise PermissionDenied("Scan-scope review actions require a POST request.")
    if not is_global_admin(request.user):
        raise PermissionDenied("Global Administrator access is required.")
    scope = get_object_or_404(GreenboneScanScope, pk=scope_id)
    if scope.status != GreenboneScanScope.Status.REQUESTED:
        messages.info(request, "This Greenbone scan-scope request has already been reviewed.")
    elif action == "approve":
        blocker = _greenbone_scope_review_blocker(scope)
        if blocker:
            messages.error(request, blocker)
            return redirect("greenbone_scan_scope_queue")
        scope.status = GreenboneScanScope.Status.APPROVED
        scope.reviewed_by = request.user
        scope.reviewed_at = timezone.now()
        scope.save(update_fields=["status", "reviewed_by", "reviewed_at", "updated_at"])
        messages.success(request, "Greenbone scan scope approved. Approval alone does not create a target or start a scan.")
    elif action == "cancel":
        scope.status = GreenboneScanScope.Status.CANCELLED
        scope.reviewed_by = request.user
        scope.reviewed_at = timezone.now()
        scope.save(update_fields=["status", "reviewed_by", "reviewed_at", "updated_at"])
        messages.success(request, "Greenbone scan-scope request cancelled. No Greenbone target or scan was created.")
    else:
        raise PermissionDenied("Unsupported scan-scope review action.")
    return redirect("greenbone_scan_scope_queue")


from .models import GreenboneAssessmentRun


@mfa_required
def greenbone_assessment_history(request, slug):
    tenant = tenant_for_request(request, slug, [Membership.Role.TENANT_ADMIN, Membership.Role.NOC_SOC, Membership.Role.VIEWER])
    return render(request, "greenbone_assessment_history.html", {
        "tenant": tenant,
        "runs": GreenboneAssessmentRun.objects.filter(tenant=tenant)[:20],
        "is_provider": is_global_admin(request.user),
    })


@mfa_required
def wazuh_endpoint_correlation(request, slug):
    if not is_global_admin(request.user):
        raise PermissionDenied("Global Administrator access is required.")
    tenant = get_object_or_404(Tenant, slug=slug, active=True)
    unmatched = list(
        SecurityFinding.objects.filter(
            tenant=tenant, source=SecurityFinding.Source.WAZUH, asset__isnull=True,
        ).exclude(observed_hostname="").values_list("observed_hostname", flat=True).distinct().order_by("observed_hostname")
    )
    if request.method == "POST":
        form = WazuhEndpointCorrelationForm(request.POST, tenant=tenant)
        if form.is_valid():
            hostname = form.cleaned_data["hostname"]
            if hostname not in unmatched:
                raise PermissionDenied("This Wazuh endpoint is not available for correlation.")
            asset = form.cleaned_data["asset"]
            link, created = WazuhEndpointAssetLink.objects.update_or_create(
                tenant=tenant, hostname=hostname,
                defaults={"asset": asset, "created_by": request.user},
            )
            updated = SecurityFinding.objects.filter(
                tenant=tenant, source=SecurityFinding.Source.WAZUH,
                observed_hostname=hostname, asset__isnull=True,
            ).update(asset=asset)
            first_finding = SecurityFinding.objects.filter(
                tenant=tenant, source=SecurityFinding.Source.WAZUH, observed_hostname=hostname,
            ).order_by("id").first()
            if first_finding:
                FindingAuditEvent.objects.create(
                    finding=first_finding, actor=request.user, action=FindingAuditEvent.Action.UPDATED,
                    summary=f"Wazuh endpoint correlated to a verified tenant asset; {updated} finding records updated.",
                )
            messages.success(request, "Wazuh endpoint correlated to the selected asset. Existing findings now show the asset inventory IP when present.")
            return redirect("wazuh_endpoint_correlation", slug=tenant.slug)
    else:
        form = WazuhEndpointCorrelationForm(tenant=tenant)
    linked = WazuhEndpointAssetLink.objects.filter(tenant=tenant).select_related("asset")
    return render(request, "wazuh_endpoint_correlation.html", {
        "tenant": tenant, "form": form, "unmatched": unmatched, "linked": linked, "is_provider": True,
    })

from django.contrib.auth import get_user_model
from django.core.management import call_command
from datetime import timedelta
from io import StringIO
from pathlib import Path
from django.test import TestCase, override_settings
from django.utils import timezone
from unittest.mock import patch
from .authorization import AuthorizationDenied, require_asset_access, require_tenant_role, visible_tenants
from .mfa import decrypt_secret, encrypt_secret, generate_secret, verify_code
from .invitations import invitation_token_hash
from .models import AgentEnrollment, AgentEnrollmentEvent, AgentPackage, AgentProvisioningJob, AgentRegistrationValidation, Asset, AssetCompliance, AssetExternalIdentity, AssetNetworkInterface, AssetSoftware, ComplianceAuditEvent, Department, InventoryConnector, InventorySyncRun, MFAProfile, Membership, SecurityConnector, SoftwareComplianceRule, Tenant, TenantAdminInvitation, TenantAgentProvisioning, TenantLocation
from .secret_store import SecretUnavailable, has_secret, resolve_secret
from .envelope import generate_delivery_token, hash_delivery_token
from .registration import hash_registration_code
from .envelope import decode_public_key, seal_configuration
from .zabbix_dashboard import summary_for_enrollments


TEST_FERNET_KEY = "u4YNM35scWbrYU84fVFJxYcC7E2a9QHnvqHqVTwYod4="


@override_settings(LSMON_MFA_ENCRYPTION_KEY=TEST_FERNET_KEY)
class TenantBoundaryTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("tenant-a")
        self.tenant_a = Tenant.objects.create(name="A", slug="a")
        self.tenant_b = Tenant.objects.create(name="B", slug="b")
        Membership.objects.create(tenant=self.tenant_a, user=self.user, role=Membership.Role.TENANT_ADMIN)
        self.asset_b = Asset.objects.create(tenant=self.tenant_b, name="B-server", asset_type="server")

    def _mfa_verified(self, user):
        profile = MFAProfile.objects.create(user=user, secret_ciphertext=encrypt_secret(generate_secret()))
        profile.enrolled_at = profile.last_verified_at = __import__("django.utils.timezone", fromlist=["now"]).now()
        profile.save(update_fields=["enrolled_at", "last_verified_at"])
        session = self.client.session
        session["mfa_verified_user_id"] = str(user.pk)
        session.save()

    def test_linux_pem_rsa_public_key_is_accepted_for_encrypted_delivery(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import hashes, hmac, padding as symmetric_padding, serialization
        from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        import base64
        import json
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        encoded = base64.urlsafe_b64encode(pem).rstrip(b"=").decode("ascii")
        self.assertEqual(decode_public_key(encoded, "rsa-pem-public-v1").key_size, 3072)
        configuration = {"server": "https://example.test/inventory", "tag": "linux-test"}
        envelope = json.loads(seal_configuration(encoded, configuration, context="linux-test", algorithm="rsa-pem-public-v1"))
        self.assertEqual(envelope["algorithm"], "rsa-oaep-sha256+a256cbc-hs256")
        def unb64(value):
            return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        keys = private_key.decrypt(
            unb64(envelope["encrypted_key"]),
            asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        aad, iv, ciphertext = b"lsmon-agent-delivery-v1:linux-test", unb64(envelope["iv"]), unb64(envelope["ciphertext"])
        authenticator = hmac.HMAC(keys[32:], hashes.SHA256())
        authenticator.update(aad + iv + ciphertext)
        self.assertEqual(authenticator.finalize(), unb64(envelope["tag"]))
        decryptor = Cipher(algorithms.AES(keys[:32]), modes.CBC(iv)).decryptor()
        unpadder = symmetric_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpadder.finalize()
        self.assertEqual(json.loads(plaintext), configuration)

    def test_tenant_admin_cannot_access_other_tenant_asset(self):
        with self.assertRaises(AuthorizationDenied):
            require_asset_access(self.user, self.asset_b, [Membership.Role.TENANT_ADMIN])

    def test_global_admin_can_access_any_active_tenant(self):
        global_admin = get_user_model().objects.create_user("global-admin")
        Membership.objects.create(user=global_admin, role=Membership.Role.GLOBAL_ADMIN)
        self.assertIsNone(require_tenant_role(global_admin, self.tenant_b.id, []))
        self.assertEqual(list(visible_tenants(global_admin)), [self.tenant_a, self.tenant_b])

    def test_portal_requires_sign_in(self):
        response = self.client.get("/")
        self.assertRedirects(response, "/sign-in/?next=%2F")

    def test_tenant_page_is_scoped_to_membership(self):
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.get("/tenants/")
        self.assertRedirects(response, "/t/a/")

    def test_global_tenant_list_links_to_workspace_and_scoped_assets(self):
        global_admin = get_user_model().objects.create_user("global-tenant-navigation")
        Membership.objects.create(user=global_admin, role=Membership.Role.GLOBAL_ADMIN)
        Asset.objects.create(tenant=self.tenant_a, name="Imported computer", asset_type="Computer")
        self.client.force_login(global_admin)
        self._mfa_verified(global_admin)

        response = self.client.get("/tenants/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'href="/t/a/"')
        self.assertContains(response, 'href="/t/a/assets/"')
        self.assertContains(response, "1 asset")

    def test_operations_is_denied_to_tenant_admin(self):
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.get("/operations/")
        self.assertEqual(response.status_code, 403)

    def test_totp_secret_is_encrypted_and_verifiable(self):
        import pyotp
        secret = generate_secret()
        ciphertext = encrypt_secret(secret)
        self.assertNotEqual(ciphertext, secret)
        self.assertEqual(decrypt_secret(ciphertext), secret)
        self.assertTrue(verify_code(ciphertext, pyotp.TOTP(secret).now()))

    def test_global_admin_can_create_tenant_and_pending_invitation(self):
        global_admin = get_user_model().objects.create_user("admin@tecstaqops.com")
        Membership.objects.create(user=global_admin, role=Membership.Role.GLOBAL_ADMIN)
        self.client.force_login(global_admin)
        self._mfa_verified(global_admin)
        response = self.client.post("/tenants/create/", {
            "name": "Tecstaq", "tenant_admin_email": "tenant.admin@example.test",
        })
        self.assertRedirects(response, "/tenants/")
        tenant = Tenant.objects.get(name="Tecstaq")
        self.assertEqual(tenant.slug, "tecstaq")
        provisioning = TenantAgentProvisioning.objects.get(tenant=tenant)
        self.assertEqual(provisioning.inventory_tag, "tecstaq")
        self.assertEqual(provisioning.status, TenantAgentProvisioning.Status.PENDING)
        invitation = TenantAdminInvitation.objects.get(tenant=tenant)
        self.assertEqual(invitation.email, "tenant.admin@example.test")
        self.assertIsNone(invitation.accepted_at)
        self.assertIsNone(invitation.token_hash)

    def test_tenant_admin_dashboard_and_other_tenant_route_are_denied_or_scoped(self):
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        self.assertRedirects(self.client.get("/"), "/t/a/")
        self.assertEqual(self.client.get("/t/a/").status_code, 200)
        self.assertEqual(self.client.get("/t/b/").status_code, 403)

    def test_tenant_admin_can_register_only_own_assets_and_glpi_configuration(self):
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.post("/t/a/assets/add/", {
            "name": "Tecstaq firewall", "asset_type": "firewall", "primary_ip": "10.10.10.1",
            "fqdn": "fw01.tecstaq.example", "operating_system": "FirewallOS 8", "site": "Pune",
            "collection_method": "glpi_snmp", "status": "active",
        })
        self.assertRedirects(response, "/t/a/assets/")
        asset = Asset.objects.get(tenant=self.tenant_a, name="Tecstaq firewall")
        self.assertEqual(str(asset.primary_ip), "10.10.10.1")
        self.assertEqual(asset.collection_method, Asset.CollectionMethod.GLPI_SNMP)
        self.assertEqual(self.client.get("/t/b/assets/").status_code, 403)
        response = self.client.post("/t/a/integrations/glpi/", {
            "base_url": "https://glpi.tecstaq.example", "credential_reference": "LSMON_GLPI_TECSTAQ_TOKEN", "scope": "Tecstaq / Entity 12",
        })
        self.assertRedirects(response, "/t/a/")
        connector = InventoryConnector.objects.get(tenant=self.tenant_a)
        self.assertEqual(connector.provider, InventoryConnector.Provider.GLPI)
        self.assertEqual(connector.credential_reference, "LSMON_GLPI_TECSTAQ_TOKEN")

    def test_tenant_admin_can_save_only_own_wazuh_configuration_reference(self):
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.post("/t/a/integrations/wazuh/", {
            "base_url": "https://127.0.0.1:55000/",
            "credential_reference": "LSMON_WAZUH_TECSTAQ_READ",
            "scope": "tecstaq",
        })
        self.assertRedirects(response, "/t/a/integrations/wazuh/")
        connector = SecurityConnector.objects.get(tenant=self.tenant_a)
        self.assertEqual(connector.provider, SecurityConnector.Provider.WAZUH)
        self.assertEqual(connector.base_url, "https://127.0.0.1:55000")
        self.assertEqual(connector.credential_reference, "LSMON_WAZUH_TECSTAQ_READ")
        self.assertEqual(self.client.get("/t/b/integrations/wazuh/").status_code, 403)

    def test_wazuh_configuration_requires_https_and_tenant_admin_role(self):
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.post("/t/a/integrations/wazuh/", {
            "base_url": "http://127.0.0.1:55000",
            "credential_reference": "LSMON_WAZUH_TECSTAQ_READ",
            "scope": "tecstaq",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Use an HTTPS Wazuh API URL.")
        self.assertFalse(SecurityConnector.objects.exists())
        viewer = get_user_model().objects.create_user("viewer-a")
        Membership.objects.create(tenant=self.tenant_a, user=viewer, role=Membership.Role.VIEWER)
        self.client.force_login(viewer)
        self._mfa_verified(viewer)
        self.assertEqual(self.client.get("/t/a/integrations/wazuh/").status_code, 403)

    def test_tenant_asset_hierarchy_and_asset_assignment_are_tenant_scoped(self):
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.post("/t/a/assets/structure/", {
            "kind": "location", "location-name": "Head Office", "location-code": "HO",
        })
        self.assertRedirects(response, "/t/a/assets/structure/")
        location = TenantLocation.objects.get(tenant=self.tenant_a, name="Head Office")
        response = self.client.post("/t/a/assets/structure/", {
            "kind": "department", "department-name": "Finance", "department-code": "FIN",
        })
        self.assertRedirects(response, "/t/a/assets/structure/")
        department = Department.objects.get(tenant=self.tenant_a, name="Finance")
        foreign_location = TenantLocation.objects.create(tenant=self.tenant_b, name="Other customer site")
        response = self.client.post("/t/a/assets/add/", {
            "name": "Finance-PC-01", "asset_type": "Computer", "location": foreign_location.pk,
            "department": department.pk, "collection_method": "manual", "status": "active",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Asset.objects.filter(tenant=self.tenant_a, name="Finance-PC-01").exists())
        response = self.client.post("/t/a/assets/add/", {
            "name": "Finance-PC-01", "asset_type": "Computer", "location": location.pk,
            "department": department.pk, "collection_method": "manual", "status": "active",
        })
        self.assertRedirects(response, "/t/a/assets/")
        asset = Asset.objects.get(tenant=self.tenant_a, name="Finance-PC-01")
        self.assertEqual(asset.location, location)
        self.assertEqual(asset.department, department)

    def test_glpi_preview_and_apply_are_tenant_scoped_and_do_not_touch_glpi(self):
        connector = InventoryConnector.objects.create(
            tenant=self.tenant_a, provider=InventoryConnector.Provider.GLPI,
            base_url="https://glpi.example.test", credential_reference="LSMON_GLPI_A_SYNC", scope="Entity A",
        )
        other_asset = Asset.objects.create(tenant=self.tenant_b, name="Other customer computer", asset_type="Computer")
        from .models import AssetExternalIdentity, InventorySyncRun
        AssetExternalIdentity.objects.create(
            asset=other_asset, source=AssetExternalIdentity.Source.GLPI, external_id="42",
        )
        from .glpi_sync import GlpiComputer, GlpiNetworkInterface
        adapter = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
        adapter.list_computers.return_value = [GlpiComputer(external_id="42", name="Tecstaq-PC", location_name="Head Office")]
        with patch("lsmon_core.management.commands.sync_glpi_assets.GlpiReadOnlyAdapter", return_value=adapter), patch.dict(
            "os.environ", {"LSMON_GLPI_SYNC_SECRET_LSMON_GLPI_A_SYNC": '{"app_token":"app","user_token":"user"}'}, clear=False
        ):
            output = StringIO()
            call_command("sync_glpi_assets", "--tenant-slug", "a", stdout=output)
            self.assertIn("GLPI_SYNC_PREVIEW tenant=a discovered=1 create=1 update=0 review=0", output.getvalue())
            call_command("sync_glpi_assets", "--tenant-slug", "a", "--apply", stdout=output)
        imported = Asset.objects.get(tenant=self.tenant_a, name="Tecstaq-PC")
        self.assertEqual(imported.location.name, "Head Office")
        self.assertEqual(imported.collection_method, Asset.CollectionMethod.GLPI_AGENT)
        other_asset.refresh_from_db()
        self.assertEqual(other_asset.name, "Other customer computer")
        self.assertEqual(InventorySyncRun.objects.filter(connector=connector, status=InventorySyncRun.Status.APPLIED).count(), 1)
        self.assertEqual(adapter.open.call_count, 2)
        self.assertEqual(adapter.close.call_count, 2)

    def test_glpi_reader_defaults_to_the_ipv4_only_transport(self):
        from .glpi_sync import GlpiReadOnlyAdapter, Request, open_ipv4_https

        adapter = GlpiReadOnlyAdapter(
            "https://glpi.example.test",
            {"app_token": "app", "user_token": "user"},
        )
        self.assertIs(adapter.opener, open_ipv4_https)
        captured = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *unused):
                return False

            def read(self):
                return b'{"session_token":"test"}'

        def opener(request, timeout):
            captured.update(dict(request.header_items()))
            return Response()

        GlpiReadOnlyAdapter(
            "https://glpi.example.test",
            {"app_token": "app", "user_token": "user"},
            opener=opener,
        ).open()
        self.assertEqual(captured["User-agent"], "LSMON-GLPI-ReadOnly/1.0")

    def test_glpi_routing_verification_reads_one_computer_without_writing_portal_state(self):
        InventoryConnector.objects.create(
            tenant=self.tenant_a, provider=InventoryConnector.Provider.GLPI,
            base_url="https://glpi.example.test", credential_reference="LSMON_GLPI_A_ROUTE", scope="Entity A",
        )
        from .glpi_sync import GlpiComputer
        adapter = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
        adapter.get_computer.return_value = GlpiComputer(
            external_id="9001", name="Fresh-endpoint", entity_name="Tecstaq",
        )
        before_runs = InventorySyncRun.objects.count()
        with patch("lsmon_core.management.commands.verify_glpi_routing.GlpiReadOnlyAdapter", return_value=adapter), patch.dict(
            "os.environ", {"LSMON_GLPI_SYNC_SECRET_LSMON_GLPI_A_ROUTE": '{"app_token":"app","user_token":"user"}'}, clear=False,
        ):
            output = StringIO()
            call_command(
                "verify_glpi_routing", "--tenant-slug", "a", "--glpi-computer-id", "9001",
                "--expected-entity", "tecstaq", stdout=output,
            )
        self.assertIn("GLPI_ROUTING_VERIFIED tenant=a computer_id=9001", output.getvalue())
        self.assertEqual(InventorySyncRun.objects.count(), before_runs)
        adapter.open.assert_called_once()
        adapter.get_computer.assert_called_once_with("9001")
        adapter.close.assert_called_once()

    def test_glpi_full_apply_rebuilds_software_only_after_successful_full_read(self):
        InventoryConnector.objects.create(
            tenant=self.tenant_a, provider=InventoryConnector.Provider.GLPI,
            base_url="https://glpi.example.test", credential_reference="LSMON_GLPI_A_FULL", scope="Entity A",
        )
        from .glpi_sync import GlpiComputer, GlpiNetworkInterface
        adapter = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
        adapter.list_computers_full.return_value = (
            [GlpiComputer(
                external_id="99", name="Full-PC", serial_number="SER-99", manufacturer="Acme",
                model="Model X", operating_system="Windows 11 Pro", location_name="Head Office",
                primary_ip="10.10.0.9", fqdn="full-pc.example.test",
                network_interfaces=(GlpiNetworkInterface(
                    external_id="port-1", name="Ethernet", mac_address="aa:bb:cc:dd:ee:ff",
                    network_name="office-lan", ip_addresses=("10.10.0.9", "fe80::1"),
                ),),
            )],
            {"99": [("Microsoft Defender", "4.18"), ("Adobe Reader", "2026")]},
        )
        with patch("lsmon_core.management.commands.sync_glpi_assets.GlpiReadOnlyAdapter", return_value=adapter), patch.dict(
            "os.environ", {"LSMON_GLPI_SYNC_SECRET_LSMON_GLPI_A_FULL": '{"app_token":"app","user_token":"user"}'}, clear=False
        ):
            output = StringIO()
            call_command("sync_glpi_assets", "--tenant-slug", "a", "--limit", "1", "--full", "--apply", stdout=output)
        asset = Asset.objects.get(tenant=self.tenant_a, name="Full-PC")
        self.assertEqual(str(asset.primary_ip), "10.10.0.9")
        self.assertEqual(asset.fqdn, "full-pc.example.test")
        self.assertEqual(asset.location.name, "Head Office")
        self.assertEqual(list(AssetSoftware.objects.filter(asset=asset).values_list("name", "version")), [
            ("Adobe Reader", "2026"), ("Microsoft Defender", "4.18"),
        ])
        interface = AssetNetworkInterface.objects.get(asset=asset, external_id="port-1")
        self.assertEqual(interface.name, "Ethernet")
        self.assertEqual(interface.mac_address, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(interface.ip_addresses, ["10.10.0.9", "fe80::1"])
        self.assertIn("GLPI_SYNC_APPLIED tenant=a discovered=1 create=1 update=0 review=0", output.getvalue())

    def test_glpi_full_reader_uses_only_os_inventory_labels(self):
        from .glpi_sync import GlpiComputer, GlpiReadOnlyAdapter

        adapter = GlpiReadOnlyAdapter("https://glpi.example.test", {"app_token": "app", "user_token": "user"})
        computer = GlpiComputer(external_id="99", name="Full-PC", operating_system="")
        with patch.object(adapter, "list_computers", return_value=[computer]), \
             patch.object(adapter, "_computer_detail", return_value=computer), \
             patch.object(adapter, "_operating_system_for_computer", return_value="Microsoft Windows 11 Pro 25H2 build 26200.8524"), \
             patch.object(adapter, "_network_interfaces_for_computer", return_value=()), \
             patch.object(adapter, "_software_version_names", return_value={}), \
             patch.object(adapter, "_software_for_computer", return_value=[]):
            computers, software = adapter.list_computers_full(limit=1)
        self.assertEqual(computers[0].operating_system, "Microsoft Windows 11 Pro 25H2 build 26200.8524")
        self.assertEqual(software, {"99": []})

    def test_glpi_apply_does_not_erase_optional_portal_values_when_glpi_omits_them(self):
        connector = InventoryConnector.objects.create(
            tenant=self.tenant_a, provider=InventoryConnector.Provider.GLPI,
            base_url="https://glpi.example.test", credential_reference="LSMON_GLPI_A_KEEP", scope="Entity A",
        )
        asset = Asset.objects.create(
            tenant=self.tenant_a, name="Keep-PC", asset_type="Computer",
            primary_ip="10.20.30.40", fqdn="keep.example.test", operating_system="Windows 11",
        )
        from .models import AssetExternalIdentity
        AssetExternalIdentity.objects.create(asset=asset, source=AssetExternalIdentity.Source.GLPI, external_id="99")
        from .glpi_sync import GlpiComputer
        adapter = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
        adapter.list_computers.return_value = [GlpiComputer(external_id="99", name="Keep-PC")]
        with patch("lsmon_core.management.commands.sync_glpi_assets.GlpiReadOnlyAdapter", return_value=adapter), patch.dict(
            "os.environ", {"LSMON_GLPI_SYNC_SECRET_LSMON_GLPI_A_KEEP": '{"app_token":"app","user_token":"user"}'}, clear=False
        ):
            call_command("sync_glpi_assets", "--tenant-slug", "a", "--apply")
        asset.refresh_from_db()
        self.assertEqual(str(asset.primary_ip), "10.20.30.40")
        self.assertEqual(asset.fqdn, "keep.example.test")
        self.assertEqual(asset.operating_system, "Windows 11")

    def test_glpi_scheduler_runs_tenant_scoped_full_sync_then_portal_compliance(self):
        root = Path(__file__).resolve().parents[1]
        service = (root / "systemd" / "lsmon-glpi-sync@.service").read_text(encoding="utf-8")
        timer = (root / "systemd" / "lsmon-glpi-sync-tecstaq.timer").read_text(encoding="utf-8")
        self.assertIn("EnvironmentFile=/etc/lsmon/glpi-sync.env", service)
        self.assertIn("sync_glpi_assets --tenant-slug %i --limit 100 --full --apply", service)
        self.assertIn("evaluate_software_compliance --tenant-slug %i", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("Unit=lsmon-glpi-sync@tecstaq.service", timer)
        self.assertIn("Persistent=true", timer)

    def test_scheduled_compliance_command_records_a_system_activity_event(self):
        asset = Asset.objects.create(tenant=self.tenant_a, name="Scheduled-PC", asset_type="Computer")
        AssetSoftware.objects.create(asset=asset, source=AssetSoftware.Source.GLPI, name="Microsoft Defender")
        SoftwareComplianceRule.objects.create(
            tenant=self.tenant_a, name="Endpoint protection", rule_type="required", patterns="Defender",
        )
        output = StringIO()

        call_command("evaluate_software_compliance", "--tenant-slug", "a", stdout=output)

        event = ComplianceAuditEvent.objects.get(tenant=self.tenant_a)
        self.assertEqual(event.action, ComplianceAuditEvent.Action.EVALUATED)
        self.assertIsNone(event.actor)
        self.assertIn("1 assets assessed", event.summary)
        self.assertIn("SOFTWARE_COMPLIANCE_EVALUATED tenant=a compliant=1", output.getvalue())

    def test_asset_detail_is_tenant_scoped_and_displays_observed_software(self):
        asset = Asset.objects.create(tenant=self.tenant_a, name="Software-PC", asset_type="Computer")
        AssetSoftware.objects.create(asset=asset, source=AssetSoftware.Source.GLPI, name="Microsoft Defender", version="4.18")
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.get(f"/t/a/assets/{asset.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Installed software")
        self.assertContains(response, "Microsoft Defender")
        self.assertEqual(self.client.get(f"/t/b/assets/{asset.id}/").status_code, 403)

    def test_tenant_admin_can_store_portal_owned_asset_placement_without_changing_glpi_fields(self):
        source_location = TenantLocation.objects.create(tenant=self.tenant_a, name="GLPI source location")
        customer_location = TenantLocation.objects.create(tenant=self.tenant_a, name="Goregaon, Mumbai, India")
        department = Department.objects.create(tenant=self.tenant_a, name="Operations")
        foreign_location = TenantLocation.objects.create(tenant=self.tenant_b, name="Other customer location")
        asset = Asset.objects.create(
            tenant=self.tenant_a, name="Placement-PC", asset_type="Computer",
            location=source_location, primary_ip="10.0.0.10",
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)

        self.assertEqual(self.client.get(f"/t/b/assets/{asset.id}/placement/").status_code, 403)
        response = self.client.post(f"/t/a/assets/{asset.id}/placement/", {
            "assigned_location": customer_location.pk,
            "department": department.pk,
            "business_unit": "Customer Support",
            "local_ip": "192.168.50.20",
        })

        self.assertRedirects(response, f"/t/a/assets/{asset.id}/")
        asset.refresh_from_db()
        self.assertEqual(asset.assigned_location, customer_location)
        self.assertEqual(asset.department, department)
        self.assertEqual(asset.business_unit, "Customer Support")
        self.assertEqual(str(asset.local_ip), "192.168.50.20")
        self.assertEqual(asset.location, source_location)
        self.assertEqual(str(asset.primary_ip), "10.0.0.10")

        response = self.client.post(f"/t/a/assets/{asset.id}/placement/", {
            "assigned_location": foreign_location.pk,
            "department": department.pk,
            "business_unit": "Customer Support",
            "local_ip": "192.168.50.20",
        })
        self.assertEqual(response.status_code, 200)
        asset.refresh_from_db()
        self.assertEqual(asset.assigned_location, customer_location)

    def test_placement_queue_shows_only_assets_missing_customer_location_or_department(self):
        location = TenantLocation.objects.create(tenant=self.tenant_a, name="Mumbai")
        department = Department.objects.create(tenant=self.tenant_a, name="Back Office")
        complete = Asset.objects.create(
            tenant=self.tenant_a, name="Already organised", asset_type="Computer",
            assigned_location=location, department=department,
        )
        missing_location = Asset.objects.create(
            tenant=self.tenant_a, name="Needs location", asset_type="Computer", department=department,
        )
        missing_department = Asset.objects.create(
            tenant=self.tenant_a, name="Needs department", asset_type="Computer", assigned_location=location,
        )
        Asset.objects.create(tenant=self.tenant_b, name="Other tenant pending", asset_type="Computer")
        self.client.force_login(self.user)
        self._mfa_verified(self.user)

        response = self.client.get("/t/a/assets/organise/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Needs location")
        self.assertContains(response, "Needs department")
        self.assertNotContains(response, complete.name)
        self.assertNotContains(response, "Other tenant pending")
        self.assertContains(response, f'name="location_{missing_location.id}"')
        self.assertContains(response, "Save all assignments")
        self.assertEqual(self.client.get("/t/b/assets/organise/").status_code, 403)

        response = self.client.post("/t/a/assets/organise/", {
            f"location_{missing_location.id}": str(location.id),
            f"department_{missing_location.id}": str(department.id),
            f"location_{missing_department.id}": str(location.id),
            f"department_{missing_department.id}": str(department.id),
        })
        self.assertRedirects(response, "/t/a/assets/organise/")
        missing_location.refresh_from_db()
        missing_department.refresh_from_db()
        self.assertEqual(missing_location.assigned_location, location)
        self.assertEqual(missing_location.department, department)
        self.assertEqual(missing_department.assigned_location, location)
        self.assertEqual(missing_department.department, department)

    def test_inventory_freshness_is_tenant_scoped_and_uses_stored_glpi_observations(self):
        current_asset = Asset.objects.create(tenant=self.tenant_a, name="Current inventory", asset_type="Computer")
        stale_asset = Asset.objects.create(tenant=self.tenant_a, name="Stale inventory", asset_type="Computer")
        unreported_asset = Asset.objects.create(tenant=self.tenant_a, name="Manual inventory", asset_type="Computer")
        foreign_asset = Asset.objects.create(tenant=self.tenant_b, name="Foreign inventory", asset_type="Computer")
        AssetExternalIdentity.objects.create(
            asset=current_asset, source=AssetExternalIdentity.Source.GLPI, external_id="current",
            last_seen_at=timezone.now() - timedelta(hours=1),
        )
        AssetExternalIdentity.objects.create(
            asset=stale_asset, source=AssetExternalIdentity.Source.GLPI, external_id="stale",
            last_seen_at=timezone.now() - timedelta(hours=27),
        )
        AssetExternalIdentity.objects.create(
            asset=foreign_asset, source=AssetExternalIdentity.Source.GLPI, external_id="foreign",
            last_seen_at=timezone.now() - timedelta(hours=1),
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)

        response = self.client.get("/t/a/")
        self.assertContains(response, "1 current")
        self.assertContains(response, "1 refresh overdue")
        self.assertContains(response, "1 not reported")
        self.assertNotContains(response, "Foreign inventory")

        response = self.client.get("/t/a/assets/")
        self.assertContains(response, "Current")
        self.assertContains(response, "Refresh overdue")
        self.assertContains(response, "Not reported")

        response = self.client.get(f"/t/a/assets/{stale_asset.id}/")
        self.assertContains(response, "Last GLPI observation")
        self.assertContains(response, "Refresh overdue")

    def test_glpi_software_versions_resolve_numeric_product_ids_from_the_software_catalogue(self):
        from .glpi_sync import GlpiReadOnlyAdapter

        adapter = GlpiReadOnlyAdapter("https://glpi.example.test", {"app_token": "app", "user_token": "user"})
        with patch.object(adapter, "_paged", side_effect=[
            [{"id": 10, "name": "Microsoft Defender"}],
            [{"id": 20, "softwares_id": 10, "name": "4.18"}],
        ]):
            self.assertEqual(adapter._software_version_names(), {"20": ("Microsoft Defender", "4.18")})

    def test_glpi_item_software_version_relationship_keeps_numeric_ids(self):
        from .glpi_sync import GlpiReadOnlyAdapter

        adapter = GlpiReadOnlyAdapter("https://glpi.example.test", {"app_token": "app", "user_token": "user"})
        adapter.session_token = "session"
        captured = []

        def request(path, **kwargs):
            captured.append((path, kwargs["query"]))
            return []

        with patch.object(adapter, "_request", side_effect=request):
            self.assertEqual(adapter._software_for_computer("12", {}), [])
        self.assertEqual(captured, [("Computer/12/Item_SoftwareVersion", {"range": "0-99"})])

    def test_tenant_compliance_uses_only_scoped_rules_and_imported_software(self):
        from .compliance import evaluate_tenant

        asset = Asset.objects.create(tenant=self.tenant_a, name="Compliant-PC", asset_type="Computer")
        AssetSoftware.objects.create(asset=asset, source=AssetSoftware.Source.GLPI, name="Microsoft Defender", version="4.18")
        SoftwareComplianceRule.objects.create(
            tenant=self.tenant_a, name="Endpoint protection", rule_type="required", patterns="Defender"
        )
        SoftwareComplianceRule.objects.create(
            tenant=self.tenant_b, name="Other tenant ban", rule_type="prohibited", patterns="Defender"
        )
        results = evaluate_tenant(self.tenant_a)
        self.assertEqual(results[AssetCompliance.Status.COMPLIANT], 1)
        self.assertEqual(asset.compliance.status, AssetCompliance.Status.COMPLIANT)
        SoftwareComplianceRule.objects.create(
            tenant=self.tenant_a, name="No Defender", rule_type="prohibited", patterns="Defender"
        )
        evaluate_tenant(self.tenant_a)
        asset.refresh_from_db()
        self.assertEqual(asset.compliance.status, AssetCompliance.Status.NON_COMPLIANT)
        self.assertIn("Microsoft Defender", asset.compliance.prohibited)

    def test_tenant_admin_can_manage_scoped_compliance_criteria_with_feedback(self):
        rule = SoftwareComplianceRule.objects.create(
            tenant=self.tenant_a,
            name="Endpoint protection",
            rule_type=SoftwareComplianceRule.RuleType.REQUIRED,
            patterns="Microsoft Defender",
        )
        other_rule = SoftwareComplianceRule.objects.create(
            tenant=self.tenant_b,
            name="Other tenant rule",
            rule_type=SoftwareComplianceRule.RuleType.REQUIRED,
            patterns="Other product",
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)

        response = self.client.get(f"/t/a/compliance/{other_rule.id}/edit/")
        self.assertEqual(response.status_code, 404)

        response = self.client.post(f"/t/a/compliance/{rule.id}/edit/", {
            "name": "Endpoint protection",
            "rule_type": SoftwareComplianceRule.RuleType.REQUIRED,
            "patterns": "Microsoft Defender, Windows Defender",
            "platform": SoftwareComplianceRule.Platform.WINDOWS,
            "location": "",
            "department": "",
            "active": "on",
        }, follow=True)
        self.assertRedirects(response, "/t/a/compliance/")
        self.assertContains(response, "Criterion updated.")
        rule.refresh_from_db()
        self.assertEqual(rule.platform, SoftwareComplianceRule.Platform.WINDOWS)

        response = self.client.post("/t/a/compliance/", {"action": "evaluate"}, follow=True)
        self.assertContains(response, "Compliance recalculated:")

        response = self.client.post("/t/a/compliance/", {
            "action": "delete", "rule_id": rule.id,
        }, follow=True)
        self.assertContains(response, "was deleted")
        self.assertFalse(SoftwareComplianceRule.objects.filter(pk=rule.pk).exists())
        self.assertEqual(
            list(ComplianceAuditEvent.objects.filter(tenant=self.tenant_a).values_list("action", flat=True)),
            [
                ComplianceAuditEvent.Action.DELETED,
                ComplianceAuditEvent.Action.EVALUATED,
                ComplianceAuditEvent.Action.UPDATED,
            ],
        )

    def test_compliance_activity_is_tenant_scoped(self):
        ComplianceAuditEvent.objects.create(
            tenant=self.tenant_a, actor=self.user,
            action=ComplianceAuditEvent.Action.EVALUATED, summary="1 asset assessed.",
        )
        ComplianceAuditEvent.objects.create(
            tenant=self.tenant_b, actor=self.user,
            action=ComplianceAuditEvent.Action.EVALUATED, summary="Other tenant event.",
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)

        response = self.client.get("/t/a/compliance/audit/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "1 asset assessed.")
        self.assertNotContains(response, "Other tenant event.")

    def test_compliance_exceptions_show_only_current_tenant_non_compliant_assets(self):
        exception_asset = Asset.objects.create(tenant=self.tenant_a, name="Exception-PC", asset_type="Computer")
        compliant_asset = Asset.objects.create(tenant=self.tenant_a, name="Compliant-PC", asset_type="Computer")
        other_asset = Asset.objects.create(tenant=self.tenant_b, name="Other-tenant-PC", asset_type="Computer")
        AssetCompliance.objects.create(
            asset=exception_asset, status=AssetCompliance.Status.NON_COMPLIANT, missing="Endpoint protection",
        )
        AssetCompliance.objects.create(asset=compliant_asset, status=AssetCompliance.Status.COMPLIANT)
        AssetCompliance.objects.create(asset=other_asset, status=AssetCompliance.Status.NON_COMPLIANT, missing="Other rule")
        self.client.force_login(self.user)
        self._mfa_verified(self.user)

        response = self.client.get("/t/a/compliance/exceptions/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Exception-PC")
        self.assertContains(response, "Endpoint protection")
        self.assertNotContains(response, "Compliant-PC")
        self.assertNotContains(response, "Other-tenant-PC")

    def test_tenant_workspace_shows_scoped_compliance_summary_and_exception_link(self):
        exception_asset = Asset.objects.create(tenant=self.tenant_a, name="Workspace exception", asset_type="Computer")
        compliant_asset = Asset.objects.create(tenant=self.tenant_a, name="Workspace compliant", asset_type="Computer")
        other_asset = Asset.objects.create(tenant=self.tenant_b, name="Other tenant exception", asset_type="Computer")
        AssetCompliance.objects.create(asset=exception_asset, status=AssetCompliance.Status.NON_COMPLIANT, checked_at=timezone.now())
        AssetCompliance.objects.create(asset=compliant_asset, status=AssetCompliance.Status.COMPLIANT, checked_at=timezone.now())
        AssetCompliance.objects.create(asset=other_asset, status=AssetCompliance.Status.NON_COMPLIANT, checked_at=timezone.now())
        self.client.force_login(self.user)
        self._mfa_verified(self.user)

        response = self.client.get("/t/a/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "1 compliant")
        self.assertContains(response, "1 non-compliant")
        self.assertContains(response, 'href="/t/a/compliance/exceptions/"')
        self.assertEqual(response.context["compliance_summary"]["freshness"], "current")

    def test_compliance_csv_export_is_tenant_scoped_and_formula_safe(self):
        asset = Asset.objects.create(tenant=self.tenant_a, name="=unsafe-name", asset_type="Computer")
        other = Asset.objects.create(tenant=self.tenant_b, name="Other tenant asset", asset_type="Computer")
        AssetCompliance.objects.create(asset=asset, status=AssetCompliance.Status.NON_COMPLIANT, missing="Endpoint protection")
        AssetCompliance.objects.create(asset=other, status=AssetCompliance.Status.NON_COMPLIANT, missing="Other rule")
        self.client.force_login(self.user)
        self._mfa_verified(self.user)

        response = self.client.get("/t/a/compliance/export.csv")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv; charset=utf-8")
        self.assertIn('filename="a-compliance.csv"', response["Content-Disposition"])
        body = response.content.decode("utf-8-sig")
        self.assertIn("'=unsafe-name", body)
        self.assertIn("Endpoint protection", body)
        self.assertNotIn("Other tenant asset", body)

    def test_asset_inventory_csv_export_is_tenant_scoped_and_formula_safe(self):
        asset = Asset.objects.create(
            tenant=self.tenant_a, name="=unsafe-asset", asset_type="Computer", operating_system="Windows 11",
        )
        other = Asset.objects.create(tenant=self.tenant_b, name="Other tenant asset", asset_type="Computer")
        AssetExternalIdentity.objects.create(
            asset=asset, source=AssetExternalIdentity.Source.GLPI, external_id="safe",
            last_seen_at=timezone.now(),
        )
        AssetExternalIdentity.objects.create(
            asset=other, source=AssetExternalIdentity.Source.GLPI, external_id="foreign",
            last_seen_at=timezone.now(),
        )
        AssetSoftware.objects.create(asset=asset, source=AssetSoftware.Source.GLPI, name="Microsoft Defender")
        self.client.force_login(self.user)
        self._mfa_verified(self.user)

        response = self.client.get("/t/a/assets/export.csv")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv; charset=utf-8")
        self.assertIn('filename="a-asset-inventory.csv"', response["Content-Disposition"])
        body = response.content.decode("utf-8-sig")
        self.assertIn("'=unsafe-asset", body)
        self.assertIn("Current", body)
        self.assertIn("Observed software", body)
        self.assertIn(",1,Manual register", body)
        self.assertNotIn("Other tenant asset", body)

    def test_inventory_activity_is_tenant_scoped_and_does_not_start_a_sync(self):
        connector = InventoryConnector.objects.create(
            tenant=self.tenant_a, provider=InventoryConnector.Provider.GLPI,
            base_url="https://glpi.example.test", credential_reference="LSMON_GLPI_A", scope="A",
        )
        foreign_connector = InventoryConnector.objects.create(
            tenant=self.tenant_b, provider=InventoryConnector.Provider.GLPI,
            base_url="https://glpi.other.test", credential_reference="LSMON_GLPI_B", scope="B",
        )
        InventorySyncRun.objects.create(
            connector=connector, status=InventorySyncRun.Status.APPLIED,
            discovered_count=7, updated_count=7, summary="Read-only GLPI Computer import with installed software. GLPI was not modified.",
        )
        InventorySyncRun.objects.create(
            connector=foreign_connector, status=InventorySyncRun.Status.FAILED,
            error_code="credential_or_connection", summary="Foreign tenant result",
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)

        response = self.client.get("/t/a/assets/activity/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Inventory activity")
        self.assertContains(response, "7")
        self.assertContains(response, "Read-only GLPI Computer import")
        self.assertNotContains(response, "Foreign tenant result")


    def test_invitation_acceptance_creates_scoped_admin_and_redirects_to_mfa(self):
        token = "safe-test-token"
        invitation = TenantAdminInvitation.objects.create(
            tenant=self.tenant_a,
            email="randeep.pawar@tecstaq.com",
            token_hash=invitation_token_hash(token),
        )
        response = self.client.post(f"/invitations/accept/{token}/", {
            "password": "a-long-portal-password",
            "confirm_password": "a-long-portal-password",
        })
        self.assertRedirects(response, "/mfa/enroll/")
        user = get_user_model().objects.get(username="randeep.pawar@tecstaq.com")
        self.assertTrue(Membership.objects.filter(tenant=self.tenant_a, user=user, role=Membership.Role.TENANT_ADMIN).exists())
        self.assertTrue(MFAProfile.objects.filter(user=user).exists())
        invitation.refresh_from_db()
        self.assertIsNotNone(invitation.accepted_at)

    def test_tenant_admin_can_request_only_tenant_scoped_agent_enrollment(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.GLPI,
            operating_system=AgentPackage.OperatingSystem.WINDOWS,
            version="test-1.20",
            source_url="https://vendor.example.test/glpi-agent.msi",
            filename="glpi-agent.msi",
            sha256="A" * 64,
            expected_publisher="Test publisher",
            status=AgentPackage.Status.APPROVED,
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.post("/t/a/agent-enrollments/", {"operating_system": "windows", "package": package.pk})
        self.assertRedirects(response, "/t/a/agent-enrollments/")
        enrollment = AgentEnrollment.objects.get(tenant=self.tenant_a)
        self.assertEqual(enrollment.requested_by, self.user)
        self.assertEqual(enrollment.operating_system, AgentEnrollment.OperatingSystem.WINDOWS)
        self.assertEqual(enrollment.package, package)
        self.assertEqual(enrollment.status, AgentEnrollment.Status.REQUESTED)
        self.assertGreater(enrollment.expires_at, enrollment.created_at)
        self.assertTrue(AgentEnrollmentEvent.objects.filter(enrollment=enrollment, event_type=AgentEnrollmentEvent.EventType.REQUESTED, actor=self.user).exists())
        self.assertEqual(self.client.get("/t/b/agent-enrollments/").status_code, 403)

    def test_configured_tenant_request_is_ready_without_provider_queue_action(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.GLPI,
            operating_system=AgentPackage.OperatingSystem.WINDOWS,
            version="test-1.20-self-service",
            source_url="https://vendor.example.test/glpi-agent.msi",
            filename="glpi-agent.msi",
            sha256="9" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        TenantAgentProvisioning.objects.create(
            tenant=self.tenant_a,
            inventory_tag="a",
            glpi_inventory_url="https://glpi.example.test/front/inventory.php",
            glpi_entity_scope="A",
            credential_reference="LSMON_GLPI_A_INVENTORY",
            status=TenantAgentProvisioning.Status.CONFIGURED,
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.post("/t/a/agent-enrollments/", {"operating_system": "windows", "package": package.pk})
        self.assertRedirects(response, "/t/a/agent-enrollments/")
        enrollment = AgentEnrollment.objects.get(tenant=self.tenant_a)
        self.assertEqual(enrollment.status, AgentEnrollment.Status.READY)
        self.assertIsNotNone(enrollment.package_ready_at)
        self.assertTrue(AgentEnrollmentEvent.objects.filter(enrollment=enrollment, event_type=AgentEnrollmentEvent.EventType.BOOTSTRAP_READY, actor=self.user).exists())

    def test_zabbix_request_is_ready_without_glpi_tenant_configuration(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.ZABBIX,
            operating_system=AgentPackage.OperatingSystem.LINUX,
            version="7.0-test-rhel",
            source_url="https://vendor.example.test/zabbix-agent2.rpm",
            filename="zabbix-agent2.rpm",
            sha256="1" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.post("/t/a/agent-enrollments/", {"operating_system": "linux", "package": package.pk})
        self.assertRedirects(response, "/t/a/agent-enrollments/")
        enrollment = AgentEnrollment.objects.get(tenant=self.tenant_a, package=package)
        self.assertEqual(enrollment.status, AgentEnrollment.Status.READY)
        self.assertIsNotNone(enrollment.package_ready_at)
        self.assertEqual(str(package), "Zabbix Agent — Linux — 7.0-test-rhel")

    def test_zabbix_linux_download_embeds_no_psk_or_api_token(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.ZABBIX,
            operating_system=AgentPackage.OperatingSystem.LINUX,
            version="7.0-test-debian",
            source_url="https://vendor.example.test/zabbix-agent2.deb",
            filename="zabbix-agent2.deb",
            sha256="2" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a, requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.LINUX,
            status=AgentEnrollment.Status.READY, package=package,
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.post(f"/t/a/agent-enrollments/{enrollment.id}/single-file-linux-installer/")
        self.assertEqual(response.status_code, 200)
        installer = response.content.decode("utf-8")
        self.assertIn("Install-LsmonZabbixAgentLinux.sh", installer)
        self.assertNotIn("tls_psk", installer)
        self.assertNotIn("ZABBIX_API_TOKEN", installer)
        bootstrap = (Path(__file__).resolve().parents[1] / "bootstrap" / "Install-LsmonZabbixAgentLinux.sh").read_text(encoding="utf-8")
        self.assertIn("TLSConnect=psk", bootstrap)
        self.assertIn("DenyKey=system.run[*]", bootstrap)
        self.assertIn("apt-get install -y", bootstrap)
        self.assertIn("dnf install -y", bootstrap)

    def test_zabbix_windows_bootstrap_prevents_default_service_start(self):
        bootstrap = (Path(__file__).resolve().parents[1] / "bootstrap" / "Install-LsmonZabbixAgentWindows.ps1").read_text(encoding="utf-8")
        self.assertIn("DONOTSTART=1", bootstrap)
        self.assertIn("SERVER=127.0.0.1", bootstrap)
        self.assertIn("Get-CimInstance Win32_Service", bootstrap)
        self.assertIn("Get-AuthenticodeSignature", bootstrap)
        self.assertIn("FixedTimeEquals -Left $actualTag -Right $expectedTag", bootstrap)

    def test_tenant_zabbix_summary_queries_only_its_enrolled_hosts(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.ZABBIX,
            operating_system=AgentPackage.OperatingSystem.LINUX,
            version="7.0-dashboard-test",
            source_url="https://vendor.example.test/zabbix-agent2.deb",
            filename="zabbix-agent2.deb", sha256="3" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        own = AgentEnrollment.objects.create(tenant=self.tenant_a, requested_by=self.user, package=package, operating_system="linux")
        other = AgentEnrollment.objects.create(tenant=self.tenant_b, requested_by=self.user, package=package, operating_system="linux")
        with patch("lsmon_core.zabbix_dashboard._call", side_effect=[
            [{"hostid": "101", "host": f"lsmon-a-{str(own.id)[:12]}", "name": "A host", "status": "0", "active_available": "1"}],
            "1",
            [{"eventid": "1", "name": "Disk space low", "severity": "2", "clock": "1760520000", "acknowledged": "0"}],
        ]) as call:
            summary = summary_for_enrollments([own])
        self.assertEqual(summary["state"], "ready")
        self.assertEqual(len(summary["hosts"]), 1)
        self.assertEqual(summary["available_hosts"], 1)
        self.assertEqual(summary["problem_count"], 1)
        self.assertEqual(summary["problems"][0]["name"], "Disk space low")
        self.assertEqual(call.call_args_list[0].args[1]["filter"]["host"], [f"lsmon-a-{str(own.id)[:12]}"])
        self.assertEqual(call.call_args_list[1].args[1]["hostids"], ["101"])
        self.assertEqual(call.call_args_list[2].args[1]["hostids"], ["101"])
        self.assertNotIn(str(other.id)[:12], str(call.call_args_list))

    def test_windows_bootstrap_writes_managed_glpi_registry_configuration(self):
        from pathlib import Path
        bootstrap = (Path(__file__).resolve().parent.parent / "bootstrap" / "Install-LsmonWindowsAgent.ps1").read_text(encoding="utf-8")
        self.assertIn("HKLM:\\SOFTWARE\\GLPI-Agent", bootstrap)
        self.assertIn("server=[string]$config.server", bootstrap)
        self.assertIn("tag=[string]$config.tag", bootstrap)
        self.assertIn("'oauth-client-id'=[string]$config.oauth_client_id", bootstrap)
        self.assertIn("'oauth-client-secret'=[string]$config.oauth_client_secret", bootstrap)
        self.assertIn("LSMON validating enrollment manifest.", bootstrap)
        self.assertIn("LSMON downloading the approved agent package.", bootstrap)
        self.assertIn("-TimeoutSec 300", bootstrap)
        self.assertNotIn("90-lsmon.cfg", bootstrap)
        self.assertIn("Restart-Service -Name 'glpi-agent'", bootstrap)

    def test_only_global_admin_can_approve_or_revoke_enrollment(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.GLPI,
            operating_system=AgentPackage.OperatingSystem.LINUX,
            version="test-1.20-linux",
            source_url="https://vendor.example.test/glpi-agent.tar.gz",
            filename="glpi-agent.tar.gz",
            sha256="B" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a, requested_by=self.user, operating_system=AgentEnrollment.OperatingSystem.LINUX, package=package
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        self.assertEqual(self.client.get("/operations/enrollments/").status_code, 403)
        self.assertEqual(self.client.post(f"/operations/enrollments/{enrollment.id}/approve/").status_code, 403)

        global_admin = get_user_model().objects.create_user("global-enrollment-admin")
        Membership.objects.create(user=global_admin, role=Membership.Role.GLOBAL_ADMIN)
        TenantAgentProvisioning.objects.create(
            tenant=self.tenant_a,
            inventory_tag="a",
            glpi_inventory_url="https://glpi.example.test/front/inventory.php",
            glpi_entity_scope="A",
            credential_reference="LSMON_GLPI_A_INVENTORY",
            status=TenantAgentProvisioning.Status.CONFIGURED,
            configured_by=global_admin,
        )
        self.client.force_login(global_admin)
        self._mfa_verified(global_admin)
        self.assertEqual(self.client.get("/operations/enrollments/").status_code, 200)
        self.assertRedirects(self.client.post(f"/operations/enrollments/{enrollment.id}/approve/"), "/operations/enrollments/")
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.status, AgentEnrollment.Status.PROVISIONING)
        self.assertTrue(AgentEnrollmentEvent.objects.filter(enrollment=enrollment, event_type=AgentEnrollmentEvent.EventType.APPROVED, actor=global_admin).exists())
        self.assertRedirects(self.client.post(f"/operations/enrollments/{enrollment.id}/prepare/"), "/operations/enrollments/")
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.status, AgentEnrollment.Status.READY)
        self.assertIsNotNone(enrollment.package_ready_at)
        self.assertTrue(AgentEnrollmentEvent.objects.filter(enrollment=enrollment, event_type=AgentEnrollmentEvent.EventType.BOOTSTRAP_READY, actor=global_admin).exists())
        self.assertRedirects(self.client.post(f"/operations/enrollments/{enrollment.id}/revoke/"), "/operations/enrollments/")
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.status, AgentEnrollment.Status.REVOKED)
        self.assertIsNotNone(enrollment.revoked_at)

    def test_ready_bootstrap_is_tenant_scoped_and_contains_no_install_configuration(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.GLPI,
            operating_system=AgentPackage.OperatingSystem.MACOS,
            version="test-1.20-macos",
            source_url="https://vendor.example.test/glpi-agent.pkg",
            filename="glpi-agent.pkg",
            sha256="C" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.MACOS,
            status=AgentEnrollment.Status.READY,
            package=package,
            package_ready_at=__import__("django.utils.timezone", fromlist=["now"]).now(),
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.get(f"/t/a/agent-enrollments/{enrollment.id}/bootstrap/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["installable"])
        self.assertEqual(payload["tenant"], "a")
        self.assertEqual(payload["operating_system"], "macos")
        self.assertNotIn("credential", payload)
        self.assertNotIn("token", payload)
        enrollment.refresh_from_db()
        self.assertIsNotNone(enrollment.downloaded_at)
        self.assertTrue(AgentEnrollmentEvent.objects.filter(enrollment=enrollment, event_type=AgentEnrollmentEvent.EventType.DOWNLOADED, actor=self.user).exists())
        other_user = get_user_model().objects.create_user("tenant-b-admin")
        Membership.objects.create(tenant=self.tenant_b, user=other_user, role=Membership.Role.TENANT_ADMIN)
        self.client.force_login(other_user)
        self._mfa_verified(other_user)
        self.assertEqual(self.client.get(f"/t/b/agent-enrollments/{enrollment.id}/bootstrap/").status_code, 404)

    def test_legacy_ready_request_without_approved_package_cannot_download_or_issue_code(self):
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.WINDOWS,
            status=AgentEnrollment.Status.READY,
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        self.assertEqual(self.client.get(f"/t/a/agent-enrollments/{enrollment.id}/bootstrap/").status_code, 403)
        self.assertEqual(self.client.get(f"/t/a/agent-enrollments/{enrollment.id}/windows-bootstrap/").status_code, 403)
        self.assertEqual(self.client.post(f"/t/a/agent-enrollments/{enrollment.id}/single-file-windows-installer/").status_code, 403)
        self.assertEqual(self.client.post(f"/t/a/agent-enrollments/{enrollment.id}/registration-code/").status_code, 403)

    def test_tenant_admin_downloads_single_file_windows_installer_once(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.GLPI,
            operating_system=AgentPackage.OperatingSystem.WINDOWS,
            version="test-1.20-windows-one-file",
            source_url="https://vendor.example.test/glpi-agent.msi",
            filename="glpi-agent.msi",
            sha256="F" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.WINDOWS,
            status=AgentEnrollment.Status.READY,
            package=package,
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        url = f"/t/a/agent-enrollments/{enrollment.id}/single-file-windows-installer/"
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(f'filename="Install-LsmonWindowsAgent-{enrollment.id}.ps1"', response["Content-Disposition"])
        self.assertEqual(response["Cache-Control"], "no-store, private")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        installer = response.content.decode("utf-8")
        self.assertIn("LSMON single-use Windows enrollment installer.", installer)
        self.assertIn("-RegistrationCode $registrationCode", installer)
        self.assertIn("Start-Process -FilePath 'powershell.exe' -Verb RunAs", installer)
        self.assertNotIn("https://glpi.example.test/front/inventory.php", installer)
        enrollment.refresh_from_db()
        self.assertEqual(len(enrollment.registration_code_hash), 64)
        self.assertIsNotNone(enrollment.registration_code_issued_at)
        self.assertIsNotNone(enrollment.downloaded_at)
        self.assertTrue(AgentEnrollmentEvent.objects.filter(enrollment=enrollment, event_type=AgentEnrollmentEvent.EventType.CODE_ISSUED, actor=self.user).exists())
        self.assertTrue(AgentEnrollmentEvent.objects.filter(enrollment=enrollment, event_type=AgentEnrollmentEvent.EventType.DOWNLOADED, actor=self.user).exists())
        replacement = self.client.post(url)
        self.assertEqual(replacement.status_code, 200)
        self.assertNotEqual(installer, replacement.content.decode("utf-8"))

        other_user = get_user_model().objects.create_user("tenant-b-one-file-admin")
        Membership.objects.create(tenant=self.tenant_b, user=other_user, role=Membership.Role.TENANT_ADMIN)
        self.client.force_login(other_user)
        self._mfa_verified(other_user)
        self.assertEqual(self.client.post(f"/t/b/agent-enrollments/{enrollment.id}/single-file-windows-installer/").status_code, 404)

    def test_tenant_admin_downloads_single_file_linux_installer_once(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.GLPI,
            operating_system=AgentPackage.OperatingSystem.LINUX,
            version="test-1.21-linux-one-file",
            source_url="https://vendor.example.test/glpi-agent-1.21-linux-installer.pl",
            filename="glpi-agent-1.21-linux-installer.pl",
            sha256="E" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.LINUX,
            status=AgentEnrollment.Status.READY,
            package=package,
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        url = f"/t/a/agent-enrollments/{enrollment.id}/single-file-linux-installer/"
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(f'filename="Install-LsmonLinuxAgent-{enrollment.id}.sh"', response["Content-Disposition"])
        self.assertEqual(response["Cache-Control"], "no-store, private")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        installer = response.content.decode("utf-8")
        self.assertIn("LSMON single-use Linux enrollment installer.", installer)
        self.assertIn("exec sudo --preserve-env=LSMON_DELIVERY_WAIT_SECONDS bash", installer)
        self.assertIn("Install-LsmonLinuxAgent.sh", installer)
        self.assertNotIn("https://glpi.example.test/front/inventory.php", installer)
        self.assertNotIn("oauth_client_secret", installer)
        bootstrap_source = (Path(__file__).resolve().parents[1] / "bootstrap" / "Install-LsmonLinuxAgent.sh").read_text(encoding="utf-8")
        self.assertIn("--no-question --service=0", bootstrap_source)
        enrollment.refresh_from_db()
        self.assertEqual(len(enrollment.registration_code_hash), 64)
        self.assertIsNotNone(enrollment.registration_code_issued_at)
        self.assertIsNotNone(enrollment.downloaded_at)
        self.assertTrue(AgentEnrollmentEvent.objects.filter(enrollment=enrollment, event_type=AgentEnrollmentEvent.EventType.CODE_ISSUED, actor=self.user).exists())
        self.assertTrue(AgentEnrollmentEvent.objects.filter(enrollment=enrollment, event_type=AgentEnrollmentEvent.EventType.DOWNLOADED, actor=self.user).exists())
        replacement = self.client.post(url)
        self.assertEqual(replacement.status_code, 200)
        self.assertNotEqual(installer, replacement.content.decode("utf-8"))

    def test_tenant_admin_sees_registration_code_once_and_only_its_hash_is_stored(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.GLPI,
            operating_system=AgentPackage.OperatingSystem.WINDOWS,
            version="test-1.20-windows-code",
            source_url="https://vendor.example.test/glpi-agent.msi",
            filename="glpi-agent.msi",
            sha256="D" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.WINDOWS,
            status=AgentEnrollment.Status.READY,
            package=package,
        )
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        response = self.client.post(f"/t/a/agent-enrollments/{enrollment.id}/registration-code/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "LSM-")
        enrollment.refresh_from_db()
        self.assertEqual(len(enrollment.registration_code_hash), 64)
        self.assertIsNotNone(enrollment.registration_code_issued_at)
        self.assertNotContains(response, enrollment.registration_code_hash)
        self.assertTrue(AgentEnrollmentEvent.objects.filter(enrollment=enrollment, event_type=AgentEnrollmentEvent.EventType.CODE_ISSUED, actor=self.user).exists())
        self.assertEqual(self.client.post(f"/t/a/agent-enrollments/{enrollment.id}/registration-code/").status_code, 403)

    def test_pilot_exe_bootstrap_requires_a_valid_unconsumed_code(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.GLPI,
            operating_system=AgentPackage.OperatingSystem.WINDOWS,
            version="test-pilot-exe",
            source_url="https://vendor.example.test/glpi-agent.msi",
            filename="glpi-agent.msi",
            sha256="A" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.WINDOWS,
            status=AgentEnrollment.Status.READY,
            package=package,
            registration_code_hash=hash_registration_code("LSM-PILOT-TEST"),
        )
        response = self.client.post("/enroll/windows-bootstrap/", {
            "enrollment_id": str(enrollment.id), "registration_code": "LSM-PILOT-TEST",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("LSMON single-use Windows enrollment installer.", response.content.decode("utf-8"))
        self.assertEqual(response["Cache-Control"], "no-store, private")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.status, AgentEnrollment.Status.READY)
        self.assertIsNone(enrollment.registration_code_used_at)
        self.assertEqual(self.client.post("/enroll/windows-bootstrap/", {
            "enrollment_id": str(enrollment.id), "registration_code": "wrong",
        }).status_code, 403)

    def test_installer_validation_consumes_code_without_returning_configuration(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.GLPI,
            operating_system=AgentPackage.OperatingSystem.LINUX,
            version="test-1.20-linux-validation",
            source_url="https://vendor.example.test/glpi-agent.tar.gz",
            filename="glpi-agent.tar.gz",
            sha256="E" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.LINUX,
            status=AgentEnrollment.Status.READY,
            package=package,
        )
        code = "LSM-ABCD-EFGH-JKMP-2345"
        enrollment.registration_code_hash = __import__("lsmon_core.registration", fromlist=["hash_registration_code"]).hash_registration_code(code)
        enrollment.save(update_fields=["registration_code_hash"])
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        endpoint_public_key = __import__("base64").urlsafe_b64encode(public_key).rstrip(b"=").decode("ascii")
        response = self.client.post("/enroll/validate/", {"enrollment_id": str(enrollment.id), "registration_code": code, "endpoint_public_key": endpoint_public_key})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual({key: payload[key] for key in payload if key != "delivery_token"}, {"valid": True, "enrollment_id": str(enrollment.id), "tenant": "a", "operating_system": "linux", "configuration_available": False})
        self.assertGreaterEqual(len(payload["delivery_token"]), 40)
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.status, AgentEnrollment.Status.ACTIVATING)
        self.assertIsNotNone(enrollment.registration_code_used_at)
        self.assertTrue(AgentRegistrationValidation.objects.filter(enrollment=enrollment, accepted=True).exists())
        job = AgentProvisioningJob.objects.get(enrollment=enrollment)
        self.assertEqual(job.status, AgentProvisioningJob.Status.QUEUED)
        self.assertEqual(job.attempt_count, 0)
        self.assertEqual(job.endpoint_public_key, endpoint_public_key)
        self.assertNotEqual(job.delivery_token_hash, payload["delivery_token"])
        self.assertEqual(job.delivery_token_hash, hash_delivery_token(payload["delivery_token"]))
        self.assertEqual(self.client.post("/enroll/validate/", {"enrollment_id": str(enrollment.id), "registration_code": code, "endpoint_public_key": endpoint_public_key}).status_code, 403)

    def test_registration_rejects_missing_or_invalid_endpoint_public_key(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.GLPI,
            operating_system=AgentPackage.OperatingSystem.WINDOWS,
            version="test-1.20-windows-invalid-key",
            source_url="https://vendor.example.test/glpi-agent.msi",
            filename="glpi-agent.msi",
            sha256="F" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a, requested_by=self.user, operating_system=AgentEnrollment.OperatingSystem.WINDOWS,
            status=AgentEnrollment.Status.READY,
            package=package,
            registration_code_hash=__import__("lsmon_core.registration", fromlist=["hash_registration_code"]).hash_registration_code("LSM-ABCD-EFGH-JKMP-2345"),
        )
        response = self.client.post("/enroll/validate/", {"enrollment_id": str(enrollment.id), "registration_code": "LSM-ABCD-EFGH-JKMP-2345"})
        self.assertEqual(response.status_code, 400)
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.status, AgentEnrollment.Status.READY)
        self.assertFalse(AgentProvisioningJob.objects.filter(enrollment=enrollment).exists())

    def test_sealed_configuration_delivery_requires_token_and_is_single_use(self):
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.WINDOWS,
            status=AgentEnrollment.Status.ACTIVATING,
        )
        token = generate_delivery_token()
        job = AgentProvisioningJob.objects.create(
            enrollment=enrollment,
            delivery_token_hash=hash_delivery_token(token),
            delivery_expires_at=__import__("django.utils.timezone", fromlist=["now"]).now() + timedelta(minutes=10),
            status=AgentProvisioningJob.Status.DELIVERED,
            sealed_configuration='{"version":1,"ciphertext":"encrypted-only"}',
        )
        endpoint = f"/enroll/config/{enrollment.id}/"
        self.assertEqual(self.client.post(endpoint, {"delivery_token": "wrong"}).status_code, 403)
        response = self.client.post(endpoint, {"delivery_token": token})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["available"])
        self.assertEqual(response.json()["envelope"]["ciphertext"], "encrypted-only")
        job.refresh_from_db()
        self.assertIsNotNone(job.downloaded_at)
        self.assertEqual(self.client.post(endpoint, {"delivery_token": token}).status_code, 410)

    def test_sealed_configuration_returns_pending_without_leaking_configuration(self):
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.WINDOWS,
            status=AgentEnrollment.Status.ACTIVATING,
        )
        token = generate_delivery_token()
        AgentProvisioningJob.objects.create(
            enrollment=enrollment,
            delivery_token_hash=hash_delivery_token(token),
            delivery_expires_at=__import__("django.utils.timezone", fromlist=["now"]).now() + timedelta(minutes=10),
        )
        response = self.client.post(f"/enroll/config/{enrollment.id}/", {"delivery_token": token})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json(), {"available": False, "pending": True})

    def test_provisioner_dry_run_can_be_limited_to_one_enrollment(self):
        first = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.WINDOWS,
            status=AgentEnrollment.Status.ACTIVATING,
        )
        second = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.LINUX,
            status=AgentEnrollment.Status.ACTIVATING,
        )
        AgentProvisioningJob.objects.create(enrollment=first)
        AgentProvisioningJob.objects.create(enrollment=second)
        output = StringIO()
        call_command("provision_agent_jobs", "--enrollment-id", str(first.id), stdout=output)
        self.assertIn("QUEUED_AGENT_PROVISIONING_JOBS=1", output.getvalue())
        self.assertIn("DRY_RUN_ONLY", output.getvalue())

    def test_provisioner_prerequisite_check_validates_secret_shape_without_processing_a_job(self):
        TenantAgentProvisioning.objects.create(
            tenant=self.tenant_a,
            inventory_tag="a",
            glpi_inventory_url="https://glpi.example.test/front/inventory.php",
            glpi_entity_scope="A",
            credential_reference="LSMON_GLPI_A_INVENTORY",
            status=TenantAgentProvisioning.Status.CONFIGURED,
        )
        output = StringIO()
        with patch.dict("os.environ", {"LSMON_AGENT_SECRET_LSMON_GLPI_A_INVENTORY": '{"client_id":"test-id","client_secret":"test-secret"}'}, clear=False):
            call_command("verify_agent_provisioning_prerequisites", "--tenant-slug", "a", stdout=output)
        self.assertIn("PROVISIONING_PREREQUISITES_READY tenant=a", output.getvalue())
        self.assertNotIn("test-secret", output.getvalue())
        self.assertFalse(AgentProvisioningJob.objects.exists())

    def test_installer_validation_locks_after_five_failed_codes(self):
        package = AgentPackage.objects.create(
            vendor=AgentPackage.Vendor.GLPI,
            operating_system=AgentPackage.OperatingSystem.WINDOWS,
            version="test-1.20-windows-lockout",
            source_url="https://vendor.example.test/glpi-agent.msi",
            filename="glpi-agent.msi",
            sha256="1" * 64,
            status=AgentPackage.Status.APPROVED,
        )
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.WINDOWS,
            status=AgentEnrollment.Status.READY,
            package=package,
            registration_code_hash=__import__("lsmon_core.registration", fromlist=["hash_registration_code"]).hash_registration_code("LSM-REAL-CODE-2345-6789"),
        )
        for _ in range(5):
            self.assertEqual(self.client.post("/enroll/validate/", {"enrollment_id": str(enrollment.id), "registration_code": "invalid"}).status_code, 403)
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.registration_code_attempts, 5)
        self.assertIsNotNone(enrollment.registration_code_locked_until)
        self.assertEqual(self.client.post("/enroll/validate/", {"enrollment_id": str(enrollment.id), "registration_code": "LSM-REAL-CODE-2345-6789"}).status_code, 429)
        self.assertEqual(AgentRegistrationValidation.objects.filter(enrollment=enrollment, accepted=False).count(), 6)

    def test_only_global_admin_can_record_non_secret_agent_provisioning_references(self):
        provisioning = TenantAgentProvisioning.objects.create(tenant=self.tenant_a, inventory_tag="a")
        self.client.force_login(self.user)
        self._mfa_verified(self.user)
        self.assertEqual(self.client.get("/operations/tenants/a/agent-provisioning/").status_code, 403)
        global_admin = get_user_model().objects.create_user("global-provisioning-admin")
        Membership.objects.create(user=global_admin, role=Membership.Role.GLOBAL_ADMIN)
        self.client.force_login(global_admin)
        self._mfa_verified(global_admin)
        response = self.client.post("/operations/tenants/a/agent-provisioning/", {
            "glpi_inventory_url": "https://glpi.example.test/front/inventory.php",
            "glpi_entity_scope": "A",
            "inventory_tag": "a",
            "credential_reference": "LSMON_GLPI_A_INVENTORY",
        })
        self.assertRedirects(response, "/operations/enrollments/")
        provisioning.refresh_from_db()
        self.assertEqual(provisioning.status, TenantAgentProvisioning.Status.CONFIGURED)
        self.assertEqual(provisioning.credential_reference, "LSMON_GLPI_A_INVENTORY")
        self.assertEqual(provisioning.configured_by, global_admin)

    def test_provider_cannot_prepare_bootstrap_without_tenant_provisioning_references(self):
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant_a,
            requested_by=self.user,
            operating_system=AgentEnrollment.OperatingSystem.WINDOWS,
            status=AgentEnrollment.Status.PROVISIONING,
        )
        global_admin = get_user_model().objects.create_user("global-no-config-admin")
        Membership.objects.create(user=global_admin, role=Membership.Role.GLOBAL_ADMIN)
        self.client.force_login(global_admin)
        self._mfa_verified(global_admin)
        response = self.client.post(f"/operations/enrollments/{enrollment.id}/prepare/")
        self.assertEqual(response.status_code, 403)
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.status, AgentEnrollment.Status.PROVISIONING)

    def test_environment_secret_adapter_never_persists_or_returns_reference_as_value(self):
        reference = "LSMON_GLPI_A_INVENTORY"
        with patch.dict("os.environ", {"LSMON_AGENT_SECRET_LSMON_GLPI_A_INVENTORY": "test-only-value"}, clear=False):
            self.assertTrue(has_secret(reference))
            self.assertEqual(resolve_secret(reference), "test-only-value")
        with self.assertRaises(SecretUnavailable):
            resolve_secret(reference)

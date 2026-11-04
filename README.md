# LSMON portal

Isolated Django portal scaffold for TecstaqOps. This source contains no credentials, customer data, public routes or engine tokens.

The current implementation establishes tenant-scoped assets, external-engine identities, Global Administrator and tenant-role boundaries, encrypted Google Authenticator compatible TOTP enrollment, and a tokenless pending first-tenant-administrator invitation. Zabbix, Wazuh and GLPI remain adapter interfaces until their integration gates pass.

`stage_portal_mfa.py` stages the source into an existing private portal runtime, creates a server-held MFA encryption key only if one is missing, and applies migrations. It deliberately does not create an account, a tenant, an email invitation, a web service, a firewall rule, or a public route.

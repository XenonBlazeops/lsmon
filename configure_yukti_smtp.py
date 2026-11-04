#!/usr/bin/env python3
"""Store Yukti SMTP settings as root-only portal environment values."""
import base64
import getpass
import os
import platform
from pathlib import Path


HOST = "vmi3626301"
ENVIRONMENT = Path("/etc/lsmon/portal.env")
MANAGED = {
    "LSMON_SMTP_HOST", "LSMON_SMTP_PORT", "LSMON_SMTP_USERNAME",
    "LSMON_SMTP_PASSWORD_B64", "LSMON_SMTP_USE_TLS", "LSMON_SMTP_USE_SSL", "LSMON_SMTP_FROM",
}


def replace_values(path, values):
    retained = []
    for line in path.read_text(encoding="utf-8").splitlines():
        key = line.split("=", 1)[0] if "=" in line else ""
        if key not in MANAGED:
            retained.append(line)
    retained.extend(f"{key}={value}" for key, value in values.items())
    path.write_text("\n".join(retained) + "\n", encoding="utf-8")
    path.chmod(0o600)


if os.geteuid() != 0 or platform.node().split(".")[0] != HOST:
    raise SystemExit("STOP: run as root on vmi3626301 only")
if not ENVIRONMENT.is_file():
    raise SystemExit("STOP: portal environment is missing")

smtp_host = input("SMTP host [s.mailservice25.com]: ").strip() or "s.mailservice25.com"
port = input("SMTP port [587]: ").strip() or "587"
if port not in {"587", "465"}:
    raise SystemExit("STOP: use 587 (STARTTLS) or 465 (implicit TLS)")
username = input("SMTP username/email: ").strip()
from_email = input("Portal sender address [support@tecstaqops.com]: ").strip() or "support@tecstaqops.com"
password = getpass.getpass("SMTP password or app password: ")
if not username or not password or "@" not in from_email or any("\n" in value or "\r" in value for value in (smtp_host, username, from_email, password)):
    raise SystemExit("STOP: required SMTP input is missing or invalid")
replace_values(ENVIRONMENT, {
    "LSMON_SMTP_HOST": smtp_host,
    "LSMON_SMTP_PORT": port,
    "LSMON_SMTP_USERNAME": username,
    "LSMON_SMTP_PASSWORD_B64": base64.b64encode(password.encode()).decode(),
    "LSMON_SMTP_USE_TLS": "true" if port == "587" else "false",
    "LSMON_SMTP_USE_SSL": "true" if port == "465" else "false",
    "LSMON_SMTP_FROM": from_email,
})
print("YUKTI_SMTP_CONFIGURED")
print("No password was printed. Send a controlled test before issuing invitations.")

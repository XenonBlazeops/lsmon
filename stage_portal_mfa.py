#!/usr/bin/env python3
"""Stage the private LSMON MFA and tenant workflow. No web route is created."""
import os
import platform
import shutil
import subprocess
from pathlib import Path


HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-mfa")
DESTINATION = Path("/opt/lsmon-portal")
ENVIRONMENT = Path("/etc/lsmon/portal.env")
BACKUP_ROOT = Path("/var/backups/lsmon-portal")
EXCLUDED = {"venv", "__pycache__", "lsmon-test.sqlite3"}


def run(command, *, env=None):
    subprocess.run(command, check=True, env=env)


def copy_source(source, destination):
    for item in source.iterdir():
        if item.name in EXCLUDED or item.suffix in {".pyc", ".sqlite3"}:
            continue
        target = destination / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.sqlite3"))
        else:
            shutil.copy2(item, target)


def read_environment(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


if os.geteuid() != 0 or platform.node().split(".")[0] != HOST:
    raise SystemExit("STOP: run as root on vmi3626301 only")
if not (SOURCE / "manage.py").is_file() or not (DESTINATION / "manage.py").is_file() or not ENVIRONMENT.is_file():
    raise SystemExit("STOP: expected staged source, existing runtime, or portal environment is missing")

BACKUP_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
backup = BACKUP_ROOT / "pre-mfa-stage"
if backup.exists():
    raise SystemExit(f"STOP: review or rename existing backup: {backup}")
shutil.copytree(DESTINATION, backup, ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source(SOURCE, DESTINATION)
run([str(DESTINATION / "venv/bin/pip"), "install", "--requirement", str(DESTINATION / "requirements.txt")])

values = read_environment(ENVIRONMENT)
if not values.get("LSMON_MFA_ENCRYPTION_KEY"):
    generated = subprocess.check_output(
        [str(DESTINATION / "venv/bin/python"), "-c", "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"],
        text=True,
    ).strip()
    with ENVIRONMENT.open("a", encoding="utf-8") as handle:
        handle.write(f"LSMON_MFA_ENCRYPTION_KEY={generated}\n")
    ENVIRONMENT.chmod(0o600)
    values["LSMON_MFA_ENCRYPTION_KEY"] = generated

environment = os.environ.copy()
environment.update(values)
run([str(DESTINATION / "venv/bin/python"), str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=environment)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
print("PORTAL_MFA_STAGED")
print(f"Code backup: {backup}")
print("Database migrations: 0002_global_membership, 0003_tenant_mfa, 0004_pending_invitation")
print("No portal user, tenant, email delivery, web service, firewall rule, or public route was created.")

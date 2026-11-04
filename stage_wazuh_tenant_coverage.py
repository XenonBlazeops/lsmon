#!/usr/bin/env python3
"""Deploy the read-only tenant Wazuh group-coverage display."""

import os
import platform
import shutil
import subprocess
from pathlib import Path


HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-wazuh-tenant-coverage")
DESTINATION = Path("/opt/lsmon-portal")
PORTAL_ENVIRONMENT = Path("/etc/lsmon/portal.env")
WAZUH_SECRET = Path("/etc/lsmon/wazuh-read.env")
DROP_IN = Path("/etc/systemd/system/lsmon-portal.service.d/wazuh-read.env.conf")
BACKUP = Path("/var/backups/lsmon-portal/pre-wazuh-tenant-coverage-stage")


def run(command, *, env=None):
    subprocess.run(command, check=True, env=env)


def env_values(path):
    return {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in path.read_text().splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }


def copy_source():
    for item in SOURCE.iterdir():
        if item.name in {"venv", "__pycache__", "lsmon-test.sqlite3"} or item.suffix in {".pyc", ".sqlite3"}:
            continue
        target = DESTINATION / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
        else:
            shutil.copy2(item, target)


if os.geteuid() != 0 or platform.node().split(".")[0] != HOST:
    raise SystemExit("STOP: run as root on vmi3626301 only")

required = (
    SOURCE / "manage.py",
    SOURCE / "lsmon_core" / "views.py",
    SOURCE / "lsmon_core" / "wazuh_dashboard.py",
    SOURCE / "templates" / "tenant_home.html",
    DESTINATION / "manage.py",
    PORTAL_ENVIRONMENT,
    WAZUH_SECRET,
)
if not all(path.is_file() for path in required):
    raise SystemExit("STOP: staged source, portal runtime/environment, or root-only Wazuh reader secret is incomplete")
if BACKUP.exists() or DROP_IN.exists():
    raise SystemExit("STOP: review the existing Wazuh coverage backup or service drop-in before retrying")
if WAZUH_SECRET.stat().st_uid != 0 or WAZUH_SECRET.stat().st_mode & 0o077:
    raise SystemExit("STOP: Wazuh reader secret must remain root-owned and not group/world accessible")

shutil.copytree(DESTINATION, BACKUP, ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source()

environment = os.environ.copy()
environment.update(env_values(PORTAL_ENVIRONMENT))
python = str(DESTINATION / "venv/bin/python")
run([python, "-m", "py_compile", str(DESTINATION / "lsmon_core" / "views.py")], env=environment)
run([python, "-m", "py_compile", str(DESTINATION / "lsmon_core" / "wazuh_dashboard.py")], env=environment)
run([python, str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=environment)
run([python, str(DESTINATION / "manage.py"), "check"], env=environment)

DROP_IN.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
DROP_IN.write_text("[Service]\nEnvironmentFile=-/etc/lsmon/wazuh-read.env\n")
os.chmod(DROP_IN, 0o644)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "daemon-reload"])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])

print("WAZUH_TENANT_COVERAGE_STAGE_READY")
print("Tenant workspaces can display only active/enrolled coverage from their configured Wazuh agent group.")
print("This stage does not create agents, change Wazuh groups/policies, ingest findings, alter endpoints, or expose credentials.")
print(f"Code backup: {BACKUP}")

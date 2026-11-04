#!/usr/bin/env python3
"""Stage the tenant-scoped agent enrollment foundation on vmi3626301 only.

This stage deploys portal workflow code and database migrations only.  It does
not write a secret, connect to GLPI, create an OAuth client, issue an installer,
or activate an endpoint.
"""
import os
import platform
import shutil
import subprocess
from pathlib import Path


HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-agent-enrollment")
DESTINATION = Path("/opt/lsmon-portal")
ENVIRONMENT = Path("/etc/lsmon/portal.env")
BACKUP = Path("/var/backups/lsmon-portal/pre-agent-enrollment-foundation-stage")
EXCLUDED = {"venv", "__pycache__", "lsmon-test.sqlite3"}
REQUIRED_MIGRATIONS = tuple(f"{number:04d}_" for number in range(9, 15))


def run(command, *, env=None):
    subprocess.run(command, check=True, env=env)


def environment_values(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


def copy_source(source, destination):
    for item in source.iterdir():
        if item.name in EXCLUDED or item.suffix in {".pyc", ".sqlite3"}:
            continue
        target = destination / item.name
        if item.is_dir():
            shutil.copytree(
                item,
                target,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.sqlite3"),
            )
        else:
            shutil.copy2(item, target)


if os.geteuid() != 0 or platform.node().split(".")[0] != HOST:
    raise SystemExit("STOP: run as root on vmi3626301 only")
if not (SOURCE / "manage.py").is_file() or not (DESTINATION / "manage.py").is_file() or not ENVIRONMENT.is_file():
    raise SystemExit("STOP: expected staged source, existing runtime, or portal environment is missing")
if BACKUP.exists():
    raise SystemExit(f"STOP: review or rename existing backup: {BACKUP}")
migrations = SOURCE / "lsmon_core" / "migrations"
if not all(any(path.name.startswith(prefix) for path in migrations.glob("*.py")) for prefix in REQUIRED_MIGRATIONS):
    raise SystemExit("STOP: staged source is missing an agent-enrollment migration (0009 through 0014)")

shutil.copytree(DESTINATION, BACKUP, ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source(SOURCE, DESTINATION)
env = os.environ.copy()
env.update(environment_values(ENVIRONMENT))
run([str(DESTINATION / "venv/bin/python"), str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=env)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
print("AGENT_ENROLLMENT_FOUNDATION_STAGE_READY")
print("Tenant enrollment requests, provider approvals, non-secret bootstrap manifests, and one-time registration-code validation are ready.")
print("No OAuth credential, secret environment value, GLPI API request, GLPI OAuth client, agent package, endpoint enrollment, or firewall change was made.")
print(f"Code backup: {BACKUP}")

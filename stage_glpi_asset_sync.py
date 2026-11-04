#!/usr/bin/env python3
"""Deploy the preview-first, read-only GLPI Computer import source.

This stage deliberately does not create a GLPI API credential, contact GLPI,
schedule an import, or modify customer assets.
"""
import os
import platform
import shutil
import subprocess
from pathlib import Path

HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-glpi-asset-sync")
DESTINATION = Path("/opt/lsmon-portal")
PORTAL_ENVIRONMENT = Path("/etc/lsmon/portal.env")
BACKUP = Path("/var/backups/lsmon-portal/pre-glpi-asset-sync-stage")
EXCLUDED = {"venv", "__pycache__", "lsmon-test.sqlite3"}


def run(command, *, env=None):
    subprocess.run(command, check=True, env=env)


def values(path):
    return {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in path.read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }


def copy_source():
    for item in SOURCE.iterdir():
        if item.name in EXCLUDED or item.suffix in {".pyc", ".sqlite3"}:
            continue
        target = DESTINATION / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.sqlite3"))
        else:
            shutil.copy2(item, target)


if os.geteuid() != 0 or platform.node().split(".")[0] != HOST:
    raise SystemExit("STOP: run as root on vmi3626301 only")
required = (
    SOURCE / "manage.py",
    SOURCE / "lsmon_core" / "migrations" / "0021_inventory_sync_run.py",
    SOURCE / "lsmon_core" / "management" / "commands" / "sync_glpi_assets.py",
    DESTINATION / "manage.py",
    PORTAL_ENVIRONMENT,
)
if not all(path.is_file() for path in required):
    raise SystemExit("STOP: staged source, portal runtime, or portal environment is incomplete")
if BACKUP.exists():
    raise SystemExit(f"STOP: review or rename existing backup: {BACKUP}")

shutil.copytree(DESTINATION, BACKUP,
                ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source()
environment = os.environ.copy()
environment.update(values(PORTAL_ENVIRONMENT))
python = str(DESTINATION / "venv/bin/python")
run([python, "-m", "py_compile",
     str(DESTINATION / "lsmon_core" / "models.py"),
     str(DESTINATION / "lsmon_core" / "glpi_sync.py"),
     str(DESTINATION / "lsmon_core" / "glpi_sync_secrets.py"),
     str(DESTINATION / "lsmon_core" / "management" / "commands" / "sync_glpi_assets.py")], env=environment)
run([python, str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=environment)
run([python, str(DESTINATION / "manage.py"), "check"], env=environment)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
print("GLPI_ASSET_SYNC_STAGE_READY")
print("The portal can perform an explicit, tenant-scoped GLPI Computer preview after a separate read-only sync credential is configured.")
print("This stage does not create credentials, contact GLPI, run an import, schedule a worker, modify GLPI, or modify customer assets.")
print(f"Code backup: {BACKUP}")

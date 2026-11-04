#!/usr/bin/env python3
"""Deploy the confirmed read-only GLPI operating-system inventory mapping."""
import os
import platform
import shutil
import subprocess
from pathlib import Path


HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-glpi-os-inventory-enrichment")
DESTINATION = Path("/opt/lsmon-portal")
PORTAL_ENVIRONMENT = Path("/etc/lsmon/portal.env")
BACKUP = Path("/var/backups/lsmon-portal/pre-glpi-os-inventory-enrichment-stage")
EXCLUDED = {"venv", "__pycache__", "lsmon-test.sqlite3"}


def run(command, *, env=None):
    subprocess.run(command, check=True, env=env)


def environment_values(path):
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
            shutil.copytree(
                item, target, dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"),
            )
        else:
            shutil.copy2(item, target)


if os.geteuid() != 0 or platform.node().split(".")[0] != HOST:
    raise SystemExit("STOP: run as root on vmi3626301 only")
required = (
    SOURCE / "manage.py",
    SOURCE / "lsmon_core" / "glpi_sync.py",
    SOURCE / "lsmon_core" / "management" / "commands" / "sync_glpi_assets.py",
    DESTINATION / "manage.py",
    PORTAL_ENVIRONMENT,
)
if not all(path.is_file() for path in required):
    raise SystemExit("STOP: staged source, GLPI OS reader, portal runtime, or portal environment is incomplete")
if BACKUP.exists():
    raise SystemExit(f"STOP: review or rename existing backup: {BACKUP}")

shutil.copytree(
    DESTINATION, BACKUP,
    ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"),
)
copy_source()
environment = os.environ.copy()
environment.update(environment_values(PORTAL_ENVIRONMENT))
python = str(DESTINATION / "venv/bin/python")
run([python, "-m", "py_compile", str(DESTINATION / "lsmon_core" / "glpi_sync.py")], env=environment)
run([python, "-m", "py_compile", str(DESTINATION / "lsmon_core" / "management" / "commands" / "sync_glpi_assets.py")], env=environment)
run([python, str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=environment)
run([python, str(DESTINATION / "manage.py"), "check"], env=environment)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
print("GLPI_OS_INVENTORY_ENRICHMENT_STAGE_READY")
print("A later explicit full sync can read GLPI Item_OperatingSystem labels using GET-only requests.")
print("This stage does not contact GLPI, run a sync, alter GLPI, or modify customer assets.")
print(f"Code backup: {BACKUP}")

#!/usr/bin/env python3
"""Deploy read-only GLPI network-interface inventory enrichment."""
import os
import platform
import shutil
import subprocess
from pathlib import Path

HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-glpi-network-interface-inventory")
DESTINATION = Path("/opt/lsmon-portal")
PORTAL_ENVIRONMENT = Path("/etc/lsmon/portal.env")
BACKUP = Path("/var/backups/lsmon-portal/pre-glpi-network-interface-inventory-stage")


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
    SOURCE / "manage.py", SOURCE / "lsmon_core" / "models.py", SOURCE / "lsmon_core" / "glpi_sync.py",
    SOURCE / "lsmon_core" / "management" / "commands" / "sync_glpi_assets.py",
    SOURCE / "lsmon_core" / "migrations" / "0026_asset_network_interface.py",
    SOURCE / "lsmon_core" / "views.py", SOURCE / "templates" / "asset_detail.html",
    DESTINATION / "manage.py", PORTAL_ENVIRONMENT,
)
if not all(path.is_file() for path in required):
    raise SystemExit("STOP: staged source, network-inventory files, portal runtime, or portal environment is incomplete")
if BACKUP.exists():
    raise SystemExit(f"STOP: review or rename existing backup: {BACKUP}")

shutil.copytree(DESTINATION, BACKUP, ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source()
environment = os.environ.copy()
environment.update(env_values(PORTAL_ENVIRONMENT))
python = str(DESTINATION / "venv/bin/python")
for relative_path in (
    "lsmon_core/models.py", "lsmon_core/glpi_sync.py", "lsmon_core/views.py",
    "lsmon_core/management/commands/sync_glpi_assets.py",
):
    run([python, "-m", "py_compile", str(DESTINATION / relative_path)], env=environment)
run([python, str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=environment)
run([python, str(DESTINATION / "manage.py"), "check"], env=environment)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
print("GLPI_NETWORK_INTERFACE_INVENTORY_STAGE_READY")
print("A later explicit full sync can read GLPI NIC names, MAC addresses, network labels, and IP addresses using GET-only requests.")
print("This stage does not contact GLPI, run a sync, alter endpoints, or change customer assignments.")
print(f"Code backup: {BACKUP}")

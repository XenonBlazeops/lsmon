#!/usr/bin/env python3
"""Deploy portal-owned customer placement metadata for tenant assets."""
import os
import platform
import shutil
import subprocess
from pathlib import Path

HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-asset-placement-overlay")
DESTINATION = Path("/opt/lsmon-portal")
PORTAL_ENVIRONMENT = Path("/etc/lsmon/portal.env")
BACKUP = Path("/var/backups/lsmon-portal/pre-asset-placement-overlay-stage")


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
            shutil.copytree(
                item,
                target,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"),
            )
        else:
            shutil.copy2(item, target)


if os.geteuid() != 0 or platform.node().split(".")[0] != HOST:
    raise SystemExit("STOP: run as root on vmi3626301 only")

required = (
    SOURCE / "manage.py",
    SOURCE / "lsmon_core" / "models.py",
    SOURCE / "lsmon_core" / "forms.py",
    SOURCE / "lsmon_core" / "views.py",
    SOURCE / "lsmon_core" / "migrations" / "0025_asset_placement_overlay.py",
    SOURCE / "lsmon_portal" / "urls.py",
    SOURCE / "templates" / "asset_list.html",
    SOURCE / "templates" / "asset_detail.html",
    SOURCE / "templates" / "asset_placement.html",
    DESTINATION / "manage.py",
    PORTAL_ENVIRONMENT,
)
if not all(path.is_file() for path in required):
    raise SystemExit("STOP: staged source, asset-placement files, portal runtime, or portal environment is incomplete")
if BACKUP.exists():
    raise SystemExit(f"STOP: review or rename existing backup: {BACKUP}")

shutil.copytree(DESTINATION, BACKUP, ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source()
environment = os.environ.copy()
environment.update(env_values(PORTAL_ENVIRONMENT))
python = str(DESTINATION / "venv/bin/python")
run([python, "-m", "py_compile", str(DESTINATION / "lsmon_core" / "models.py")], env=environment)
run([python, "-m", "py_compile", str(DESTINATION / "lsmon_core" / "forms.py")], env=environment)
run([python, "-m", "py_compile", str(DESTINATION / "lsmon_core" / "views.py")], env=environment)
run([python, str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=environment)
run([python, str(DESTINATION / "manage.py"), "check"], env=environment)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
print("ASSET_PLACEMENT_OVERLAY_STAGE_READY")
print("Tenant Administrators can assign portal-managed locations, departments, business units, and local IP details without changing GLPI.")
print("This stage does not contact GLPI, run a sync, alter endpoints, or change source inventory.")
print(f"Code backup: {BACKUP}")

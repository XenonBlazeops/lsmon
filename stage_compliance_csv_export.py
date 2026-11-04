#!/usr/bin/env python3
"""Deploy tenant-scoped, formula-safe compliance CSV export."""
import os
import platform
import shutil
import subprocess
from pathlib import Path

HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-compliance-csv-export")
DESTINATION = Path("/opt/lsmon-portal")
PORTAL_ENVIRONMENT = Path("/etc/lsmon/portal.env")
BACKUP = Path("/var/backups/lsmon-portal/pre-compliance-csv-export-stage")


def run(command, *, env=None):
    subprocess.run(command, check=True, env=env)


def env_values(path):
    return {line.split("=", 1)[0]: line.split("=", 1)[1] for line in path.read_text().splitlines() if "=" in line and not line.lstrip().startswith("#")}


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
required = (SOURCE / "manage.py", SOURCE / "lsmon_core" / "views.py", SOURCE / "lsmon_portal" / "urls.py", SOURCE / "templates" / "compliance_exceptions.html", DESTINATION / "manage.py", PORTAL_ENVIRONMENT)
if not all(path.is_file() for path in required):
    raise SystemExit("STOP: staged source, compliance-export files, portal runtime, or portal environment is incomplete")
if BACKUP.exists():
    raise SystemExit(f"STOP: review or rename existing backup: {BACKUP}")
shutil.copytree(DESTINATION, BACKUP, ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source()
environment = os.environ.copy()
environment.update(env_values(PORTAL_ENVIRONMENT))
python = str(DESTINATION / "venv/bin/python")
run([python, "-m", "py_compile", str(DESTINATION / "lsmon_core" / "views.py")], env=environment)
run([python, str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=environment)
run([python, str(DESTINATION / "manage.py"), "check"], env=environment)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
print("COMPLIANCE_CSV_EXPORT_STAGE_READY")
print("Tenant users can export only their portal-held compliance results in a formula-safe CSV file.")
print("This stage does not contact GLPI, run a sync, alter endpoints, or change criteria.")
print(f"Code backup: {BACKUP}")

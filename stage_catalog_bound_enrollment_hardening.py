#!/usr/bin/env python3
"""Deploy catalog-bound enrollment fail-closed checks without enabling the worker."""
import os
import platform
import shutil
import subprocess
from pathlib import Path

HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-catalog-bound-enrollment-hardening")
DESTINATION = Path("/opt/lsmon-portal")
ENVIRONMENT = Path("/etc/lsmon/portal.env")
BACKUP = Path("/var/backups/lsmon-portal/pre-catalog-bound-enrollment-hardening-stage")
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
            shutil.copytree(item, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.sqlite3"))
        else:
            shutil.copy2(item, target)


if os.geteuid() != 0 or platform.node().split(".")[0] != HOST:
    raise SystemExit("STOP: run as root on vmi3626301 only")
if not (SOURCE / "manage.py").is_file() or not (DESTINATION / "manage.py").is_file() or not ENVIRONMENT.is_file():
    raise SystemExit("STOP: expected staged source, existing runtime, or portal environment is missing")
if BACKUP.exists():
    raise SystemExit(f"STOP: review or rename existing backup: {BACKUP}")

shutil.copytree(DESTINATION, BACKUP, ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source()
env = os.environ.copy()
env.update(values(ENVIRONMENT))
run([str(DESTINATION / "venv/bin/python"), str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=env)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
print("CATALOG_BOUND_ENROLLMENT_HARDENING_STAGE_READY")
print("Only approved catalog-bound enrollments can download a manifest/bootstrap or issue/validate a registration code. No worker, secret, GLPI request, package download, installation, or endpoint enrollment was run.")
print(f"Code backup: {BACKUP}")

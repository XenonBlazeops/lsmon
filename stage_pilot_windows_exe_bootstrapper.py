#!/usr/bin/env python3
"""Deploy the lab-only, self-signed Windows EXE enrollment handoff."""
import os
import platform
import shutil
import subprocess
from pathlib import Path

HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-pilot-windows-exe-bootstrapper")
DESTINATION = Path("/opt/lsmon-portal")
ENVIRONMENT = Path("/etc/lsmon/portal.env")
BACKUP = Path("/var/backups/lsmon-portal/pre-pilot-windows-exe-bootstrapper-stage")
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
required = [
    SOURCE / "manage.py",
    SOURCE / "lsmon_core" / "views.py",
    SOURCE / "bootstrap" / "Install-LsmonWindowsAgent.ps1",
    SOURCE / "bootstrapper" / "LSMON Endpoint Setup.exe",
    SOURCE / "bootstrapper" / "Tecstaq-LSMON-Test-Signing.cer",
]
if not all(item.is_file() for item in required):
    raise SystemExit("STOP: staged pilot EXE bootstrapper source is incomplete")
if not (DESTINATION / "manage.py").is_file() or not ENVIRONMENT.is_file():
    raise SystemExit("STOP: existing portal runtime or portal environment is missing")
if BACKUP.exists():
    raise SystemExit(f"STOP: review or rename existing backup: {BACKUP}")

shutil.copytree(DESTINATION, BACKUP,
                ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source()
environment = os.environ.copy()
environment.update(values(ENVIRONMENT))
run([str(DESTINATION / "venv/bin/python"), str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=environment)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
print("PILOT_WINDOWS_EXE_BOOTSTRAPPER_STAGE_READY")
print("Tenant administrators can download the self-signed pilot EXE and public certificate; the EXE obtains a one-time bootstrap only after code validation.")
print("This stage does not enroll an endpoint, run a worker, download an MSI, install an agent, contact GLPI, or reveal a credential.")
print("The public endpoint /enroll/windows-bootstrap/ must be excluded from Cloudflare Access exactly like the existing enrollment validation/configuration paths.")
print(f"Code backup: {BACKUP}")

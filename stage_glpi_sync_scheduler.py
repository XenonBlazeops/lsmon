#!/usr/bin/env python3
"""Install the daily root-owned, GET-only Tecstaq GLPI sync timer."""
import os
import platform
import shutil
import subprocess
from pathlib import Path


HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-glpi-sync-scheduler")
DESTINATION = Path("/opt/lsmon-portal")
PORTAL_ENVIRONMENT = Path("/etc/lsmon/portal.env")
GLPI_ENVIRONMENT = Path("/etc/lsmon/glpi-sync.env")
BACKUP = Path("/var/backups/lsmon-portal/pre-glpi-sync-scheduler-stage")
SERVICE = Path("/etc/systemd/system/lsmon-glpi-sync@.service")
TIMER = Path("/etc/systemd/system/lsmon-glpi-sync-tecstaq.timer")
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
    SOURCE / "lsmon_core" / "management" / "commands" / "sync_glpi_assets.py",
    SOURCE / "lsmon_core" / "management" / "commands" / "evaluate_software_compliance.py",
    SOURCE / "systemd" / "lsmon-glpi-sync@.service",
    SOURCE / "systemd" / "lsmon-glpi-sync-tecstaq.timer",
    DESTINATION / "manage.py",
    PORTAL_ENVIRONMENT,
    GLPI_ENVIRONMENT,
)
if not all(path.is_file() for path in required):
    raise SystemExit("STOP: staged source, scheduler units, root-only environments, or portal runtime is incomplete")
if BACKUP.exists() or SERVICE.exists() or TIMER.exists():
    raise SystemExit("STOP: scheduler unit or backup already exists; review before replacement")

shutil.copytree(
    DESTINATION, BACKUP,
    ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"),
)
copy_source()
shutil.copy2(SOURCE / "systemd" / SERVICE.name, SERVICE)
shutil.copy2(SOURCE / "systemd" / TIMER.name, TIMER)
environment = os.environ.copy()
environment.update(environment_values(PORTAL_ENVIRONMENT))
python = str(DESTINATION / "venv/bin/python")
run([python, "-m", "py_compile", str(DESTINATION / "lsmon_core" / "management" / "commands" / "sync_glpi_assets.py")], env=environment)
run([python, "-m", "py_compile", str(DESTINATION / "lsmon_core" / "management" / "commands" / "evaluate_software_compliance.py")], env=environment)
run([python, str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=environment)
run([python, str(DESTINATION / "manage.py"), "check"], env=environment)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "daemon-reload"])
run(["systemctl", "enable", "--now", TIMER.name])
run(["systemctl", "is-active", TIMER.name])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
print("GLPI_SYNC_SCHEDULER_STAGE_READY")
print("The Tecstaq timer is enabled daily at 02:15 server-local time with up to 10 minutes random delay.")
print("Each run performs GET-only GLPI full sync, then portal-only compliance evaluation.")
print("The timer was enabled but this stage did not start a GLPI sync run, change GLPI, or alter endpoints.")
print(f"Code backup: {BACKUP}")

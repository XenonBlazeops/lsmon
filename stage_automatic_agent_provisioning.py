#!/usr/bin/env python3
"""Deploy automatic, least-privilege enrollment delivery on the approved host."""
import os
import platform
import shutil
import subprocess
from pathlib import Path

HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-automatic-agent-provisioning")
DESTINATION = Path("/opt/lsmon-portal")
ENVIRONMENT = Path("/etc/lsmon/portal.env")
PROVISIONER_ENVIRONMENT = Path("/etc/lsmon/provisioner.env")
SERVICE = Path("/etc/systemd/system/lsmon-provisioner.service")
TIMER = Path("/etc/systemd/system/lsmon-provisioner.timer")
BACKUP = Path("/var/backups/lsmon-portal/pre-automatic-agent-provisioning-stage")
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
if not all((
    (SOURCE / "manage.py").is_file(),
    (SOURCE / "bootstrap" / "Install-LsmonWindowsAgent.ps1").is_file(),
    (SOURCE / "systemd" / "lsmon-provisioner.service").is_file(),
    (SOURCE / "systemd" / "lsmon-provisioner.timer").is_file(),
    (DESTINATION / "manage.py").is_file(),
    ENVIRONMENT.is_file(),
    PROVISIONER_ENVIRONMENT.is_file(),
)):
    raise SystemExit("STOP: expected source, runtime, unit, or root-owned environment is missing")
if BACKUP.exists():
    raise SystemExit(f"STOP: review or rename existing backup: {BACKUP}")

shutil.copytree(DESTINATION, BACKUP,
                ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source()
shutil.copy2(SOURCE / "systemd" / "lsmon-provisioner.service", SERVICE)
shutil.copy2(SOURCE / "systemd" / "lsmon-provisioner.timer", TIMER)
environment = os.environ.copy()
environment.update(values(ENVIRONMENT))
run([str(DESTINATION / "venv/bin/python"), str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=environment)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "daemon-reload"])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
run(["systemctl", "enable", "--now", "lsmon-provisioner.timer"])
run(["systemctl", "is-active", "lsmon-provisioner.timer"])
print("AUTOMATIC_AGENT_PROVISIONING_STAGE_READY")
print("A least-privilege timer now processes queued, validated enrollments without UUID-specific operator commands. The Windows bootstrap writes a managed non-secret GLPI Agent server/tag configuration after MSI installation.")
print("The timer does not create tenants, packages, GLPI rules, or credentials, and it does not expose secret values.")
print(f"Code backup: {BACKUP}")

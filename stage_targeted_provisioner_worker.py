#!/usr/bin/env python3
"""Deploy a disabled, enrollment-targeted provisioner service template."""
import os
import platform
import shutil
import subprocess
from pathlib import Path

HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-targeted-provisioner-worker")
DESTINATION = Path("/opt/lsmon-portal")
ENVIRONMENT = Path("/etc/lsmon/portal.env")
UNIT_DESTINATION = Path("/etc/systemd/system/lsmon-provisioner@.service")
BACKUP = Path("/var/backups/lsmon-portal/pre-targeted-provisioner-worker-stage")
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
if not (SOURCE / "systemd/lsmon-provisioner@.service").is_file():
    raise SystemExit("STOP: targeted provisioner unit is missing from staged source")
if BACKUP.exists() or UNIT_DESTINATION.exists():
    raise SystemExit("STOP: targeted provisioner service already exists or backup path is occupied; review before replacement")

shutil.copytree(DESTINATION, BACKUP, ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source()
shutil.copy2(SOURCE / "systemd/lsmon-provisioner@.service", UNIT_DESTINATION)
env = os.environ.copy()
env.update(values(ENVIRONMENT))
run([str(DESTINATION / "venv/bin/python"), str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=env)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "daemon-reload"])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
print("TARGETED_PROVISIONER_WORKER_STAGE_READY")
print("A manual one-shot worker template can process only a named enrollment UUID. It is not enabled or started; no secret, GLPI request, package download, installation, or endpoint enrollment was run.")
print(f"Code backup: {BACKUP}")

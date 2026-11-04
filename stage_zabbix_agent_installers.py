#!/usr/bin/env python3
"""Deploy tenant-scoped Zabbix Agent 2 installer support to the LSMON portal."""
import os
import platform
import shutil
import subprocess
from pathlib import Path

HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-zabbix-agent-installers")
DESTINATION = Path("/opt/lsmon-portal")
PORTAL_ENVIRONMENT = Path("/etc/lsmon/portal.env")
PROVISIONER_ENVIRONMENT = Path("/etc/lsmon/provisioner.env")
BACKUP = Path("/var/backups/lsmon-portal/pre-zabbix-agent-installers-windows-msi-server-property-stage")
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
    SOURCE / "bootstrap" / "Install-LsmonZabbixAgentLinux.sh",
    SOURCE / "bootstrap" / "Install-LsmonZabbixAgentWindows.ps1",
    SOURCE / "lsmon_core" / "zabbix_api.py",
    DESTINATION / "manage.py",
    PORTAL_ENVIRONMENT,
    PROVISIONER_ENVIRONMENT,
)
if not all(path.is_file() for path in required):
    raise SystemExit("STOP: staged source, portal runtime, or provisioner environment is incomplete")
if not any(line.startswith("ZABBIX_API_TOKEN=") and len(line.split("=", 1)[1]) > 20
           for line in PROVISIONER_ENVIRONMENT.read_text(encoding="utf-8").splitlines()):
    raise SystemExit("STOP: /etc/lsmon/provisioner.env must contain the dedicated ZABBIX_API_TOKEN before deployment")
if BACKUP.exists():
    raise SystemExit(f"STOP: review or rename existing backup: {BACKUP}")

run(["bash", "-n", str(SOURCE / "bootstrap" / "Install-LsmonZabbixAgentLinux.sh")])
shutil.copytree(DESTINATION, BACKUP,
                ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source()
environment = os.environ.copy()
environment.update(values(PORTAL_ENVIRONMENT))
run([str(DESTINATION / "venv/bin/python"), "-m", "py_compile",
     str(DESTINATION / "lsmon_core" / "views.py"),
     str(DESTINATION / "lsmon_core" / "provisioner.py"),
     str(DESTINATION / "lsmon_core" / "zabbix_api.py")], env=environment)
run([str(DESTINATION / "venv/bin/python"), str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=environment)
run([str(DESTINATION / "venv/bin/python"), str(DESTINATION / "manage.py"), "check"], env=environment)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-provisioner.timer"])
print("ZABBIX_AGENT_INSTALLERS_STAGE_READY")
print("Approved Zabbix Agent 2 packages can now issue one-time, tenant-scoped Linux or Windows installers.")
print("The stage does not create a catalog package, issue a code, contact Zabbix, install an agent, or enroll an endpoint.")
print("The existing provisioner timer uses its root-owned environment for the Zabbix API token.")
print(f"Code backup: {BACKUP}")

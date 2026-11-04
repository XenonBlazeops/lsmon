#!/usr/bin/env python3
"""Deploy Windows RSA envelope compatibility and bootstrap source; worker stays disabled."""
import os, platform, shutil, subprocess
from pathlib import Path

HOST="vmi3626301"; SOURCE=Path("/home/ubuntu/lsmon-portal-windows-bootstrap"); DESTINATION=Path("/opt/lsmon-portal"); ENVIRONMENT=Path("/etc/lsmon/portal.env"); BACKUP=Path("/var/backups/lsmon-portal/pre-windows-bootstrap-stage")
def run(command, *, env=None): subprocess.run(command, check=True, env=env)
def values(path): return {line.split("=",1)[0]:line.split("=",1)[1] for line in path.read_text(encoding="utf-8").splitlines() if "=" in line and not line.lstrip().startswith("#")}
def copy_source():
    for item in SOURCE.iterdir():
        if item.name in {"venv","__pycache__","lsmon-test.sqlite3"} or item.suffix in {".pyc",".sqlite3"}: continue
        target=DESTINATION/item.name
        if item.is_dir(): shutil.copytree(item,target,dirs_exist_ok=True,ignore=shutil.ignore_patterns("__pycache__","*.pyc","*.sqlite3"))
        else: shutil.copy2(item,target)
if os.geteuid()!=0 or platform.node().split(".")[0]!=HOST: raise SystemExit("STOP: run as root on vmi3626301 only")
if not (SOURCE/"manage.py").is_file() or not (DESTINATION/"manage.py").is_file() or not ENVIRONMENT.is_file(): raise SystemExit("STOP: expected staged source, existing runtime, or portal environment is missing")
if not (SOURCE/"lsmon_core/migrations/0019_windows_bootstrap_key.py").is_file() or not (SOURCE/"bootstrap/Install-LsmonWindowsAgent.ps1").is_file(): raise SystemExit("STOP: staged Windows bootstrap source is incomplete")
if BACKUP.exists(): raise SystemExit(f"STOP: review or rename existing backup: {BACKUP}")
shutil.copytree(DESTINATION,BACKUP,ignore=shutil.ignore_patterns("venv","__pycache__","*.pyc","*.sqlite3")); copy_source()
env=os.environ.copy();env.update(values(ENVIRONMENT));run([str(DESTINATION/"venv/bin/python"),str(DESTINATION/"manage.py"),"migrate","--noinput"],env=env);run(["chown","-R","lsmon:lsmon",str(DESTINATION)]);run(["systemctl","restart","lsmon-portal.service"]);run(["systemctl","is-active","lsmon-portal.service"])
print("WINDOWS_BOOTSTRAP_COMPATIBILITY_STAGE_READY")
print("Windows bootstrap source and RSA envelope support are deployed. No worker was enabled or run; no secret, GLPI request, package download, agent installation, or endpoint enrollment occurred.")
print(f"Code backup: {BACKUP}")

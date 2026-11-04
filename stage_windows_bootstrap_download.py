#!/usr/bin/env python3
"""Deploy tenant Windows bootstrap download UI; no worker or installation action."""
import os, platform, shutil, subprocess
from pathlib import Path
HOST="vmi3626301"; SOURCE=Path("/home/ubuntu/lsmon-portal-windows-bootstrap-download"); DESTINATION=Path("/opt/lsmon-portal"); ENVIRONMENT=Path("/etc/lsmon/portal.env"); BACKUP=Path("/var/backups/lsmon-portal/pre-windows-bootstrap-download-stage")
def run(c,env=None): subprocess.run(c,check=True,env=env)
def vals(p): return {x.split('=',1)[0]:x.split('=',1)[1] for x in p.read_text().splitlines() if '=' in x and not x.lstrip().startswith('#')}
if os.geteuid()!=0 or platform.node().split('.')[0]!=HOST: raise SystemExit('STOP: run as root on vmi3626301 only')
if not (SOURCE/'manage.py').is_file() or not (DESTINATION/'manage.py').is_file() or not ENVIRONMENT.is_file() or not (SOURCE/'bootstrap/Install-LsmonWindowsAgent.ps1').is_file(): raise SystemExit('STOP: staged source or runtime is incomplete')
if BACKUP.exists(): raise SystemExit(f'STOP: review or rename existing backup: {BACKUP}')
shutil.copytree(DESTINATION,BACKUP,ignore=shutil.ignore_patterns('venv','__pycache__','*.pyc','*.sqlite3'))
for item in SOURCE.iterdir():
    if item.name in {'venv','__pycache__','lsmon-test.sqlite3'} or item.suffix in {'.pyc','.sqlite3'}: continue
    target=DESTINATION/item.name
    if item.is_dir(): shutil.copytree(item,target,dirs_exist_ok=True,ignore=shutil.ignore_patterns('__pycache__','*.pyc','*.sqlite3'))
    else: shutil.copy2(item,target)
env=os.environ.copy();env.update(vals(ENVIRONMENT));run([str(DESTINATION/'venv/bin/python'),str(DESTINATION/'manage.py'),'migrate','--noinput'],env);run(['chown','-R','lsmon:lsmon',str(DESTINATION)]);run(['systemctl','restart','lsmon-portal.service']);run(['systemctl','is-active','lsmon-portal.service'])
print('WINDOWS_BOOTSTRAP_DOWNLOAD_STAGE_READY')
print('Tenant Windows bootstrap download is available for ready Windows enrollments. No worker, secret, GLPI request, package download, installation, or endpoint enrollment was run.')
print(f'Code backup: {BACKUP}')

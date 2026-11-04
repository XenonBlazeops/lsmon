#!/usr/bin/env python3
"""Create private LSMON portal runtime and PostgreSQL role; no web route/service."""
import os, platform, secrets, shutil, subprocess
from pathlib import Path
HOST="vmi3626301"; SOURCE=Path("/home/ubuntu/lsmon-portal"); DEST=Path("/opt/lsmon-portal"); ENV=Path("/etc/lsmon/portal.env")
def run(a, **k): subprocess.run(a,check=True,**k)
if os.geteuid()!=0 or platform.node().split('.')[0]!=HOST: raise SystemExit("STOP: root on vmi3626301 only")
if not (SOURCE/"manage.py").is_file() or DEST.exists() or ENV.exists(): raise SystemExit("STOP: source missing or existing runtime detected")
run(["useradd","--system","--home-dir",str(DEST),"--shell","/usr/sbin/nologin","lsmon"])
shutil.copytree(SOURCE,DEST,ignore=shutil.ignore_patterns("__pycache__","*.sqlite3"))
run(["chown","-R","lsmon:lsmon",str(DEST)])
run(["python3","-m","venv",str(DEST/"venv")]); run([str(DEST/"venv/bin/pip"),"install","--requirement",str(DEST/"requirements.txt")])
password=secrets.token_urlsafe(32); django_secret=secrets.token_urlsafe(48)
sql=f"CREATE ROLE lsmon_portal LOGIN PASSWORD '{password}'; CREATE DATABASE lsmon_portal OWNER lsmon_portal;"
run(["runuser","-u","postgres","--","psql","-v","ON_ERROR_STOP=1","-c",sql])
ENV.parent.mkdir(mode=0o700); ENV.write_text("LSMON_DJANGO_SECRET_KEY="+django_secret+"\nLSMON_DB_ENGINE=django.db.backends.postgresql\nLSMON_DB_NAME=lsmon_portal\nLSMON_DB_USER=lsmon_portal\nLSMON_DB_PASSWORD="+password+"\nLSMON_DB_HOST=127.0.0.1\nLSMON_DB_PORT=5432\n",encoding="utf-8"); ENV.chmod(0o600)
run(["bash","-c",f"set -a; . {ENV}; set +a; {DEST}/venv/bin/python {DEST}/manage.py migrate --noinput"])
print("PORTAL_FOUNDATION_INSTALLED\nRuntime: /opt/lsmon-portal\nEnvironment: /etc/lsmon/portal.env\nNo web service or public route was created.")

#!/usr/bin/env python3
"""Complete interrupted LSMON database setup and rotate the exposed role password."""
import os, platform, secrets, subprocess
from pathlib import Path
H='vmi3626301'; DEST=Path('/opt/lsmon-portal'); ENV=Path('/etc/lsmon/portal.env')
def run(a):
    result = subprocess.run(a, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'database command failed')
if os.geteuid()!=0 or platform.node().split('.')[0]!=H: raise SystemExit('STOP: root on vmi3626301 only')
if not (DEST/'manage.py').is_file() or ENV.exists(): raise SystemExit('STOP: unexpected runtime or existing environment')
p=secrets.token_urlsafe(32); s=secrets.token_urlsafe(48)
run(['runuser','-u','postgres','--','psql','-v','ON_ERROR_STOP=1','-c',f"DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lsmon_portal') THEN ALTER ROLE lsmon_portal PASSWORD '{p}'; ELSE CREATE ROLE lsmon_portal LOGIN PASSWORD '{p}'; END IF; END $$;"])
run(['runuser','-u','postgres','--','createdb','-O','lsmon_portal','lsmon_portal'])
ENV.parent.mkdir(mode=0o700,exist_ok=True); ENV.write_text(f'LSMON_DJANGO_SECRET_KEY={s}\nLSMON_DB_ENGINE=django.db.backends.postgresql\nLSMON_DB_NAME=lsmon_portal\nLSMON_DB_USER=lsmon_portal\nLSMON_DB_PASSWORD={p}\nLSMON_DB_HOST=127.0.0.1\nLSMON_DB_PORT=5432\n'); ENV.chmod(0o600)
run(['bash','-c',f'set -a; . {ENV}; set +a; {DEST}/venv/bin/python {DEST}/manage.py migrate --noinput'])
print('PORTAL_DATABASE_REPAIRED\nNo credential values were printed.')

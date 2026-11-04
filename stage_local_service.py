#!/usr/bin/env python3
"""Install local-only Gunicorn and Nginx service endpoints for LSMON."""
import os
import platform
import shutil
import subprocess
from pathlib import Path


HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-local-service")
DESTINATION = Path("/opt/lsmon-portal")
ENVIRONMENT = Path("/etc/lsmon/portal.env")
UNIT = Path("/etc/systemd/system/lsmon-portal.service")
NGINX = Path("/etc/nginx/conf.d/lsmon-portal-local.conf")
BACKUP_ROOT = Path("/var/backups/lsmon-portal")
EXCLUDED = {"venv", "__pycache__", "lsmon-test.sqlite3"}

UNIT_CONTENT = """[Unit]
Description=LSMON private portal
After=network-online.target postgresql@18-main.service
Wants=network-online.target

[Service]
Type=exec
User=lsmon
Group=lsmon
WorkingDirectory=/opt/lsmon-portal
EnvironmentFile=/etc/lsmon/portal.env
ExecStart=/opt/lsmon-portal/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:8000 --access-logfile - --error-logfile - lsmon_portal.wsgi:application
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/lsmon-portal

[Install]
WantedBy=multi-user.target
"""

NGINX_CONTENT = """server {
    listen 127.0.0.1:8080;
    server_name app.tecstaqops.com;
    server_tokens off;
    client_max_body_size 1m;

    location /static/ {
        alias /opt/lsmon-portal/static/;
        access_log off;
        expires 1h;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
        proxy_http_version 1.1;
    }
}
"""


def run(command, *, env=None):
    subprocess.run(command, check=True, env=env)


def copy_source(source, destination):
    for item in source.iterdir():
        if item.name in EXCLUDED or item.suffix in {".pyc", ".sqlite3"}:
            continue
        target = destination / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.sqlite3"))
        else:
            shutil.copy2(item, target)


def read_environment(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


if os.geteuid() != 0 or platform.node().split(".")[0] != HOST:
    raise SystemExit("STOP: run as root on vmi3626301 only")
if not (SOURCE / "lsmon_portal/wsgi.py").is_file() or not (DESTINATION / "manage.py").is_file() or not ENVIRONMENT.is_file():
    raise SystemExit("STOP: expected staged source, existing runtime, or portal environment is missing")
if UNIT.exists() or NGINX.exists():
    raise SystemExit("STOP: local service configuration already exists; do not overwrite it")

backup = BACKUP_ROOT / "pre-local-service-stage"
if backup.exists():
    raise SystemExit(f"STOP: review or rename existing backup: {backup}")
BACKUP_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
shutil.copytree(DESTINATION, backup, ignore=shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.sqlite3"))
copy_source(SOURCE, DESTINATION)
run([str(DESTINATION / "venv/bin/pip"), "install", "--requirement", str(DESTINATION / "requirements.txt")])

values = read_environment(ENVIRONMENT)
with ENVIRONMENT.open("a", encoding="utf-8") as handle:
    if not values.get("LSMON_PUBLIC_HOST"):
        handle.write("LSMON_PUBLIC_HOST=app.tecstaqops.com\n")
        values["LSMON_PUBLIC_HOST"] = "app.tecstaqops.com"
    if "LSMON_BEHIND_TLS" not in values:
        handle.write("LSMON_BEHIND_TLS=false\n")
        values["LSMON_BEHIND_TLS"] = "false"
ENVIRONMENT.chmod(0o600)
environment = os.environ.copy()
environment.update(values)
run([str(DESTINATION / "venv/bin/python"), str(DESTINATION / "manage.py"), "migrate", "--noinput"], env=environment)
run(["chown", "-R", "lsmon:lsmon", str(DESTINATION)])
UNIT.write_text(UNIT_CONTENT, encoding="utf-8")
UNIT.chmod(0o644)
NGINX.write_text(NGINX_CONTENT, encoding="utf-8")
NGINX.chmod(0o644)
run(["nginx", "-t"])
run(["systemctl", "daemon-reload"])
run(["systemctl", "enable", "--now", "lsmon-portal.service"])
run(["systemctl", "reload", "nginx"])
status = subprocess.check_output(
    ["curl", "--fail", "--silent", "--show-error", "--output", "/dev/null", "--write-out", "%{http_code}", "-H", "Host: app.tecstaqops.com", "http://127.0.0.1:8080/"],
    text=True,
).strip()
if status != "302":
    raise SystemExit(f"STOP: expected local sign-in redirect (302), received HTTP {status}")
print("PORTAL_LOCAL_SERVICE_READY")
print("Gunicorn: 127.0.0.1:8000 only")
print("Nginx: 127.0.0.1:8080 only")
print(f"Code backup: {backup}")
print("No firewall rule, Cloudflare route, TLS setting, portal user, tenant, or email delivery was created.")

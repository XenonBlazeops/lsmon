#!/usr/bin/env python3
"""Repair the failed, unapplied tenant-slug migration on vmi3626301 only."""
import os
import platform
import shutil
import subprocess
from pathlib import Path

HOST = "vmi3626301"
SOURCE = Path("/home/ubuntu/lsmon-portal-tenant-routing-repair")
DESTINATION = Path("/opt/lsmon-portal")
ENVIRONMENT = Path("/etc/lsmon/portal.env")
MIGRATION = DESTINATION / "lsmon_core/migrations/0006_tenant_slug.py"
REPAIRED_MIGRATION = SOURCE / "0006_tenant_slug.py"
BACKUP = Path("/var/backups/lsmon-portal/failed-0006_tenant_slug.py")


def run(command, *, env=None, capture=False):
    return subprocess.run(command, check=True, env=env, text=True, capture_output=capture)


def environment_values(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


def scalar_psql(sql):
    result = run(
        ["runuser", "-u", "postgres", "--", "psql", "-d", "lsmon_portal", "-Atqc", sql],
        capture=True,
    )
    return result.stdout.strip()


if os.geteuid() != 0 or platform.node().split(".")[0] != HOST:
    raise SystemExit("STOP: run as root on vmi3626301 only")
if not ENVIRONMENT.is_file() or not MIGRATION.is_file() or not REPAIRED_MIGRATION.is_file():
    raise SystemExit("STOP: required portal environment or migration file is missing")
if BACKUP.exists():
    raise SystemExit(f"STOP: prior migration backup already exists: {BACKUP}")

env = os.environ.copy()
env.update(environment_values(ENVIRONMENT))
status = run(
    [str(DESTINATION / "venv/bin/python"), str(DESTINATION / "manage.py"), "showmigrations", "lsmon_core"],
    env=env,
    capture=True,
).stdout
if "[ ] 0006_tenant_slug" not in status:
    raise SystemExit("STOP: 0006 is not in the expected unapplied state")
if scalar_psql("SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='lsmon_core_tenant' AND column_name='slug';") != "0":
    raise SystemExit("STOP: tenant.slug already exists; manual review is required")
if scalar_psql("SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND tablename='lsmon_core_tenant' AND indexname LIKE 'lsmon_core_tenant_slug%';") != "0":
    raise SystemExit("STOP: a tenant slug index exists; manual review is required")

shutil.copy2(MIGRATION, BACKUP)
shutil.copy2(REPAIRED_MIGRATION, MIGRATION)
run([str(DESTINATION / "venv/bin/python"), str(DESTINATION / "manage.py"), "migrate", "lsmon_core", "0006", "--noinput"], env=env)
run(["chown", "lsmon:lsmon", str(MIGRATION)])
run(["systemctl", "restart", "lsmon-portal.service"])
run(["systemctl", "is-active", "lsmon-portal.service"])
tenant_rows = scalar_psql("SELECT string_agg(name || ':' || slug, ', ' ORDER BY name) FROM lsmon_core_tenant;")
print("TENANT_ROUTING_MIGRATION_REPAIRED")
print(f"Tenant routes: {tenant_rows}")
print(f"Original failed migration backup: {BACKUP}")
print("No tenant, user, membership, email, monitoring connector, or firewall change was created.")

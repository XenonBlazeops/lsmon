#!/usr/bin/env python3
"""Apply the R1 migration using the same environment as lsmon-portal.service."""

from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path


PORTAL_ROOT = Path("/opt/lsmon-portal")
ENVIRONMENT = Path("/etc/lsmon/portal.env")
MIGRATION = "0029_securityfinding_findingremediation_findingexception_and_more"
SERVICE = "lsmon-portal.service"


def environment_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def run(command: list[str], *, env: dict[str, str]) -> None:
    subprocess.run(command, cwd=PORTAL_ROOT, env=env, check=True)


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("STOP: run this repair as root")
    if socket.gethostname() != "vmi3626301":
        raise SystemExit("STOP: this repair is restricted to vmi3626301")
    if not (PORTAL_ROOT / "manage.py").is_file() or not ENVIRONMENT.is_file():
        raise SystemExit("STOP: expected LSMON portal runtime or environment is absent")
    if not (PORTAL_ROOT / "lsmon_core/migrations/0029_securityfinding_findingremediation_findingexception_and_more.py").is_file():
        raise SystemExit("STOP: the R1 migration source is absent")

    environment = os.environ.copy()
    environment.update(environment_values(ENVIRONMENT))
    python = str(PORTAL_ROOT / "venv/bin/python")
    run([python, "manage.py", "migrate", "lsmon_core", MIGRATION, "--noinput"], env=environment)
    run([python, "manage.py", "check"], env=environment)
    run(["systemctl", "restart", SERVICE], env=environment)
    run(["systemctl", "is-active", "--quiet", SERVICE], env=environment)

    print("SECURITY_REMEDIATION_FOUNDATION_ENV_REPAIR_READY")
    print("R1 migration was applied using the portal service environment.")
    print("No scanner, Wazuh query, CVE import, endpoint, patch, cloud action, credential, or command was run or exposed.")


if __name__ == "__main__":
    main()

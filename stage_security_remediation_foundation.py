#!/usr/bin/env python3
"""Deploy the portal-only tenant-scoped Findings and Remediation Center."""

from __future__ import annotations

import datetime as dt
import os
import shutil
import socket
import subprocess
from pathlib import Path


PORTAL_ROOT = Path("/opt/lsmon-portal")
SOURCE_ROOT = Path(__file__).resolve().parent
BACKUP_ROOT = Path("/var/backups/lsmon-portal")
SERVICE = "lsmon-portal.service"
FILES = (
    Path("lsmon_core/models.py"),
    Path("lsmon_core/forms.py"),
    Path("lsmon_core/views.py"),
    Path("lsmon_core/migrations/0029_securityfinding_findingremediation_findingexception_and_more.py"),
    Path("lsmon_portal/urls.py"),
    Path("templates/base.html"),
    Path("templates/security_findings.html"),
    Path("templates/security_finding_form.html"),
    Path("templates/security_finding_detail.html"),
)
EXISTING_PORTAL_FILES = (
    Path("lsmon_core/models.py"),
    Path("lsmon_core/forms.py"),
    Path("lsmon_core/views.py"),
    Path("lsmon_portal/urls.py"),
    Path("templates/base.html"),
)


def run(command: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def copy_tree_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("STOP: run this stage as root")
    if socket.gethostname() != "vmi3626301":
        raise SystemExit("STOP: this stage is restricted to vmi3626301")
    if not (Path("/etc/lsmon/portal.env").is_file() and PORTAL_ROOT.is_dir()):
        raise SystemExit("STOP: expected LSMON portal prerequisites are absent")
    if not all((SOURCE_ROOT / path).is_file() for path in FILES):
        raise SystemExit("STOP: expected staged source files are absent")
    if not all((PORTAL_ROOT / path).is_file() for path in EXISTING_PORTAL_FILES):
        raise SystemExit("STOP: expected staged or portal source files are absent")
    if "class SecurityFinding" not in (SOURCE_ROOT / "lsmon_core/models.py").read_text(encoding="utf-8"):
        raise SystemExit("STOP: staged model source is incomplete")
    if "security_findings" not in (SOURCE_ROOT / "lsmon_core/views.py").read_text(encoding="utf-8"):
        raise SystemExit("STOP: staged tenant isolation views are incomplete")
    if "Verified closure requires" not in (SOURCE_ROOT / "lsmon_core/models.py").read_text(encoding="utf-8"):
        raise SystemExit("STOP: staged verified-closure guard is incomplete")

    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    backup = BACKUP_ROOT / f"pre-security-remediation-foundation-stage-{timestamp}"
    backup.mkdir(parents=True, mode=0o700)
    migration_applied = False

    try:
        for relative_path in FILES:
            target = PORTAL_ROOT / relative_path
            if target.exists():
                copy_tree_file(target, backup / relative_path)
        for relative_path in FILES:
            copy_tree_file(SOURCE_ROOT / relative_path, PORTAL_ROOT / relative_path)
        python = str(PORTAL_ROOT / "venv" / "bin" / "python")
        run([python, "-m", "py_compile", *[str(PORTAL_ROOT / path) for path in FILES if path.suffix == ".py"]])
        run([python, "manage.py", "check"], cwd=PORTAL_ROOT)
        run([python, "manage.py", "migrate", "--noinput"], cwd=PORTAL_ROOT)
        migration_applied = True
        run(["chown", "-R", "lsmon:lsmon", *[str(PORTAL_ROOT / path) for path in FILES]])
        run(["systemctl", "restart", SERVICE])
        run(["systemctl", "is-active", "--quiet", SERVICE])
    except Exception:
        # Never restore pre-migration Python after a successful migration: the
        # schema and runtime must remain compatible until deliberate rollback.
        if not migration_applied:
            for relative_path in FILES:
                saved = backup / relative_path
                if saved.is_file():
                    copy_tree_file(saved, PORTAL_ROOT / relative_path)
            run(["chown", "-R", "lsmon:lsmon", *[str(PORTAL_ROOT / path) for path in FILES if (PORTAL_ROOT / path).exists()]])
            run(["systemctl", "restart", SERVICE])
        raise

    print("SECURITY_REMEDIATION_FOUNDATION_STAGE_READY")
    print("Tenant-scoped normalized findings, remediation references, time-bounded exceptions, and secret-free audit history are ready.")
    print("No scanner, Wazuh query, endpoint, patch, cloud action, credential, or remediation command was run or exposed.")
    print(f"Code backup: {backup}")


if __name__ == "__main__":
    main()

#!/usr/bin/env bash
# Export a secret-excluding snapshot of the live LSMON portal source.
# This is a reconciliation/export helper only: it never changes the live
# source, database, systemd units, Docker containers, or network settings.
set -euo pipefail

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  export-live-source-snapshot.sh [OUTPUT_DIRECTORY]

Exports /opt/lsmon-portal as a gzip tar archive with an adjacent SHA-256
checksum and manifest. Runtime state, virtual environments, staging/release
directories, local databases, environment files, and private-key material are
excluded.

Default output directory: /home/ubuntu/lsmon-live-source-snapshots
EOF
}

[[ $# -le 1 ]] || { usage >&2; exit 64; }

source_root=/opt/lsmon-portal
output_dir=${1:-/home/ubuntu/lsmon-live-source-snapshots}

[[ -d $source_root ]] || fail "Live portal directory does not exist: $source_root"
[[ -f $source_root/manage.py ]] || fail "manage.py is missing from: $source_root"
[[ $output_dir == /* ]] || fail 'Output directory must be absolute'

timestamp=$(date -u +%Y%m%d%H%M%S)
archive="$output_dir/lsmon-live-source-$timestamp.tar.gz"
checksum="$archive.sha256"
manifest="$output_dir/lsmon-live-source-$timestamp.manifest.txt"
workdir=$(mktemp -d /tmp/lsmon-live-source.XXXXXX)

cleanup() {
  rm -rf -- "$workdir"
}
trap cleanup EXIT

install -d -m 0750 "$output_dir"

# The archive is intentionally source-only. Secrets and runtime data belong in
# the existing root-only restore point and Acronis backup, not in a workstation
# reconciliation bundle.
tar -C /opt \
  --exclude='lsmon-portal/venv' \
  --exclude='lsmon-portal/releases' \
  --exclude='lsmon-portal/staging' \
  --exclude='lsmon-portal/artifacts' \
  --exclude='lsmon-portal/.git' \
  --exclude='lsmon-portal/**/__pycache__' \
  --exclude='lsmon-portal/*.sqlite3' \
  --exclude='lsmon-portal/.env' \
  --exclude='lsmon-portal/.env.*' \
  --exclude='lsmon-portal/**/*.key' \
  --exclude='lsmon-portal/**/*.pem' \
  --exclude='lsmon-portal/**/id_ed25519' \
  --exclude='lsmon-portal/**/id_rsa' \
  -czf "$archive" lsmon-portal

tar -tzf "$archive" > "$workdir/archive.list"
grep -qx 'lsmon-portal/manage.py' "$workdir/archive.list" \
  || fail 'Snapshot is missing lsmon-portal/manage.py'
grep -qx 'lsmon-portal/requirements.txt' "$workdir/archive.list" \
  || fail 'Snapshot is missing lsmon-portal/requirements.txt'
if grep -Eq '(^|/)(\.env|\.env\.|.*\.sqlite3|.*\.key|.*\.pem|id_ed25519|id_rsa)$' "$workdir/archive.list"; then
  fail 'Snapshot safety check found a forbidden secret/runtime path'
fi

sha256sum "$archive" > "$checksum"
{
  printf 'created_utc=%s\n' "$(date -u --iso-8601=seconds)"
  printf 'hostname=%s\n' "$(hostname)"
  printf 'source=%s\n' "$source_root"
  printf 'archive=%s\n' "$(basename "$archive")"
  printf 'sha256=%s\n' "$(awk '{print $1}' "$checksum")"
  printf 'purpose=source reconciliation only; not a production restore archive\n'
} > "$manifest"

# Permit the normal Ubuntu SFTP account to download the export without making
# its contents writable by that account. If that account is absent, leave the
# files root-owned and state the location for a root-operated transfer.
if id ubuntu >/dev/null 2>&1 && [[ $output_dir == /home/ubuntu/* ]]; then
  chown root:ubuntu "$archive" "$checksum" "$manifest"
  chmod 0640 "$archive" "$checksum" "$manifest"
else
  chmod 0600 "$archive" "$checksum" "$manifest"
fi

printf 'Live source snapshot created. No service or application state changed.\n'
printf 'Archive:  %s\n' "$archive"
printf 'Checksum: %s\n' "$checksum"
printf 'Manifest: %s\n' "$manifest"

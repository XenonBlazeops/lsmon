#!/usr/bin/env bash
# Verify and stage an LSMON release. This script deliberately does not activate it.
set -euo pipefail

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  stage-lsmon-release.sh RELEASE_ID ARCHIVE.tar.gz ARCHIVE.tar.gz.sha256 [RELEASE_ROOT]

Verifies the archive checksum and contents, then stages the extracted release.
It does not change the active release, start or restart services, run migrations,
or alter Docker, Nginx, Cloudflare, ports, or databases.

Default RELEASE_ROOT: /opt/lsmon-portal/releases
EOF
}

[[ $# -ge 3 && $# -le 4 ]] || {
  usage >&2
  exit 64
}

release_id=$1
archive=$2
checksum=$3
release_root=${4:-/opt/lsmon-portal/releases}

[[ $release_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail "Invalid release ID: $release_id"
[[ -r $archive ]] || fail "Archive is not readable: $archive"
[[ -r $checksum ]] || fail "Checksum file is not readable: $checksum"
[[ $release_root == /* ]] || fail "Release root must be an absolute path: $release_root"

case "$release_root" in
  /|/opt|/opt/lsmon-portal) fail "Unsafe release root: $release_root" ;;
esac

final_release="$release_root/$release_id"
[[ ! -e $final_release ]] || fail "Release already exists: $final_release"

install -d -m 0750 "$release_root"
verify_dir=$(mktemp -d "$release_root/.verify.${release_id}.XXXXXX")
stage_dir=$(mktemp -d "$release_root/.stage.${release_id}.XXXXXX")

cleanup() {
  [[ -n ${verify_dir:-} && -d $verify_dir ]] && rm -rf -- "$verify_dir"
  [[ -n ${stage_dir:-} && -d $stage_dir ]] && rm -rf -- "$stage_dir"
}
trap cleanup EXIT

archive_copy="$verify_dir/$(basename "$archive")"
checksum_copy="$verify_dir/$(basename "$checksum")"
cp -- "$archive" "$archive_copy"
cp -- "$checksum" "$checksum_copy"

(
  cd "$verify_dir"
  sha256sum --check --status "$(basename "$checksum_copy")"
) || fail "Checksum verification failed"

tar -tzf "$archive_copy" > "$verify_dir/archive.list"

grep -Eq '(^/|(^|/)\.\.(/|$))' "$verify_dir/archive.list" \
  && fail "Archive contains an unsafe path"
grep -qx 'lsmon-portal/manage.py' "$verify_dir/archive.list" \
  || fail "Archive does not contain lsmon-portal/manage.py"
grep -qx 'lsmon-portal/requirements.txt' "$verify_dir/archive.list" \
  || fail "Archive does not contain lsmon-portal/requirements.txt"

tar -xzf "$archive_copy" -C "$stage_dir"
test -f "$stage_dir/lsmon-portal/manage.py" || fail "Staged release is missing manage.py"
test -f "$stage_dir/lsmon-portal/requirements.txt" || fail "Staged release is missing requirements.txt"

mv -- "$stage_dir/lsmon-portal" "$final_release"
stage_dir=''

printf 'Release staged successfully: %s\n' "$final_release"
printf 'No activation or service changes were performed.\n'

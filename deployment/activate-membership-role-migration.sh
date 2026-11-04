#!/usr/bin/env bash
# Apply only the missing LSMON membership-role migration on the approved host.
set -euo pipefail

fail() {
  printf 'STOP: %s\n' "$*" >&2
  exit 1
}

HOST='vmi3626301'
LIVE='/opt/lsmon-portal'
ENV_FILE='/etc/lsmon/portal.env'
MIGRATION='0041_alter_membership_role.py'
SOURCE_DIR='/home/ubuntu/lsmon-membership-role-migration-v1'
SOURCE="$SOURCE_DIR/$MIGRATION"
TARGET="$LIVE/lsmon_core/migrations/$MIGRATION"
STAMP="$(date -u +%Y%m%d%H%M%S)"
BACKUP_DIR='/var/backups/lsmon-portal'
DATABASE_DUMP="$BACKUP_DIR/pre-membership-role-migration-${STAMP}.dump"

[[ ${EUID} -eq 0 ]] || fail 'Run as root.'
[[ $(hostname -s) == "$HOST" ]] || fail "This package is approved only for $HOST."
[[ -f $SOURCE ]] || fail "Missing staged migration: $SOURCE"
[[ -f $LIVE/manage.py && -f $ENV_FILE ]] || fail 'Live portal or environment file is missing.'
[[ ! -e $TARGET ]] || fail "Migration already exists: $TARGET"
grep -q 'PLATFORM_OPERATIONS' "$LIVE/lsmon_core/models.py" || fail 'Live model does not contain the expected platform role.'
grep -q 'platform_operations' "$SOURCE" || fail 'Staged migration does not contain the expected platform role.'
grep -q '0040_oidc_identity' "$SOURCE" || fail 'Staged migration has an unexpected dependency.'

install -d -o root -g root -m 0700 "$BACKUP_DIR"

echo '=== Preflight ==='
systemctl is-active --quiet lsmon-portal.service || fail 'lsmon-portal.service is not active.'

echo '=== Current migration status ==='
systemd-run --quiet --wait --pipe --collect \
  -p User=lsmon \
  -p Group=lsmon \
  -p WorkingDirectory="$LIVE" \
  -p EnvironmentFile="$ENV_FILE" \
  "$LIVE/venv/bin/python" manage.py showmigrations lsmon_core

PORTAL_DB="$(
  systemd-run --quiet --wait --pipe --collect \
    -p User=lsmon \
    -p Group=lsmon \
    -p WorkingDirectory="$LIVE" \
    -p EnvironmentFile="$ENV_FILE" \
    "$LIVE/venv/bin/python" manage.py shell -c \
    'from django.conf import settings; print(settings.DATABASES["default"]["NAME"])' \
    | tail -n 1
)"
[[ -n $PORTAL_DB ]] || fail 'Could not determine the portal database name.'

echo '=== Creating PostgreSQL rollback dump ==='
# Root opens the root-only backup file; pg_dump itself still runs as postgres.
runuser -u postgres -- pg_dump --format=custom "$PORTAL_DB" > "$DATABASE_DUMP"
chmod 0600 "$DATABASE_DUMP"

echo '=== Installing the single migration file ==='
install -o lsmon -g lsmon -m 0644 "$SOURCE" "$TARGET"

echo '=== Applying only lsmon_core.0041 ==='
systemd-run --quiet --wait --pipe --collect \
  -p User=lsmon \
  -p Group=lsmon \
  -p WorkingDirectory="$LIVE" \
  -p EnvironmentFile="$ENV_FILE" \
  "$LIVE/venv/bin/python" manage.py migrate lsmon_core 0041 --noinput

echo '=== Post-deployment validation ==='
systemd-run --quiet --wait --pipe --collect \
  -p User=lsmon \
  -p Group=lsmon \
  -p WorkingDirectory="$LIVE" \
  -p EnvironmentFile="$ENV_FILE" \
  "$LIVE/venv/bin/python" manage.py check

systemd-run --quiet --wait --pipe --collect \
  -p User=lsmon \
  -p Group=lsmon \
  -p WorkingDirectory="$LIVE" \
  -p EnvironmentFile="$ENV_FILE" \
  "$LIVE/venv/bin/python" manage.py showmigrations lsmon_core \
  | grep -F '[X] 0041_alter_membership_role'

systemctl is-active --quiet lsmon-portal.service || fail 'Portal service is not active after migration.'

echo 'MEMBERSHIP_ROLE_MIGRATION_APPLIED'
echo "Database rollback dump: $DATABASE_DUMP"
echo "Migration-file rollback: remove $TARGET, then restore $DATABASE_DUMP only if a deliberate database rollback is required."

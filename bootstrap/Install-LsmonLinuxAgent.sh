#!/usr/bin/env bash
# LSMON Linux bootstrap. Called only by a tenant-scoped one-file download.
# The registration code is single-use; OAuth credentials are delivered only in
# an encrypted envelope after the code has been validated by the portal.
set -euo pipefail
IFS=$'\n\t'

manifest_path="${1:-}"
registration_code="${2:-}"
delivery_wait_seconds="${LSMON_DELIVERY_WAIT_SECONDS:-600}"

fail() { printf '%s\n' "LSMON bootstrap stopped: $*" >&2; exit 1; }
cleanup() {
  if [[ -n "${work_dir:-}" && -d "$work_dir" ]]; then
    rm -rf -- "$work_dir"
  fi
}
trap cleanup EXIT

[[ "${EUID}" -eq 0 ]] || fail 'Run this installer as root (for example: sudo bash ./Install-LsmonLinuxAgent-*.sh).'
[[ -n "$manifest_path" && -f "$manifest_path" ]] || fail 'Enrollment manifest was not found.'
[[ -n "$registration_code" ]] || fail 'The one-time registration code was not supplied.'
command -v curl >/dev/null || fail 'curl is required.'
command -v openssl >/dev/null || fail 'openssl is required.'
command -v python3 >/dev/null || fail 'python3 is required.'
command -v perl >/dev/null || fail 'perl is required by the GLPI installer.'
command -v sha256sum >/dev/null || fail 'sha256sum is required.'
command -v base64 >/dev/null || fail 'base64 is required.'

read_manifest_field() {
  python3 - "$manifest_path" "$1" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
for key in sys.argv[2].split('.'):
    value = value[key]
if not isinstance(value, str):
    raise ValueError("expected a string")
print(value)
PY
}

manifest_kind="$(read_manifest_field kind)"
operating_system="$(read_manifest_field operating_system)"
enrollment_id="$(read_manifest_field enrollment_id)"
expires_at="$(read_manifest_field expires_at)"
validation_url="$(read_manifest_field validation_url)"
configuration_url="$(read_manifest_field configuration_url)"
package_url="$(read_manifest_field package.source_url)"
package_filename="$(read_manifest_field package.filename)"
package_sha256="$(read_manifest_field package.sha256)"

[[ "$manifest_kind" == 'lsmon-agent-bootstrap-manifest' && "$operating_system" == 'linux' ]] || fail 'This is not a Linux LSMON enrollment manifest.'
[[ "$validation_url" == https://* && "$configuration_url" == https://* && "$package_url" == https://* ]] || fail 'The manifest requires HTTPS URLs.'
[[ "$package_filename" =~ ^[A-Za-z0-9._-]+$ && "$package_sha256" =~ ^[A-Fa-f0-9]{64}$ ]] || fail 'The approved package metadata is invalid.'
python3 - "$expires_at" <<'PY' || fail 'This enrollment manifest has expired or is malformed.'
from datetime import datetime, timezone
import sys
value = datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
if value <= datetime.now(timezone.utc):
    raise SystemExit(1)
PY

work_dir="$(mktemp -d "/tmp/lsmon-${enrollment_id}.XXXXXX")"
chmod 700 "$work_dir"
package_path="$work_dir/$package_filename"
private_key="$work_dir/endpoint-private.pem"
public_key="$work_dir/endpoint-public.pem"
validation_response="$work_dir/validation.json"
delivery_response="$work_dir/delivery.json"

printf '%s\n' 'LSMON validating enrollment manifest.'
printf '%s\n' 'LSMON downloading the approved agent package.'
curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --output "$package_path" "$package_url"
printf '%s\n' 'LSMON validating the downloaded agent package.'
actual_sha256="$(sha256sum "$package_path" | awk '{print $1}')"
[[ "${actual_sha256^^}" == "${package_sha256^^}" ]] || fail 'Downloaded package checksum does not match the approved catalog record.'

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$private_key" >/dev/null 2>&1
chmod 600 "$private_key"
openssl pkey -in "$private_key" -pubout -out "$public_key" >/dev/null 2>&1
b64url_file() { base64 -w0 "$1" | tr '+/' '-_' | tr -d '='; }
endpoint_public_key="$(b64url_file "$public_key")"

printf '%s\n' 'LSMON package verified; registering this endpoint.'
curl --fail --silent --show-error --connect-timeout 15 --max-time 30 \
  --data-urlencode "enrollment_id=$enrollment_id" \
  --data-urlencode "registration_code=${registration_code^^}" \
  --data-urlencode "endpoint_public_key=$endpoint_public_key" \
  --data-urlencode 'endpoint_key_algorithm=rsa-pem-public-v1' \
  --output "$validation_response" "$validation_url" || fail 'Registration was rejected.'
delivery_token="$(python3 - "$validation_response" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("valid") is not True or not isinstance(data.get("delivery_token"), str):
    raise SystemExit(1)
print(data["delivery_token"])
PY
)" || fail 'Registration was rejected.'

printf '%s\n' "LSMON registration accepted for enrollment $enrollment_id; waiting up to ${delivery_wait_seconds} seconds for encrypted tenant configuration."
delivery_available=''
for ((attempt=0; attempt < (delivery_wait_seconds / 2); attempt++)); do
  sleep 2
  if curl --fail --silent --show-error --connect-timeout 15 --max-time 30 \
      --data-urlencode "delivery_token=$delivery_token" --output "$delivery_response" "$configuration_url"; then
    delivery_available="$(python3 - "$delivery_response" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
print('yes' if data.get('available') is True and isinstance(data.get('envelope'), dict) else '')
PY
)"
    [[ "$delivery_available" == yes ]] && break
  fi
done
[[ "$delivery_available" == yes ]] || fail 'Encrypted tenant configuration was not delivered before the timeout.'

python3 - "$delivery_response" "$work_dir" <<'PY'
import base64, json, pathlib, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
envelope = data["envelope"]
required = {"algorithm", "encrypted_key", "iv", "ciphertext", "tag"}
if envelope.get("algorithm") != "rsa-oaep-sha256+a256cbc-hs256" or not required <= set(envelope):
    raise SystemExit("unsupported configuration envelope")
target = pathlib.Path(sys.argv[2])
def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
for key in ("encrypted_key", "iv", "ciphertext", "tag"):
    (target / key).write_bytes(decode(envelope[key]))
PY

openssl pkeyutl -decrypt -inkey "$private_key" -in "$work_dir/encrypted_key" \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 \
  -out "$work_dir/keys"
[[ "$(wc -c < "$work_dir/keys")" -eq 64 ]] || fail 'Configuration key material was invalid.'
head -c 32 "$work_dir/keys" > "$work_dir/aes_key"
tail -c 32 "$work_dir/keys" > "$work_dir/mac_key"
printf 'lsmon-agent-delivery-v1:%s' "$enrollment_id" > "$work_dir/aad"
cat "$work_dir/aad" "$work_dir/iv" "$work_dir/ciphertext" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$(od -An -tx1 -v "$work_dir/mac_key" | tr -d ' \n')" -binary > "$work_dir/actual_tag"
[[ "$(od -An -tx1 -v "$work_dir/actual_tag" | tr -d ' \n')" == "$(od -An -tx1 -v "$work_dir/tag" | tr -d ' \n')" ]] || fail 'Configuration authentication failed.'
openssl enc -d -aes-256-cbc -K "$(od -An -tx1 -v "$work_dir/aes_key" | tr -d ' \n')" \
  -iv "$(od -An -tx1 -v "$work_dir/iv" | tr -d ' \n')" -in "$work_dir/ciphertext" -out "$work_dir/config.json"

printf '%s\n' 'LSMON encrypted tenant configuration received; installing the agent.'
# The vendor installer otherwise prompts for a GLPI URL and starts its service
# before this tenant's protected configuration has been written.  Install its
# files silently, keep the service stopped, then apply the delivered settings.
perl "$package_path" --install --no-question --service=0
grep -Eq '^[[:space:]]*include[[:space:]]+[" ]?conf\.d/' /etc/glpi-agent/agent.cfg || fail 'The installed GLPI Agent configuration does not include conf.d/.'
install -d -m 700 /etc/glpi-agent/conf.d
python3 - "$work_dir/config.json" /etc/glpi-agent/conf.d/90-lsmon.cfg <<'PY'
import json, os, pathlib, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
expected = ("server", "tag", "oauth_client_id", "oauth_client_secret")
if any(not isinstance(data.get(key), str) or not data[key] or "\n" in data[key] or "\r" in data[key] for key in expected):
    raise SystemExit("invalid tenant configuration")
if not data["server"].startswith("https://"):
    raise SystemExit("inventory target must use HTTPS")
content = "# Managed by LSMON enrollment. Contains the tenant OAuth secret.\n" + "\n".join((
    f"server = {data['server']}", f"tag = {data['tag']}", "tasks = inventory",
    "no-httpd = 1", "no-p2p = 1", "force = 1",
    f"oauth-client-id = {data['oauth_client_id']}",
    f"oauth-client-secret = {data['oauth_client_secret']}", "",
))
path = pathlib.Path(sys.argv[2])
path.write_text(content, encoding="utf-8")
os.chmod(path, 0o600)
PY
systemctl enable --now glpi-agent
glpi-agent --force
printf '%s\n' 'LSMON Linux agent bootstrap completed.'

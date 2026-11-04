#!/usr/bin/env bash
# Tenant-scoped Zabbix Agent 2 bootstrap. The PSK arrives only in the encrypted delivery envelope.
set -euo pipefail
IFS=$'\n\t'
manifest_path="${1:-}"; registration_code="${2:-}"; delivery_wait_seconds="${LSMON_DELIVERY_WAIT_SECONDS:-600}"
fail(){ printf '%s\n' "LSMON Zabbix bootstrap stopped: $*" >&2; exit 1; }
cleanup(){ [[ -n "${work_dir:-}" && -d "$work_dir" ]] && rm -rf -- "$work_dir"; }
trap cleanup EXIT
[[ "$EUID" -eq 0 ]] || fail 'Run this installer as root.'
[[ -f "$manifest_path" && -n "$registration_code" ]] || fail 'Enrollment manifest or registration code missing.'
for binary in curl openssl python3 sha256sum base64; do command -v "$binary" >/dev/null || fail "$binary is required."; done
field(){ python3 - "$manifest_path" "$1" <<'PY'
import json,sys
v=json.load(open(sys.argv[1],encoding='utf-8'))
for key in sys.argv[2].split('.'): v=v[key]
if not isinstance(v,str): raise ValueError('string required')
print(v)
PY
}
kind="$(field kind)"; vendor="$(field package.vendor)"; os="$(field operating_system)"; enrollment_id="$(field enrollment_id)"
validation_url="$(field validation_url)"; configuration_url="$(field configuration_url)"; package_url="$(field package.source_url)"; package_filename="$(field package.filename)"; package_sha256="$(field package.sha256)"
[[ "$kind" == 'lsmon-agent-bootstrap-manifest' && "$vendor" == 'zabbix' && "$os" == 'linux' ]] || fail 'Not a Linux Zabbix enrollment manifest.'
[[ "$validation_url" == https://* && "$configuration_url" == https://* && "$package_url" == https://* ]] || fail 'Manifest requires HTTPS URLs.'
[[ "$package_filename" =~ ^[A-Za-z0-9._+-]+$ && "$package_sha256" =~ ^[A-Fa-f0-9]{64}$ ]] || fail 'Approved package metadata is invalid.'
work_dir="$(mktemp -d "/tmp/lsmon-zabbix-${enrollment_id}.XXXXXX")"; chmod 700 "$work_dir"
package_path="$work_dir/$package_filename"; private_key="$work_dir/private.pem"; public_key="$work_dir/public.pem"
printf '%s\n' 'LSMON validating enrollment manifest.'
printf '%s\n' 'LSMON downloading the approved Zabbix Agent 2 package.'
curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --output "$package_path" "$package_url"
[[ "$(sha256sum "$package_path" | awk '{print $1}')" == "${package_sha256,,}" ]] || fail 'Package checksum does not match the approved catalog record.'
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$private_key" >/dev/null 2>&1; chmod 600 "$private_key"; openssl pkey -in "$private_key" -pubout -out "$public_key" >/dev/null 2>&1
endpoint_public_key="$(base64 -w0 "$public_key" | tr '+/' '-_' | tr -d '=')"; validation_response="$work_dir/validation.json"; delivery_response="$work_dir/delivery.json"
printf '%s\n' 'LSMON package verified; registering this endpoint.'
curl --fail --silent --show-error --connect-timeout 15 --max-time 30 --data-urlencode "enrollment_id=$enrollment_id" --data-urlencode "registration_code=${registration_code^^}" --data-urlencode "endpoint_public_key=$endpoint_public_key" --data-urlencode 'endpoint_key_algorithm=rsa-pem-public-v1' --output "$validation_response" "$validation_url" || fail 'Registration was rejected.'
delivery_token="$(python3 - "$validation_response" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8'))
if d.get('valid') is not True or not isinstance(d.get('delivery_token'),str): raise SystemExit(1)
print(d['delivery_token'])
PY
)" || fail 'Registration was rejected.'
printf '%s\n' "LSMON registration accepted for enrollment $enrollment_id; waiting up to ${delivery_wait_seconds} seconds for encrypted configuration."
available=''
for ((i=0;i<(delivery_wait_seconds/2);i++)); do
  sleep 2
  if curl --fail --silent --show-error --connect-timeout 15 --max-time 30 --data-urlencode "delivery_token=$delivery_token" --output "$delivery_response" "$configuration_url"; then
    available="$(python3 - "$delivery_response" <<'PY'
import json,sys
d=json.load(open(sys.argv[1],encoding='utf-8'))
print('yes' if d.get('available') is True and isinstance(d.get('envelope'),dict) else '')
PY
)"
    [[ "$available" == yes ]] && break
  fi
done
[[ "$available" == yes ]] || fail 'Encrypted tenant configuration was not delivered before the timeout.'
python3 - "$delivery_response" "$work_dir" <<'PY'
import base64,json,pathlib,sys
e=json.load(open(sys.argv[1],encoding='utf-8'))['envelope']; needed={'encrypted_key','iv','ciphertext','tag'}
if e.get('algorithm')!='rsa-oaep-sha256+a256cbc-hs256' or not needed <= set(e): raise SystemExit('unsupported envelope')
t=pathlib.Path(sys.argv[2])
for key in needed: t.joinpath(key).write_bytes(base64.urlsafe_b64decode(e[key]+'='*(-len(e[key])%4)))
PY
openssl pkeyutl -decrypt -inkey "$private_key" -in "$work_dir/encrypted_key" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -out "$work_dir/keys"
[[ "$(wc -c < "$work_dir/keys")" -eq 64 ]] || fail 'Configuration key material was invalid.'
head -c32 "$work_dir/keys" > "$work_dir/aes"; tail -c32 "$work_dir/keys" > "$work_dir/mac"; printf 'lsmon-agent-delivery-v1:%s' "$enrollment_id" > "$work_dir/aad"
cat "$work_dir/aad" "$work_dir/iv" "$work_dir/ciphertext" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$(od -An -tx1 -v "$work_dir/mac"|tr -d ' \n')" -binary > "$work_dir/actual_tag"
[[ "$(od -An -tx1 -v "$work_dir/actual_tag"|tr -d ' \n')" == "$(od -An -tx1 -v "$work_dir/tag"|tr -d ' \n')" ]] || fail 'Configuration authentication failed.'
openssl enc -d -aes-256-cbc -K "$(od -An -tx1 -v "$work_dir/aes"|tr -d ' \n')" -iv "$(od -An -tx1 -v "$work_dir/iv"|tr -d ' \n')" -in "$work_dir/ciphertext" -out "$work_dir/config.json"
printf '%s\n' 'LSMON encrypted Zabbix configuration received; installing the agent.'
# Prevent package-maintainer scripts from starting Agent 2 with a vendor-default
# listener before the encrypted tenant configuration has been written.
systemctl mask zabbix-agent2.service 2>/dev/null || true
case "$package_filename" in
  *.deb) command -v apt-get >/dev/null || fail 'This package requires Ubuntu or Debian.'; DEBIAN_FRONTEND=noninteractive apt-get install -y "$package_path" ;;
  *.rpm) command -v dnf >/dev/null || fail 'This package requires Rocky, AlmaLinux, or RHEL.'; dnf install -y "$package_path" ;;
  *) fail 'Approved Zabbix package must be a .deb or .rpm file.' ;;
esac
install -d -m0755 /etc/zabbix/zabbix_agent2.d
python3 - "$work_dir/config.json" /etc/zabbix/zabbix_agent2.d/90-lsmon.conf /etc/zabbix/lsmon_agent2.psk <<'PY'
import grp,json,os,pathlib,re,sys
d=json.load(open(sys.argv[1],encoding='utf-8')); keys=('server_active','hostname','tls_psk_identity','tls_psk')
if any(not isinstance(d.get(k),str) or not d[k] or '\n' in d[k] or '\r' in d[k] for k in keys): raise SystemExit('invalid configuration')
if not re.fullmatch(r'[0-9a-fA-F]{64}',d['tls_psk']): raise SystemExit('invalid PSK')
psk_path=pathlib.Path(sys.argv[3]); config_path=pathlib.Path(sys.argv[2])
psk_path.write_text(d['tls_psk']+'\n',encoding='ascii')
text='\n'.join(('Server=127.0.0.1','ListenIP=127.0.0.1',f"ServerActive={d['server_active']}",f"Hostname={d['hostname']}",'TLSConnect=psk','TLSAccept=psk',f"TLSPSKIdentity={d['tls_psk_identity']}",f'TLSPSKFile={sys.argv[3]}','DenyKey=system.run[*]','DenyKey=system.run[*,*]',''))
config_path.write_text(text,encoding='utf-8')
zabbix_gid=grp.getgrnam('zabbix').gr_gid
for path in (config_path,psk_path):
    os.chown(path,0,zabbix_gid)
    os.chmod(path,0o640)
PY
systemctl unmask zabbix-agent2.service
systemctl enable --now zabbix-agent2.service; systemctl is-active --quiet zabbix-agent2.service || fail 'Zabbix Agent 2 did not start.'
printf '%s\n' 'LSMON Zabbix Agent 2 bootstrap completed.'

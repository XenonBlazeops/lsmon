"""Server-side Zabbix API adapter used only by the provisioning worker."""
import json
import os
import secrets
from urllib.request import Request, urlopen
from .zabbix_dashboard import managed_host_name


class ZabbixProvisioningError(Exception):
    pass


def _call(method, params):
    token = os.environ.get("ZABBIX_API_TOKEN")
    if not token:
        raise ZabbixProvisioningError("zabbix_api_token_unavailable")
    request = Request(
        "http://127.0.0.1:8080/api_jsonrpc.php",
        data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode(),
        headers={"Content-Type": "application/json-rpc", "Host": "zabbix.tecstaqops.com", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode())
    except Exception as error:
        raise ZabbixProvisioningError("zabbix_api_unavailable") from error
    if payload.get("error"):
        raise ZabbixProvisioningError("zabbix_api_rejected")
    return payload.get("result", [])


def _id(method, name, key, filter_key="name"):
    result = _call(method, {"output": [key, "name"], "filter": {filter_key: [name]}})
    if len(result) != 1:
        raise ZabbixProvisioningError("zabbix_required_object_unavailable")
    return result[0][key]


def provision_active_agent(enrollment):
    """Create or safely rotate one active-check-only, PSK-protected host.

    A bootstrap can be interrupted after the worker creates the Zabbix host but
    before it downloads its encrypted configuration.  Retrying that enrollment
    must rotate the PSK on the same host rather than create a duplicate.
    """
    group_id = _id("hostgroup.get", "LSMON / Managed Endpoints", "groupid")
    template_name = "Windows by Zabbix agent active" if enrollment.operating_system == "windows" else "Linux by Zabbix agent active"
    template_id = _id("template.get", template_name, "templateid", "host")
    host = managed_host_name(enrollment)
    identity = f"lsmon-{enrollment.id}"
    psk = secrets.token_hex(32)
    payload = {"host": host, "name": host, "groups": [{"groupid": group_id}], "templates": [{"templateid": template_id}], "interfaces": [], "tls_connect": 2, "tls_accept": 2, "tls_psk_identity": identity, "tls_psk": psk}
    existing = _call("host.get", {"output": ["hostid"], "filter": {"host": [host]}})
    if len(existing) > 1:
        raise ZabbixProvisioningError("zabbix_host_not_unique")
    if existing:
        result = _call("host.update", {"hostid": existing[0]["hostid"], **payload})
        if not result:
            raise ZabbixProvisioningError("zabbix_host_update_failed")
    else:
        created = _call("host.create", payload)
        if not created:
            raise ZabbixProvisioningError("zabbix_host_create_failed")
    return {"server_active": "zabbix-agent.tecstaqops.com:10051", "hostname": host, "tls_psk_identity": identity, "tls_psk": psk, "deny_remote_commands": True}

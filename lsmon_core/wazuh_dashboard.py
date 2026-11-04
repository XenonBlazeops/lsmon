"""Read-only, tenant-scoped Wazuh coverage adapter.

The adapter deliberately asks Wazuh only for the configured tenant agent group.
It does not query global agents, alerts, vulnerabilities, or configuration.
"""

import base64
import json
import os
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from .secret_store import validate_reference


LOCAL_WAZUH_HOSTS = {"127.0.0.1", "::1", "localhost"}
GROUP_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,160}$")


class WazuhDashboardUnavailable(Exception):
    """A safe, non-sensitive reason a Wazuh summary cannot be displayed."""


def _local_endpoint(base_url):
    parsed = urlparse(base_url)
    try:
        approved = parsed.scheme == "https" and parsed.hostname in LOCAL_WAZUH_HOSTS and parsed.port == 55000
    except ValueError:
        approved = False
    if not approved:
        raise WazuhDashboardUnavailable("read_only_endpoint_not_approved")
    return base_url.rstrip("/")


def _credential(reference):
    validate_reference(reference)
    try:
        value = json.loads(os.environ[reference])
        username, password = value["username"], value["password"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise WazuhDashboardUnavailable("read_only_credential_unavailable") from None
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        raise WazuhDashboardUnavailable("read_only_credential_unavailable")
    return username, password


def _request(endpoint, method, path, *, basic_auth=None, token=None):
    headers = {"Accept": "application/json"}
    if basic_auth is not None:
        encoded = base64.b64encode(f"{basic_auth[0]}:{basic_auth[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(f"{endpoint}{path}", headers=headers, method=method)
    try:
        # The self-signed API certificate is accepted only after _local_endpoint
        # restricts transport to the local Wazuh manager.
        with urlopen(request, timeout=5, context=ssl._create_unverified_context()) as response:
            return response.read().decode()
    except (HTTPError, URLError, TimeoutError, ValueError):
        raise WazuhDashboardUnavailable("read_only_api_unavailable") from None


def summary_for_connector(connector, expected_assets):
    """Return only coverage from this connector's approved Wazuh agent group."""
    base = {
        "expected_assets": expected_assets,
        "agent_count": 0,
        "active_agents": 0,
    }
    if connector is None:
        return {**base, "state": "no_connector"}
    if not GROUP_PATTERN.fullmatch(connector.scope or ""):
        return {**base, "state": "invalid_scope"}
    try:
        endpoint = _local_endpoint(connector.base_url)
        credential = _credential(connector.credential_reference)
        token = _request(endpoint, "POST", "/security/user/authenticate?raw=true", basic_auth=credential).strip()
        if not token:
            raise WazuhDashboardUnavailable("read_only_api_rejected")
        group = quote(connector.scope, safe="")
        payload = json.loads(_request(
            endpoint, "GET", f"/groups/{group}/agents?limit=500&select=id,name,status,group", token=token,
        ))
        if payload.get("error") not in (0, None):
            raise WazuhDashboardUnavailable("read_only_api_rejected")
        agents = payload.get("data", {}).get("affected_items", [])
        if not isinstance(agents, list):
            raise WazuhDashboardUnavailable("read_only_api_rejected")
    except WazuhDashboardUnavailable as error:
        return {**base, "state": str(error)}
    except json.JSONDecodeError:
        return {**base, "state": "read_only_api_rejected"}
    return {
        **base,
        "state": "ready",
        "agent_count": len(agents),
        "active_agents": sum(agent.get("status") == "active" for agent in agents if isinstance(agent, dict)),
    }


def provider_summary_for_connectors(connectors):
    """Return provider-wide coverage counts without returning tenant agents.

    Each configured tenant connector is queried independently through its own
    reader identity and group restriction.  This summary intentionally returns
    counts only, so the provider overview cannot reveal endpoint names.
    """
    result = {
        "configured_tenants": 0,
        "available_tenants": 0,
        "agent_count": 0,
        "active_agents": 0,
    }
    for connector in connectors:
        summary = summary_for_connector(connector, 0)
        result["configured_tenants"] += 1
        if summary["state"] == "ready":
            result["available_tenants"] += 1
            result["agent_count"] += summary["agent_count"]
            result["active_agents"] += summary["active_agents"]
    return result

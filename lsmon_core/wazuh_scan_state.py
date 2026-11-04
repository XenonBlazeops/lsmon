"""Read-only, tenant-scoped Wazuh SCA and FIM freshness adapter.

This module reports only agent identity, status, and bounded completion
timestamps.  It never returns SCA results, FIM paths, rules, alerts, or raw
Wazuh API bodies.  The existing Wazuh reader role and its group restriction are
the authorization boundary; the portal still requests only its configured
tenant group.
"""

from datetime import datetime, timedelta, timezone as datetime_timezone

from .wazuh_dashboard import (
    GROUP_PATTERN,
    WazuhDashboardUnavailable,
    _credential,
    _local_endpoint,
    _request,
)


STALE_AFTER = timedelta(hours=26)
TIMESTAMP_KEYS = {"end_scan", "start_scan", "end", "start"}


def _timestamps(value):
    """Extract only bounded timestamp strings from an API response object."""
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in TIMESTAMP_KEYS and isinstance(child, str) and len(child) <= 64:
                parsed = _parse_timestamp(child)
                if parsed is not None:
                    found.append(parsed)
            found.extend(_timestamps(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_timestamps(child))
    return found


def _parse_timestamp(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(datetime_timezone.utc)


def _latest_timestamp(raw_body):
    try:
        import json
        candidates = _timestamps(json.loads(raw_body))
    except (TypeError, ValueError):
        return None
    return max(candidates, default=None)


def _freshness(timestamp, now):
    if timestamp is None:
        return "not_reported"
    return "current" if now - timestamp <= STALE_AFTER else "stale"


def _utc_display(timestamp):
    return timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if timestamp is not None else "Not reported"


def summary_for_connector(connector, *, now=None):
    """Return only current tenant-group scan completion state.

    A Wazuh response failure makes the individual endpoint unavailable.  It
    does not cause a retry, scan, or configuration change.
    """
    base = {"state": "not_configured", "agent_count": 0, "current": 0, "stale": 0,
            "not_reported": 0, "unavailable": 0, "agents": [], "latest": None}
    if connector is None:
        return {**base, "state": "no_connector"}
    if not GROUP_PATTERN.fullmatch(connector.scope or ""):
        return {**base, "state": "invalid_scope"}
    now = now or datetime.now(datetime_timezone.utc)
    try:
        endpoint = _local_endpoint(connector.base_url)
        credential = _credential(connector.credential_reference)
        token = _request(endpoint, "POST", "/security/user/authenticate?raw=true", basic_auth=credential).strip()
        if not token:
            raise WazuhDashboardUnavailable("read_only_api_rejected")
        import json
        from urllib.parse import quote
        group = quote(connector.scope, safe="")
        response = json.loads(_request(
            endpoint, "GET", f"/groups/{group}/agents?limit=500&select=id,name,status,group", token=token,
        ))
        raw_agents = response.get("data", {}).get("affected_items", [])
        if not isinstance(raw_agents, list):
            raise WazuhDashboardUnavailable("read_only_api_rejected")
    except (WazuhDashboardUnavailable, ValueError):
        return {**base, "state": "reader_unavailable"}

    rows = []
    for agent in raw_agents:
        if not isinstance(agent, dict) or not isinstance(agent.get("id"), str):
            continue
        identifier = agent["id"]
        name = agent.get("name") if isinstance(agent.get("name"), str) else identifier
        name = name[:160]
        try:
            sca = _latest_timestamp(_request(endpoint, "GET", f"/sca/{identifier}?limit=1", token=token))
            fim = _latest_timestamp(_request(endpoint, "GET", f"/syscheck/{identifier}/last_scan", token=token))
        except WazuhDashboardUnavailable:
            rows.append({"id": identifier, "name": name, "status": agent.get("status"),
                         "sca": None, "fim": None, "sca_display": "Not reported",
                         "fim_display": "Not reported", "freshness": "unavailable"})
            continue
        latest = max((value for value in (sca, fim) if value is not None), default=None)
        rows.append({"id": identifier, "name": name, "status": agent.get("status"),
                     "sca": sca, "fim": fim, "sca_display": _utc_display(sca),
                     "fim_display": _utc_display(fim), "freshness": _freshness(latest, now)})

    counts = {key: sum(item["freshness"] == key for item in rows)
              for key in ("current", "stale", "not_reported", "unavailable")}
    reported = [value for item in rows for value in (item["sca"], item["fim"]) if value is not None]
    latest = max(reported, default=None)
    return {"state": "ready", "agent_count": len(rows), "agents": rows, "latest": latest,
            "latest_display": _utc_display(latest), **counts}


def provider_summary_for_connectors(connectors, *, now=None):
    """Aggregate only count summaries from each tenant's own reader.

    This intentionally makes one separate call path per connector.  It does
    not share tenant credentials, return per-agent rows to the provider, or
    use a provider-wide Wazuh identity.
    """
    result = {
        "configured_tenants": 0,
        "available_tenants": 0,
        "agent_count": 0,
        "current": 0,
        "stale": 0,
        "not_reported": 0,
        "unavailable": 0,
        "tenants": [],
    }
    for connector in connectors:
        summary = summary_for_connector(connector, now=now)
        tenant = connector.tenant
        row = {"name": tenant.name, "slug": tenant.slug, "state": summary["state"],
               "agent_count": 0, "current": 0, "stale": 0, "not_reported": 0, "unavailable": 0}
        result["configured_tenants"] += 1
        if summary["state"] == "ready":
            result["available_tenants"] += 1
            for key in ("agent_count", "current", "stale", "not_reported", "unavailable"):
                row[key] = summary[key]
                result[key] += summary[key]
        if summary["state"] != "ready":
            row["attention"] = "Reader unavailable"
        else:
            row["attention"] = "Review" if row["stale"] or row["not_reported"] or row["unavailable"] else "Current"
        result["tenants"].append(row)
    return result

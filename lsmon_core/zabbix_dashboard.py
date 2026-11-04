"""Read-only, tenant-scoped Zabbix dashboard adapter.

The provisioner token is deliberately not accepted here.  A deployment must
provide a separate ZABBIX_DASHBOARD_API_TOKEN with read-only access.
"""
import json
import os
from datetime import datetime, timezone
from urllib.request import Request, urlopen


class ZabbixDashboardUnavailable(Exception):
    """The dashboard cannot safely obtain current Zabbix data."""


def managed_host_name(enrollment):
    """Return the deterministic Zabbix hostname for one LSMON enrollment."""
    return f"lsmon-{enrollment.tenant.slug}-{str(enrollment.id)[:12]}"


def _call(method, params):
    token = os.environ.get("ZABBIX_DASHBOARD_API_TOKEN")
    if not token:
        raise ZabbixDashboardUnavailable("read_only_token_unavailable")
    endpoint = os.environ.get("ZABBIX_DASHBOARD_API_URL", "http://127.0.0.1:8080/api_jsonrpc.php")
    request = Request(
        endpoint,
        data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode(),
        headers={
            "Content-Type": "application/json-rpc",
            "Host": "zabbix.tecstaqops.com",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode())
    except Exception as error:
        raise ZabbixDashboardUnavailable("read_only_api_unavailable") from error
    if payload.get("error"):
        raise ZabbixDashboardUnavailable("read_only_api_rejected")
    return payload.get("result", [])


def _problem(problem):
    try:
        observed_at = datetime.fromtimestamp(int(problem["clock"]), tz=timezone.utc)
    except (KeyError, TypeError, ValueError, OverflowError):
        observed_at = None
    return {
        "name": problem.get("name", "Unnamed Zabbix problem"),
        "severity": int(problem.get("severity", 0)),
        "observed_at": observed_at,
        "acknowledged": str(problem.get("acknowledged", "0")) == "1",
    }


def summary_for_enrollments(enrollments):
    """Return a safe dashboard summary for the supplied tenant enrollments.

    Callers supply only Zabbix enrollments which they are authorized to view.
    No broad host or problem query is ever made from a tenant dashboard.
    """
    hostnames = [managed_host_name(enrollment) for enrollment in enrollments]
    if not hostnames:
        return {"state": "no_enrollments", "expected_hosts": 0, "hosts": [], "problems": []}
    try:
        hosts = _call("host.get", {
            "output": ["hostid", "host", "name", "status", "active_available"],
            "filter": {"host": hostnames},
        })
    except ZabbixDashboardUnavailable as error:
        return {"state": str(error), "expected_hosts": len(hostnames), "hosts": [], "problems": []}

    host_ids = [host["hostid"] for host in hosts if host.get("hostid")]
    problem_limit = 10
    try:
        problem_count = _call("problem.get", {
            "hostids": host_ids,
            "recent": True,
            "countOutput": True,
        }) if host_ids else "0"
        problems = _call("problem.get", {
            "output": ["eventid", "name", "severity", "clock", "acknowledged"],
            "hostids": host_ids,
            "recent": True,
            "sortfield": ["eventid"],
            "sortorder": "DESC",
            "limit": problem_limit,
        }) if host_ids else []
    except ZabbixDashboardUnavailable as error:
        return {"state": str(error), "expected_hosts": len(hostnames), "hosts": [], "problems": []}

    normalized_hosts = [{
        "name": host.get("name") or host.get("host"),
        "available": str(host.get("active_available", "0")) == "1",
        "enabled": str(host.get("status", "1")) == "0",
    } for host in hosts]
    return {
        "state": "ready",
        "expected_hosts": len(hostnames),
        "hosts": normalized_hosts,
        "available_hosts": sum(host["available"] and host["enabled"] for host in normalized_hosts),
        "problems": [_problem(problem) for problem in problems],
        "problem_count": int(problem_count) if str(problem_count).isdigit() else len(problems),
        "problem_limit": problem_limit,
    }

"""Read-only tenant-scoped Wazuh alert-count adapter.

Alerts are stored in the Wazuh indexer rather than the Wazuh manager API. The
portal consequently accepts only a loopback indexer endpoint and relies on a
separate provider-managed read-only Indexer identity. That identity must use
document-level security for the tenant's assigned Wazuh agent IDs. The portal
does not send agent IDs or a group filter because neither is an authorization
boundary; Indexer DLS is the boundary.
"""

import base64
import json
import os
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from .secret_store import validate_reference
from .wazuh_dashboard import GROUP_PATTERN


LOCAL_INDEXER_HOSTS = {"127.0.0.1", "::1", "localhost"}


class WazuhFindingsUnavailable(Exception):
    """A safe, non-sensitive reason the findings summary cannot be displayed."""


def _local_indexer_endpoint(base_url):
    parsed = urlparse(base_url)
    try:
        approved = parsed.scheme == "https" and parsed.hostname in LOCAL_INDEXER_HOSTS and parsed.port == 9200
    except ValueError:
        approved = False
    if not approved:
        raise WazuhFindingsUnavailable("findings_endpoint_not_approved")
    return base_url.rstrip("/")


def _credential(reference):
    validate_reference(reference)
    try:
        value = json.loads(os.environ[reference])
        username, password = value["username"], value["password"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise WazuhFindingsUnavailable("findings_credential_unavailable") from None
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        raise WazuhFindingsUnavailable("findings_credential_unavailable")
    return username, password


def _search(endpoint, credential, payload):
    encoded = base64.b64encode(f"{credential[0]}:{credential[1]}".encode()).decode()
    request = Request(
        f"{endpoint}/wazuh-alerts-4.x-*/_search",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Basic {encoded}",
        },
        method="POST",
    )
    try:
        # This accepts the self-signed indexer certificate only after strict
        # loopback/port validation above. The indexer is never public.
        with urlopen(request, timeout=5, context=ssl._create_unverified_context()) as response:
            return json.loads(response.read().decode())
    except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError):
        raise WazuhFindingsUnavailable("findings_api_unavailable") from None


def summary_for_connector(connector):
    """Return 24-hour severity counts, never individual alerts or raw events."""
    empty = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    if connector is None:
        return {**empty, "state": "no_connector"}
    if not connector.findings_base_url or not connector.findings_credential_reference:
        return {**empty, "state": "not_configured"}
    if not GROUP_PATTERN.fullmatch(connector.scope or ""):
        return {**empty, "state": "invalid_scope"}
    try:
        endpoint = _local_indexer_endpoint(connector.findings_base_url)
        credential = _credential(connector.findings_credential_reference)
        payload = {
            "size": 0,
            "track_total_hits": True,
            "query": {"bool": {"filter": [
                {"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}},
            ]}},
            "aggs": {
                "critical": {"filter": {"range": {"rule.level": {"gte": 15}}}},
                "high": {"filter": {"range": {"rule.level": {"gte": 12, "lte": 14}}}},
                "medium": {"filter": {"range": {"rule.level": {"gte": 7, "lte": 11}}}},
                "low": {"filter": {"range": {"rule.level": {"gte": 0, "lte": 6}}}},
            },
        }
        result = _search(endpoint, credential, payload)
        aggregations = result.get("aggregations", {})
        counts = {name: aggregations[name]["doc_count"] for name in empty if name != "total"}
        total = result.get("hits", {}).get("total", {}).get("value")
        if not isinstance(total, int) or any(not isinstance(value, int) for value in counts.values()):
            raise WazuhFindingsUnavailable("findings_api_rejected")
    except WazuhFindingsUnavailable as error:
        return {**empty, "state": str(error)}
    except (KeyError, TypeError):
        return {**empty, "state": "findings_api_rejected"}
    return {"state": "ready", "total": total, **counts}


def attention_for_summary(summary):
    """Return a safe, count-derived status without returning alert details."""
    if summary.get("state") != "ready":
        return "Reader unavailable"
    if summary["critical"]:
        return "Immediate attention"
    if summary["high"]:
        return "Priority review"
    if summary["medium"]:
        return "Review"
    if summary["low"]:
        return "Monitor"
    return "No alerts"


def provider_summary_for_connectors(connectors):
    """Aggregate safe counts from each tenant's own DLS-bound reader.

    This deliberately invokes ``summary_for_connector`` one connector at a
    time.  It never substitutes a provider-wide Indexer identity, combines
    tenant credentials, or returns individual alert data.  A connector that
    is not ready is represented only by its safe state label and contributes
    no counts to the aggregate.
    """
    empty = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    result = {
        **empty,
        "configured_tenants": 0,
        "available_tenants": 0,
        "attention_tenants": 0,
        "tenants": [],
    }
    for connector in connectors:
        summary = summary_for_connector(connector)
        tenant = connector.tenant
        row = {
            "name": tenant.name,
            "slug": tenant.slug,
            "state": summary["state"],
            **empty,
        }
        result["configured_tenants"] += 1
        if summary["state"] == "ready":
            result["available_tenants"] += 1
            for name in empty:
                row[name] = summary[name]
                result[name] += summary[name]
            row["attention"] = attention_for_summary(row)
            if row["critical"] or row["high"] or row["medium"]:
                result["attention_tenants"] += 1
        else:
            row["attention"] = attention_for_summary(row)
        result["tenants"].append(row)
    return result

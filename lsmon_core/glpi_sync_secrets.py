"""Secret boundary for the dedicated, read-only GLPI synchronization service.

The portal web process must not receive these values.  A separately-owned
systemd service imports this environment file only when a preview or an
approved apply operation is explicitly run.
"""
import json
import os

from .secret_store import SecretUnavailable, validate_reference


ENVIRONMENT_PREFIX = "LSMON_GLPI_SYNC_SECRET_"


def resolve_glpi_sync_credentials(reference):
    reference = validate_reference(reference)
    raw = os.environ.get(f"{ENVIRONMENT_PREFIX}{reference}")
    if not raw:
        raise SecretUnavailable("GLPI sync credential reference is not available to the sync service.")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SecretUnavailable("GLPI sync credential bundle is not valid JSON.") from error
    if not isinstance(value, dict) or not all(isinstance(value.get(key), str) and value[key] for key in ("app_token", "user_token")):
        raise SecretUnavailable("GLPI sync credential bundle requires non-empty app_token and user_token values.")
    access_keys = ("cf_access_client_id", "cf_access_client_secret")
    present_access_keys = [key for key in access_keys if value.get(key)]
    if present_access_keys and (len(present_access_keys) != 2 or not all(isinstance(value.get(key), str) for key in access_keys)):
        raise SecretUnavailable("Cloudflare Access credentials require both client ID and client secret.")
    result = {"app_token": value["app_token"], "user_token": value["user_token"]}
    if present_access_keys:
        result.update({key: value[key] for key in access_keys})
    return result

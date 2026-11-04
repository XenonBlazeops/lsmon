"""Pilot secret-store adapter.

Production values live outside Django in a root-owned service environment. This
module exposes references only to server-side provisioning code; views must
never return a resolved value.
"""
import os
import re


REFERENCE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
ENVIRONMENT_PREFIX = "LSMON_AGENT_SECRET_"


class SecretUnavailable(Exception):
    pass


def validate_reference(reference):
    if not REFERENCE_PATTERN.fullmatch(reference or ""):
        raise ValueError("Invalid credential reference.")
    return reference


def has_secret(reference):
    reference = validate_reference(reference)
    return bool(os.environ.get(f"{ENVIRONMENT_PREFIX}{reference}"))


def resolve_secret(reference):
    reference = validate_reference(reference)
    value = os.environ.get(f"{ENVIRONMENT_PREFIX}{reference}")
    if not value:
        raise SecretUnavailable("Credential reference is not available to the provisioning service.")
    return value

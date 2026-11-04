from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class ExternalAsset:
    source: str
    external_id: str
    name: str

class InventoryAdapter(Protocol):
    def list_assets(self, tenant_id: str) -> list[ExternalAsset]: ...

class GlpiAdapter(InventoryAdapter):
    """Placeholder: read-only GLPI inventory adapter; no credential handling here."""

class ZabbixAdapter(InventoryAdapter):
    """Placeholder: read-only telemetry adapter; no remote command capability."""

class WazuhAdapter(InventoryAdapter):
    """Placeholder: read-only posture/finding adapter; active response excluded."""

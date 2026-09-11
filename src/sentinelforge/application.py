"""Application operations shared by the CLI and local HTTP API."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .reporting import analyze_file
from .storage import AnalysisRepository, Database

_ALLOWED_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_ALLOWED_SOURCES = frozenset({"linux_auth", "windows_security", "network_connection"})


def analyze_request(path: str, source: str = "linux_auth", severity: Optional[str] = None,
                    incident_id: Optional[str] = None, database: Optional[str] = None) -> Dict[str, Any]:
    """Run the existing analysis orchestration after validating API inputs."""
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if source not in _ALLOWED_SOURCES:
        raise ValueError("unsupported source")
    if severity is not None and severity not in _ALLOWED_SEVERITIES:
        raise ValueError("invalid severity")
    if incident_id is not None and not isinstance(incident_id, str):
        raise ValueError("incident_id must be a string")
    return analyze_file(path, severity, incident_id, source, database)


def list_resource(database: Optional[str], resource: str, severity: Optional[str] = None,
                  limit: Optional[int] = None) -> list[Dict[str, Any]]:
    """Read persisted resource snapshots; an unconfigured store is empty."""
    if severity is not None and severity not in _ALLOWED_SEVERITIES:
        raise ValueError("invalid severity")
    if limit is not None and (limit < 1 or limit > 1000):
        raise ValueError("limit must be between 1 and 1000")
    if not database:
        return []
    with Database(database) as db:
        repository = AnalysisRepository(db)
        values = repository.list_payloads(resource, severity)
    return values[:limit] if limit is not None else values


def get_resource(database: Optional[str], resource: str, entity_id: str) -> Optional[Dict[str, Any]]:
    """Read one persisted resource snapshot."""
    if not database:
        return None
    with Database(database) as db:
        return AnalysisRepository(db).get_payload(resource, entity_id)


def list_runs(database: Optional[str], limit: Optional[int] = None) -> list[Dict[str, Any]]:
    return list_resource(database, "runs", limit=limit)

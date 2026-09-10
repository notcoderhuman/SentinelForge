"""Immutable, provenance-preserving investigation evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict

from .events import SecurityEvent

ALLOWED_EVIDENCE_TYPES = frozenset({"event", "alert_context", "incident_context"})


@dataclass(frozen=True)
class Evidence:
    """A traceable reference to one normalized event used in an investigation."""

    evidence_id: str
    event: SecurityEvent
    evidence_type: str
    source: str
    timestamp: datetime
    relevance: str
    provenance: str

    def __post_init__(self) -> None:
        if not self.evidence_id or not self.relevance or not self.provenance:
            raise ValueError("evidence_id, relevance, and provenance are required")
        if self.evidence_type not in ALLOWED_EVIDENCE_TYPES:
            raise ValueError(f"unsupported evidence type: {self.evidence_type}")
        if not self.source:
            raise ValueError("evidence source is required")
        if self.timestamp.tzinfo is None:
            raise ValueError("evidence timestamp must be timezone-aware")
        if self.timestamp != self.event.timestamp:
            raise ValueError("evidence timestamp must match the event timestamp")
        if self.source != self.event.source:
            raise ValueError("evidence source must match the event source")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize evidence while retaining its normalized event provenance."""
        return {
            "evidence_id": self.evidence_id,
            "event": self.event.to_dict(),
            "evidence_type": self.evidence_type,
            "source": self.source,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "relevance": self.relevance,
            "provenance": self.provenance,
        }


def create_evidence(event: SecurityEvent, evidence_type: str, relevance: str,
                    provenance: str) -> Evidence:
    """Create a deterministic evidence record from an actual normalized event."""
    identity = json.dumps({
        "event": event.to_dict(),
        "evidence_type": evidence_type,
        "relevance": relevance,
        "provenance": provenance,
    }, sort_keys=True, separators=(",", ":"))
    evidence_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return Evidence(evidence_id, event, evidence_type, event.source,
                    event.timestamp, relevance, provenance)

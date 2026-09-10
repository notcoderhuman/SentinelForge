"""Deterministic findings for supported multi-event security sequences."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Tuple


@dataclass(frozen=True)
class CorrelationFinding:
    """A bounded, evidence-linked relationship between detection alerts."""

    correlation_id: str
    name: str
    description: str
    related_alert_ids: Tuple[str, ...]
    evidence_ids: Tuple[str, ...]
    start_time: datetime
    end_time: datetime
    rationale: str

    def __post_init__(self) -> None:
        if not self.correlation_id or not self.name or not self.description:
            raise ValueError("correlation identity and description are required")
        if not self.related_alert_ids or not self.evidence_ids:
            raise ValueError("correlation must reference alerts and evidence")
        if self.start_time.tzinfo is None or self.end_time.tzinfo is None:
            raise ValueError("correlation timestamps must be timezone-aware")
        if self.end_time < self.start_time:
            raise ValueError("correlation end_time cannot precede start_time")
        if not self.rationale:
            raise ValueError("correlation rationale is required")

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly correlation representation."""
        return {
            "correlation_id": self.correlation_id,
            "name": self.name,
            "description": self.description,
            "related_alert_ids": list(self.related_alert_ids),
            "evidence_ids": list(self.evidence_ids),
            "start_time": self.start_time.isoformat().replace("+00:00", "Z"),
            "end_time": self.end_time.isoformat().replace("+00:00", "Z"),
            "rationale": self.rationale,
        }


def event_evidence_id(raw: str) -> str:
    """Return a stable reference for an actual normalized event's raw evidence."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def create_finding(name: str, description: str, alerts: Tuple[str, ...],
                   evidence: Tuple[str, ...], start_time: datetime,
                   end_time: datetime, rationale: str) -> CorrelationFinding:
    """Create a deterministic finding from explicit alert and evidence references."""
    identity = json.dumps({"name": name, "alerts": alerts, "evidence": evidence,
                           "start": start_time.isoformat(), "end": end_time.isoformat()},
                          sort_keys=True, separators=(",", ":"))
    correlation_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return CorrelationFinding(correlation_id, name, description, alerts, evidence,
                              start_time, end_time, rationale)

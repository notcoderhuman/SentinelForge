"""Structured alert objects and deterministic identifiers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List

from .events import SecurityEvent

ALLOWED_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


@dataclass(frozen=True)
class Alert:
    """A reproducible detection result with source evidence references."""

    alert_id: str
    rule_id: str
    severity: str
    timestamp: datetime
    title: str
    description: str
    evidence: List[SecurityEvent]
    source: str = "linux-auth"

    def __post_init__(self) -> None:
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity}")
        if not self.evidence:
            raise ValueError("an alert must contain evidence")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the alert without losing evidence fields."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "title": self.title,
            "description": self.description,
            "evidence": [event.to_dict() for event in self.evidence],
            "source": self.source,
        }


def create_alert(rule_id: str, severity: str, title: str, description: str,
                 evidence: List[SecurityEvent]) -> Alert:
    """Create an alert with an ID derived from stable rule and evidence data."""
    evidence_key = [event.to_dict() for event in evidence]
    identity = json.dumps({"rule_id": rule_id, "evidence": evidence_key},
                          sort_keys=True, separators=(",", ":"))
    alert_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    timestamp = max(event.timestamp for event in evidence)
    return Alert(alert_id, rule_id, severity, timestamp, title, description, evidence)

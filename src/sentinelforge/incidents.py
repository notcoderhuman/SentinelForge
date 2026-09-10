"""Incident model and explicit lifecycle transitions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, FrozenSet, Iterable, Tuple

from .alerts import Alert, ALLOWED_SEVERITIES
from .events import SecurityEvent

ALLOWED_STATUSES = frozenset({"open", "investigating", "resolved", "closed"})
_ALLOWED_TRANSITIONS = {
    "open": frozenset({"investigating", "resolved"}),
    "investigating": frozenset({"resolved"}),
    "resolved": frozenset({"closed"}),
    "closed": frozenset(),
}
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True)
class Incident:
    """An immutable correlated security situation derived from alerts."""

    incident_id: str
    title: str
    description: str
    severity: str
    status: str
    created_at: datetime
    updated_at: datetime
    related_alert_ids: Tuple[str, ...]
    affected_users: Tuple[str, ...]
    affected_entities: Tuple[str, ...]
    evidence: Tuple[SecurityEvent, ...]

    def __post_init__(self) -> None:
        if not self.incident_id or not self.title or not self.description:
            raise ValueError("incident_id, title, and description are required")
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity}")
        if self.status not in ALLOWED_STATUSES:
            raise ValueError(f"unsupported incident status: {self.status}")
        if self.created_at.tzinfo is None or self.updated_at.tzinfo is None:
            raise ValueError("incident timestamps must be timezone-aware")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if not self.related_alert_ids:
            raise ValueError("an incident must reference at least one alert")
        if not self.evidence:
            raise ValueError("an incident must contain evidence")

    def transition_to(self, new_status: str, updated_at: datetime | None = None) -> "Incident":
        """Return a new incident after a valid forward lifecycle transition."""
        if new_status not in ALLOWED_STATUSES:
            raise ValueError(f"unsupported incident status: {new_status}")
        if new_status not in _ALLOWED_TRANSITIONS[self.status]:
            raise ValueError(f"invalid incident transition: {self.status} -> {new_status}")
        transition_time = updated_at or self.updated_at
        if transition_time.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")
        if transition_time < self.updated_at:
            raise ValueError("transition time cannot precede updated_at")
        return Incident(
            incident_id=self.incident_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            status=new_status,
            created_at=self.created_at,
            updated_at=transition_time,
            related_alert_ids=self.related_alert_ids,
            affected_users=self.affected_users,
            affected_entities=self.affected_entities,
            evidence=self.evidence,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly representation with preserved evidence."""
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": self.updated_at.isoformat().replace("+00:00", "Z"),
            "related_alert_ids": list(self.related_alert_ids),
            "affected_users": list(self.affected_users),
            "affected_entities": list(self.affected_entities),
            "evidence": [event.to_dict() for event in self.evidence],
        }


def _stable_values(values: Iterable[str]) -> Tuple[str, ...]:
    return tuple(sorted(set(value for value in values if value)))


def create_incident(alerts: Iterable[Alert], context: FrozenSet[str]) -> Incident:
    """Build one deterministic open incident from a correlated alert group."""
    ordered_alerts = tuple(sorted(alerts, key=lambda alert: alert.alert_id))
    if not ordered_alerts:
        raise ValueError("cannot create an incident without alerts")
    identity = json.dumps({"alerts": [alert.alert_id for alert in ordered_alerts],
                           "context": sorted(context)}, separators=(",", ":"))
    import hashlib
    incident_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    evidence = tuple(event for alert in ordered_alerts for event in alert.evidence)
    unique_evidence = tuple(dict((event.raw, event) for event in evidence).values())
    users = _stable_values(event.username for event in unique_evidence if event.username)
    entities = _stable_values(
        f"source_ip:{event.source_ip}" for event in unique_evidence if event.source_ip
    )
    severity = max((alert.severity for alert in ordered_alerts), key=_SEVERITY_ORDER.get)
    created_at = min(alert.timestamp for alert in ordered_alerts)
    updated_at = max(alert.timestamp for alert in ordered_alerts)
    return Incident(
        incident_id=incident_id,
        title="Correlated security activity observed.",
        description="Related detection alerts share observable security context; this does not establish compromise.",
        severity=severity,
        status="open",
        created_at=created_at,
        updated_at=updated_at,
        related_alert_ids=tuple(alert.alert_id for alert in ordered_alerts),
        affected_users=users,
        affected_entities=entities,
        evidence=unique_evidence,
    )

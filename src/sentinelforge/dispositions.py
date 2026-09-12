"""Append-only analyst interpretations of persisted alerts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

ALLOWED_DISPOSITIONS = frozenset({
    "true_positive",
    "benign",
    "duplicate",
    "inconclusive",
})
MAX_REASON_BYTES = 16_384


@dataclass(frozen=True)
class AlertDisposition:
    """One immutable, server-created interpretation of an alert."""

    disposition_id: str
    alert_id: str
    incident_id: Optional[str]
    actor_user_id: str
    created_at: datetime
    disposition: str
    reason: str
    rule_id: str
    rule_fingerprint: Optional[str] = None
    engine_configuration_fingerprint: Optional[str] = None
    run_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.disposition_id or not self.alert_id or not self.actor_user_id or not self.rule_id:
            raise ValueError("disposition identity fields are required")
        if self.created_at.tzinfo is None:
            raise ValueError("disposition created_at must be timezone-aware")
        if self.disposition not in ALLOWED_DISPOSITIONS:
            raise ValueError(f"unsupported disposition: {self.disposition}")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("disposition reason must be non-empty")
        if len(self.reason.encode("utf-8")) > MAX_REASON_BYTES:
            raise ValueError("disposition reason exceeds 16384 UTF-8 bytes")
        if self.idempotency_key is not None and not self.idempotency_key:
            raise ValueError("idempotency_key must be non-empty when provided")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation without changing the record."""
        return {
            "disposition_id": self.disposition_id,
            "alert_id": self.alert_id,
            "incident_id": self.incident_id,
            "actor_user_id": self.actor_user_id,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "disposition": self.disposition,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "rule_fingerprint": self.rule_fingerprint,
            "engine_configuration_fingerprint": self.engine_configuration_fingerprint,
            "run_id": self.run_id,
            "idempotency_key": self.idempotency_key,
        }

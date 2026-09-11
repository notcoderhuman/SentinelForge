"""Structured audit record model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional


@dataclass(frozen=True)
class AuditRecord:
    audit_id: str
    timestamp: datetime
    user_id: Optional[str]
    username: Optional[str]
    action: str
    resource: str
    resource_id: Optional[str]
    outcome: str
    source: Optional[str]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"audit_id": self.audit_id, "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
                "user_id": self.user_id, "username": self.username, "action": self.action,
                "resource": self.resource, "resource_id": self.resource_id, "outcome": self.outcome,
                "source": self.source, "metadata": self.metadata}

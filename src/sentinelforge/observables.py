"""Immutable observable values extracted from normalized security events."""

from __future__ import annotations

import hashlib
import json
import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict

ALLOWED_OBSERVABLE_TYPES = frozenset({"ipv4", "ipv6", "domain", "url", "username"})


@dataclass(frozen=True)
class Observable:
    """A deterministic, provenance-preserving observable."""

    observable_id: str
    observable_type: str
    value: str
    source: str
    timestamp: datetime
    provenance: str
    confidence: int

    def __post_init__(self) -> None:
        if not self.observable_id or not self.value or not self.source or not self.provenance:
            raise ValueError("observable identity, value, source, and provenance are required")
        if self.observable_type not in ALLOWED_OBSERVABLE_TYPES:
            raise ValueError(f"unsupported observable type: {self.observable_type}")
        if self.timestamp.tzinfo is None:
            raise ValueError("observable timestamp must be timezone-aware")
        if not 0 <= self.confidence <= 100:
            raise ValueError("observable confidence must be between 0 and 100")
        if self.observable_type in {"ipv4", "ipv6"}:
            parsed = ipaddress.ip_address(self.value)
            if (self.observable_type == "ipv4" and parsed.version != 4) or (self.observable_type == "ipv6" and parsed.version != 6):
                raise ValueError("observable IP type does not match value")

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly observable representation."""
        return {
            "observable_id": self.observable_id,
            "observable_type": self.observable_type,
            "value": self.value,
            "source": self.source,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "provenance": self.provenance,
            "confidence": self.confidence,
        }


def create_observable(observable_type: str, value: str, source: str,
                      timestamp: datetime, provenance: str,
                      confidence: int = 100) -> Observable:
    """Create an observable with an ID derived from its stable provenance."""
    identity = json.dumps({"type": observable_type, "value": value,
                           "source": source, "timestamp": timestamp.isoformat(),
                           "provenance": provenance}, sort_keys=True,
                          separators=(",", ":"))
    observable_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return Observable(observable_id, observable_type, value, source, timestamp,
                      provenance, confidence)

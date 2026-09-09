"""Normalized security event model."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class SecurityEvent:
    """A normalized event while retaining the original source evidence.

    ``timestamp`` must be timezone-aware UTC. Optional fields remain ``None``
    when the source did not provide them; the model never invents values.
    """

    timestamp: datetime
    source: str
    event_type: str
    hostname: Optional[str]
    process: Optional[str]
    username: Optional[str]
    source_ip: Optional[str]
    message: str
    raw: str

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        if not self.source or not self.event_type or not self.message or not self.raw:
            raise ValueError("source, event_type, message, and raw are required")

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly dictionary representation."""
        values = asdict(self)
        values["timestamp"] = self.timestamp.isoformat().replace("+00:00", "Z")
        return values

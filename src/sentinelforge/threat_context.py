"""Explicit local threat-context records for observables."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

ALLOWED_CONTEXT_TYPES = frozenset({"known_malicious", "suspicious", "benign", "internal", "unknown"})


@dataclass(frozen=True)
class ThreatContext:
    """Caller-supplied local metadata, not an automatic reputation verdict."""

    observable_type: str
    value: str
    context_type: str
    label: str
    confidence: int
    rationale: str
    source: str

    def __post_init__(self) -> None:
        if not self.observable_type or not self.value or not self.label or not self.rationale or not self.source:
            raise ValueError("threat context fields are required")
        if self.context_type not in ALLOWED_CONTEXT_TYPES:
            raise ValueError(f"unsupported context type: {self.context_type}")
        if not 0 <= self.confidence <= 100:
            raise ValueError("context confidence must be between 0 and 100")

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly context representation."""
        return {
            "observable_type": self.observable_type,
            "value": self.value,
            "context_type": self.context_type,
            "label": self.label,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "source": self.source,
        }

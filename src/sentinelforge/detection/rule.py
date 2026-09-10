"""Immutable metadata definitions for deterministic detection rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

from ..alerts import ALLOWED_SEVERITIES


@dataclass(frozen=True)
class RuleDefinition:
    """Descriptive metadata for a Python detection function."""

    rule_id: str
    name: str
    description: str
    severity: str
    detection_window_seconds: int
    enabled: bool
    evidence_requirements: Tuple[str, ...]
    attack_mapping_reference: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.rule_id or not self.name or not self.description:
            raise ValueError("rule_id, name, and description are required")
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"unsupported rule severity: {self.severity}")
        if self.detection_window_seconds <= 0:
            raise ValueError("detection_window_seconds must be positive")
        if not self.evidence_requirements or any(not item for item in self.evidence_requirements):
            raise ValueError("evidence_requirements must contain non-empty descriptions")

    def to_dict(self) -> Dict[str, Any]:
        """Return JSON-friendly rule metadata."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "detection_window_seconds": self.detection_window_seconds,
            "enabled": self.enabled,
            "evidence_requirements": list(self.evidence_requirements),
            "attack_mapping_reference": list(self.attack_mapping_reference),
        }

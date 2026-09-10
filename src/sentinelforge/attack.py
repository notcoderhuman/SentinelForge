"""Explicit, offline MITRE ATT&CK technique mappings."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Tuple

TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@dataclass(frozen=True)
class TechniqueMapping:
    """A deterministic, evidence-limited mapping from a detection rule."""

    technique_id: str
    technique_name: str
    tactic: str
    rationale: str
    source_rule_id: str

    def __post_init__(self) -> None:
        if not TECHNIQUE_ID_PATTERN.fullmatch(self.technique_id):
            raise ValueError(f"invalid ATT&CK technique ID: {self.technique_id}")
        if not self.technique_name or not self.tactic or not self.rationale:
            raise ValueError("technique name, tactic, and rationale are required")
        if not self.source_rule_id:
            raise ValueError("source_rule_id is required")

    def to_dict(self) -> Dict[str, str]:
        """Return a JSON-friendly mapping representation."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "rationale": self.rationale,
            "source_rule_id": self.source_rule_id,
        }


# This is intentionally a small, reviewed allowlist rather than runtime inference.
_RULE_MAPPINGS: Tuple[TechniqueMapping, ...] = (
    TechniqueMapping(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        rationale="Repeated failed SSH authentication from one source IP supports a contextual brute-force mapping.",
        source_rule_id="SSH_BRUTE_FORCE",
    ),
)


def mappings_for_rule(rule_id: str) -> Tuple[TechniqueMapping, ...]:
    """Return explicit mappings for a rule, or an empty tuple when unmapped."""
    return tuple(mapping for mapping in _RULE_MAPPINGS if mapping.source_rule_id == rule_id)


def mappings_for_rules(rule_ids: Tuple[str, ...]) -> Tuple[TechniqueMapping, ...]:
    """Return unique mappings in deterministic technique and rule order."""
    mappings = {
        (mapping.technique_id, mapping.source_rule_id): mapping
        for rule_id in rule_ids
        for mapping in mappings_for_rule(rule_id)
    }
    return tuple(sorted(mappings.values(), key=lambda mapping: (mapping.technique_id, mapping.source_rule_id)))

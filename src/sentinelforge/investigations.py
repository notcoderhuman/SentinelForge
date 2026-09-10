"""Investigation model and append-only analyst notes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Tuple

from .attack import TechniqueMapping, mappings_for_rules
from .correlation import CorrelationFinding
from .evidence import Evidence
from .risk import RiskAssessment

ALLOWED_STATUSES = frozenset({"active", "completed"})


@dataclass(frozen=True)
class AnalystNote:
    """A caller-supplied note that is stored as inert text."""

    note_id: str
    timestamp: datetime
    author: str
    content: str

    def __post_init__(self) -> None:
        if not self.note_id or not self.author or not self.content:
            raise ValueError("note_id, author, and content are required")
        if self.timestamp.tzinfo is None:
            raise ValueError("note timestamp must be timezone-aware")

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly note representation."""
        return {
            "note_id": self.note_id,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "author": self.author,
            "content": self.content,
        }


@dataclass(frozen=True)
class TimelineEntry:
    """A chronological view of one evidence item."""

    timestamp: datetime
    evidence_id: str
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly timeline representation."""
        return {
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "evidence_id": self.evidence_id,
            "summary": self.summary,
        }


@dataclass(frozen=True)
class Investigation:
    """Immutable analytical context for exactly one incident."""

    investigation_id: str
    incident_id: str
    status: str
    created_at: datetime
    updated_at: datetime
    evidence: Tuple[Evidence, ...]
    timeline: Tuple[TimelineEntry, ...]
    analyst_notes: Tuple[AnalystNote, ...]
    source_rule_ids: Tuple[str, ...] = ()
    correlations: Tuple[CorrelationFinding, ...] = ()
    risk_assessment: RiskAssessment | None = None

    @property
    def attack_mappings(self) -> Tuple[TechniqueMapping, ...]:
        """Derive ATT&CK mappings from the linked incident's rule IDs."""
        return mappings_for_rules(self.source_rule_ids)

    def __post_init__(self) -> None:
        if not self.investigation_id or not self.incident_id:
            raise ValueError("investigation_id and incident_id are required")
        if self.status not in ALLOWED_STATUSES:
            raise ValueError(f"unsupported investigation status: {self.status}")
        if self.created_at.tzinfo is None or self.updated_at.tzinfo is None:
            raise ValueError("investigation timestamps must be timezone-aware")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if not self.evidence:
            raise ValueError("an investigation must contain evidence")
        evidence_ids = {item.evidence_id for item in self.evidence}
        if any(entry.evidence_id not in evidence_ids for entry in self.timeline):
            raise ValueError("timeline contains an unknown evidence reference")
        if len(evidence_ids) != len(self.evidence):
            raise ValueError("investigation evidence must not contain duplicates")
        if tuple(sorted(self.timeline, key=lambda entry: (entry.timestamp, entry.evidence_id))) != self.timeline:
            raise ValueError("timeline must be chronologically ordered")
        if tuple(sorted(self.analyst_notes, key=lambda note: (note.timestamp, note.note_id))) != self.analyst_notes:
            raise ValueError("analyst notes must be deterministically ordered")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the investigation without discarding provenance."""
        return {
            "investigation_id": self.investigation_id,
            "incident_id": self.incident_id,
            "status": self.status,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": self.updated_at.isoformat().replace("+00:00", "Z"),
            "evidence": [item.to_dict() for item in self.evidence],
            "timeline": [entry.to_dict() for entry in self.timeline],
            "analyst_notes": [note.to_dict() for note in self.analyst_notes],
            "attack_mappings": [mapping.to_dict() for mapping in self.attack_mappings],
            "correlations": [finding.to_dict() for finding in self.correlations],
            "risk_assessment": self.risk_assessment.to_dict() if self.risk_assessment else None,
        }

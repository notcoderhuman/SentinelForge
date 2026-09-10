"""Deterministic creation of investigations from incidents."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Tuple

from .evidence import Evidence, create_evidence
from .incidents import Incident
from .investigations import AnalystNote, Investigation, TimelineEntry


def _build_evidence(incident: Incident) -> Tuple[Evidence, ...]:
    """Convert incident events into unique, provenance-preserving evidence."""
    evidence_by_event = {}
    for event in incident.evidence:
        evidence = create_evidence(
            event=event,
            evidence_type="event",
            relevance="Event was preserved as incident evidence.",
            provenance=f"incident:{incident.incident_id}",
        )
        evidence_by_event[evidence.evidence_id] = evidence
    return tuple(sorted(evidence_by_event.values(), key=lambda item: (item.timestamp, item.evidence_id)))


def _build_timeline(evidence: Tuple[Evidence, ...]) -> Tuple[TimelineEntry, ...]:
    """Create chronological entries directly from evidence timestamps."""
    entries = [
        TimelineEntry(item.timestamp, item.evidence_id, item.event.message)
        for item in evidence
    ]
    return tuple(sorted(entries, key=lambda entry: (entry.timestamp, entry.evidence_id)))


def create_investigation(incident: Incident) -> Investigation:
    """Create one deterministic active investigation for an incident."""
    evidence = _build_evidence(incident)
    identity = json.dumps({
        "incident_id": incident.incident_id,
        "evidence_ids": [item.evidence_id for item in evidence],
    }, sort_keys=True, separators=(",", ":"))
    investigation_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return Investigation(
        investigation_id=investigation_id,
        incident_id=incident.incident_id,
        status="active",
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        evidence=evidence,
        timeline=_build_timeline(evidence),
        analyst_notes=(),
        source_rule_ids=incident.source_rule_ids,
        correlations=incident.correlations,
        risk_assessment=incident.risk_assessment,
    )


def create_note(note_id: str, timestamp: datetime, author: str, content: str) -> AnalystNote:
    """Create an inert analyst note supplied by the caller."""
    return AnalystNote(note_id, timestamp, author, content)

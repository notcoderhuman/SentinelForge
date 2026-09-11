"""Deterministic Investigation Package — canonical boundary between detection and analysis.

An Investigation Package is a self-contained, immutable, machine-readable
structure that captures one incident's worth of alerts, evidence, provenance,
diagnostics, and chronology.  It is the trusted output of the SentinelForge
detection layer and the sole input to any future analyst or LLM consumer.

Key design principles
---------------------

* **Deterministic identity** — The same logical input always produces the same
  ``package_id``, regardless of input ordering, runtime metadata, or generation
  timestamp.
* **Complete evidence linkage** — Every alert references concrete package
  evidence items.  Legacy ``null`` evidence IDs are replaced with stable
  deterministic identifiers derived from canonical event content.
* **Explicit provenance** — Every evidence item records its telemetry source and
  detection provenance.  Multi-source alerts expose *all* contributing sources,
  not just the first one.
* **Diagnostics/coverage** — Ingestion failures and parser rejections are
  preserved so that "no alert" does not silently become "no activity."
* **No security claims** — The package is a deterministic representation of
  available evidence.  It does not establish compromise, malware, attacker
  attribution, or intent.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .alerts import Alert
from .events import SecurityEvent
from .incidents import Incident

# ---------------------------------------------------------------------------
# Package version — bump when the schema changes.
# ---------------------------------------------------------------------------
PACKAGE_VERSION = "1"

# ---------------------------------------------------------------------------
# Evidence identity
# ---------------------------------------------------------------------------

# Fields that, when present, contribute to a deterministic evidence hash for
# events that lack a native stable ``event_id``.  The same fields — in the
# same order — are used every time, ensuring ordering- and position-independence.
_CANONICAL_EVIDENCE_FIELDS = (
    "timestamp", "event_type", "source", "hostname", "username", "message", "raw",
)


def _canonicalize_event(event: SecurityEvent) -> Dict[str, Any]:
    """Return a dict containing only the fields that define canonical identity.

    All values are JSON-serializable (timestamps are converted to ISO strings).
    """
    d: Dict[str, Any] = {}
    for k in _CANONICAL_EVIDENCE_FIELDS:
        val = getattr(event, k, None)
        if k == "timestamp" and isinstance(val, datetime):
            val = val.isoformat().replace("+00:00", "Z")
        d[k] = val
    return d


def _deterministic_event_id(event: SecurityEvent) -> str:
    """Return a stable evidence identifier for one event.

    * If the event already carries a non-empty ``event_id``, it is preserved
      unchanged.
    * Otherwise, a 16-hex-char SHA-256 digest of the canonicalized event
      content is returned.  The digest is independent of array position,
      runtime IDs, and input ordering.
    """
    if event.event_id:
        return event.event_id
    payload = json.dumps(_canonicalize_event(event), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Provenance helpers
# ---------------------------------------------------------------------------


def _evidence_sources(event: SecurityEvent) -> List[str]:
    """Return all telemetry sources for an event (always one source)."""
    return [event.source]


def _alert_contributing_sources(alert: Alert) -> Tuple[str, ...]:
    """Return *all* telemetry sources represented in an alert's evidence.

    Unlike the legacy ``alert.source`` field (which may report only the first
    source for cross-source alerts), this returns every distinct source
    present across all evidence events, sorted deterministically.
    """
    sources: set[str] = set()
    for ev in alert.evidence:
        if ev.source:
            sources.add(ev.source)
    return tuple(sorted(sources))


def _alert_detection_source(alert: Alert) -> str:
    """Return the detection rule's registered source family.

    This is the source of the *rule*, not the telemetry.  It is preserved
    from the legacy ``alert.source`` field and is distinct from the
    telemetry-provenance sources returned by ``_alert_contributing_sources``.
    """
    return alert.source or "unknown"


# ---------------------------------------------------------------------------
# Package data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PackageEvidence:
    """One evidence item in an Investigation Package.

    ``original_event_id`` is ``None`` when the source event had no stable ID.
    ``evidence_id`` is always present and stable.
    """
    evidence_id: str
    original_event_id: str | None
    source: str
    event_type: str
    hostname: str | None
    username: str | None
    timestamp: str
    raw: str
    normalized: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "event_type": self.event_type,
            "hostname": self.hostname,
            "username": self.username,
            "timestamp": self.timestamp,
        }
        if self.original_event_id is not None:
            d["original_event_id"] = self.original_event_id
        d["raw"] = self.raw
        d["normalized"] = self.normalized
        return d


@dataclass(frozen=True)
class PackageAlertEvidenceRef:
    """A concrete reference from a package alert to a package evidence item."""
    evidence_id: str

    def to_dict(self) -> Dict[str, str]:
        return {"evidence_id": self.evidence_id}


@dataclass(frozen=True)
class PackageAlert:
    """One alert inside an Investigation Package.

    ``evidence_refs`` is always non-empty.  Every reference is resolvable to a
    ``PackageEvidence`` item within the same package.  ``contributing_sources``
    lists *all* telemetry sources present in the alert's evidence, fixing the
    legacy single-source bug for cross-source alerts.
    """
    alert_id: str
    rule_id: str
    severity: str
    timestamp: str
    title: str
    description: str
    detection_source: str
    contributing_sources: Tuple[str, ...]
    evidence_refs: Tuple[PackageAlertEvidenceRef, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "title": self.title,
            "description": self.description,
            "detection_source": self.detection_source,
            "contributing_sources": list(self.contributing_sources),
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
        }


@dataclass(frozen=True)
class PackageDiagnostic:
    """One ingestion diagnostic relevant to the investigation.

    ``telemetry_was_accepted`` distinguishes records that were received and
    parsed (even if they produced no alert) from records that were rejected.
    When the raw input is available it is preserved.
    """
    type: str
    source: str | None
    line_number: int | None
    reason: str
    raw: str | None
    telemetry_was_accepted: bool

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "type": self.type,
            "reason": self.reason,
            "telemetry_was_accepted": self.telemetry_was_accepted,
        }
        if self.source is not None:
            d["source"] = self.source
        if self.line_number is not None:
            d["line_number"] = self.line_number
        if self.raw is not None:
            d["raw"] = self.raw
        return d


@dataclass(frozen=True)
class PackageChronologyEntry:
    """One entry in the deterministic chronological sequence."""
    kind: str  # "evidence" or "alert"
    identifier: str
    timestamp: str
    summary: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "kind": self.kind,
            "identifier": self.identifier,
            "timestamp": self.timestamp,
            "summary": self.summary,
        }


@dataclass(frozen=True)
class CoverageSummary:
    """Aggregate metadata describing the package's telemetry coverage.

    No single "quality score" is computed; the consumer may interpret the
    explicit counts.
    """
    total_evidence_items: int
    total_alerts: int
    total_diagnostics: int
    distinct_telemetry_sources: Tuple[str, ...]
    evidence_with_original_ids: int
    evidence_with_generated_ids: int
    alerts_with_complete_linkage: int
    alerts_with_incomplete_provenance: int  # alerts whose source list may be incomplete

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_evidence_items": self.total_evidence_items,
            "total_alerts": self.total_alerts,
            "total_diagnostics": self.total_diagnostics,
            "distinct_telemetry_sources": list(self.distinct_telemetry_sources),
            "evidence_with_original_ids": self.evidence_with_original_ids,
            "evidence_with_generated_ids": self.evidence_with_generated_ids,
            "alerts_with_complete_linkage": self.alerts_with_complete_linkage,
            "alerts_with_incomplete_provenance": self.alerts_with_incomplete_provenance,
        }


# ---------------------------------------------------------------------------
# Main package
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InvestigationPackage:
    """Complete canonical investigation package.

    ``generated_at`` is observational metadata for human readers.  It is
    explicitly excluded from the ``package_id`` hash input.
    """
    package_version: str
    package_id: str
    generated_at: str
    incident: Dict[str, Any] | None
    alerts: Tuple[PackageAlert, ...]
    evidence: Tuple[PackageEvidence, ...]
    diagnostics: Tuple[PackageDiagnostic, ...]
    chronology: Tuple[PackageChronologyEntry, ...]
    coverage: CoverageSummary

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Deterministic JSON-friendly representation.

        All list-valued fields are sorted by a stable key when their natural
        ordering is deterministic.  ``generated_at`` is included in the
        serialized output (it is observational metadata for consumers) but it
        does NOT affect ``package_id``.
        """
        return {
            "package_version": self.package_version,
            "package_id": self.package_id,
            "generated_at": self.generated_at,
            "incident": self.incident,
            "alerts": [a.to_dict() for a in self.alerts],
            "evidence": [e.to_dict() for e in self.evidence],
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "chronology": [c.to_dict() for c in self.chronology],
            "coverage": self.coverage.to_dict(),
        }


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _format_ts(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.isoformat().replace("+00:00", "Z")


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _compute_package_id(incident_dict: Dict[str, Any] | None,
                        alerts: Sequence[PackageAlert],
                        evidence: Sequence[PackageEvidence],
                        diagnostics: Sequence[PackageDiagnostic],
                        chronology: Sequence[PackageChronologyEntry]) -> str:
    """Compute a deterministic package ID from stable content only.

    Inputs that change the logical content (alert content, evidence content,
    diagnostics, chronology) change the ID.  ``generated_at`` does NOT
    contribute.
    """
    canonical: Dict[str, Any] = {
        "package_version": PACKAGE_VERSION,
        "incident": incident_dict,
        "alerts": [a.to_dict() for a in alerts],
        "evidence": [e.to_dict() for e in evidence],
        "diagnostics": [d.to_dict() for d in diagnostics],
        "chronology": [c.to_dict() for c in chronology],
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Public construction entry point
# ---------------------------------------------------------------------------


def build_package(alerts: Sequence[Alert],
                  diagnostics: Sequence[Dict[str, Any]] = (),
                  incident: Incident | None = None,
                  generated_at: str | None = None) -> InvestigationPackage:
    """Construct an ``InvestigationPackage`` from detection results.

    Parameters
    ----------
    alerts:
        The alerts produced by the ``DetectionEngine``.
    diagnostics:
        Ingestion diagnostics (as returned by ``ingest_file`` or ``replay_file``).
    incident:
        An optional ``Incident`` from the incident engine.  When provided, the
        package embeds the incident's relevant metadata.
    generated_at:
        Optional human-readable generation timestamp.  If omitted, UTC now is
        used.  This value does NOT affect ``package_id``.

    Returns
    -------
    InvestigationPackage
        A fully constructed package with deterministic identity.
    """
    gen = generated_at if generated_at is not None else _now_utc()

    # --- Build evidence --------------------------------------------------
    evidence_items: List[PackageEvidence] = []
    seen: Dict[str, PackageEvidence] = {}  # deduplicate by evidence_id
    for alert in alerts:
        for event in alert.evidence:
            eid = _deterministic_event_id(event)
            if eid in seen:
                continue
            normalized = event.to_dict()
            pe = PackageEvidence(
                evidence_id=eid,
                original_event_id=event.event_id,
                source=event.source,
                event_type=event.event_type,
                hostname=event.hostname,
                username=event.username,
                timestamp=_format_ts(event.timestamp),
                raw=event.raw,
                normalized=normalized,
            )
            seen[eid] = pe
            evidence_items.append(pe)

    # Sort evidence deterministically.
    evidence_items.sort(key=lambda e: (e.timestamp, e.evidence_id))

    evidence_lookup: Dict[str, PackageEvidence] = {e.evidence_id: e for e in evidence_items}

    # --- Build alerts ----------------------------------------------------
    package_alerts: List[PackageAlert] = []
    incomplete_provenance = 0
    for alert in alerts:
        refs: List[PackageAlertEvidenceRef] = []
        for event in alert.evidence:
            eid = _deterministic_event_id(event)
            if eid in evidence_lookup:
                refs.append(PackageAlertEvidenceRef(evidence_id=eid))
        contributing = _alert_contributing_sources(alert)
        # Flag if the legacy source field is incomplete (cross-source case).
        if len(contributing) > 1 and alert.source and alert.source != "unknown":
            incomplete_provenance += 1
        pa = PackageAlert(
            alert_id=alert.alert_id,
            rule_id=alert.rule_id,
            severity=alert.severity,
            timestamp=_format_ts(alert.timestamp),
            title=alert.title,
            description=alert.description,
            detection_source=_alert_detection_source(alert),
            contributing_sources=contributing,
            evidence_refs=tuple(refs),
        )
        package_alerts.append(pa)

    # Sort alerts deterministically.
    package_alerts.sort(key=lambda a: (a.timestamp, a.alert_id))

    # --- Build diagnostics -----------------------------------------------
    pkg_diagnostics: List[PackageDiagnostic] = []
    for diag in diagnostics:
        source = diag.get("source")
        line = diag.get("line_number")
        reason = diag.get("reason", "")
        raw = diag.get("raw")
        # Ingested diagnostics are always "rejected telemetry" — the parser
        # could not accept the line.
        pkg_diagnostics.append(PackageDiagnostic(
            type="parser_rejection",
            source=source,
            line_number=line,
            reason=reason,
            raw=raw,
            telemetry_was_accepted=False,
        ))
    pkg_diagnostics.sort(key=lambda d: (d.reason, d.raw or ""))

    # --- Build chronology ------------------------------------------------
    chrono: List[PackageChronologyEntry] = []
    for pe in evidence_items:
        chrono.append(PackageChronologyEntry(
            kind="evidence",
            identifier=pe.evidence_id,
            timestamp=pe.timestamp,
            summary=pe.normalized.get("message", pe.event_type),
        ))
    for pa in package_alerts:
        chrono.append(PackageChronologyEntry(
            kind="alert",
            identifier=pa.alert_id,
            timestamp=pa.timestamp,
            summary=pa.description,
        ))
    # Deterministic sort: timestamp ascending, then kind (evidence before alert
    # for same timestamp), then identifier as tie-breaker.
    chrono.sort(key=lambda e: (e.timestamp, 0 if e.kind == "evidence" else 1, e.identifier))

    # --- Build incident metadata -----------------------------------------
    incident_dict: Dict[str, Any] | None = None
    if incident is not None:
        incident_dict = incident.to_dict()

    # --- Coverage summary ------------------------------------------------
    original_ids = sum(1 for e in evidence_items if e.original_event_id is not None)
    generated_ids = len(evidence_items) - original_ids

    # Build a lookup from alert_id to the original alert's number of evidence events.
    raw_evidence_count: Dict[str, int] = {a.alert_id: len(a.evidence) for a in alerts}
    all_linked = sum(
        1 for pa in package_alerts if len(pa.evidence_refs) == raw_evidence_count.get(pa.alert_id, 0)
    )
    distinct_sources = tuple(sorted({e.source for e in evidence_items if e.source}))

    coverage = CoverageSummary(
        total_evidence_items=len(evidence_items),
        total_alerts=len(package_alerts),
        total_diagnostics=len(pkg_diagnostics),
        distinct_telemetry_sources=distinct_sources,
        evidence_with_original_ids=original_ids,
        evidence_with_generated_ids=generated_ids,
        alerts_with_complete_linkage=all_linked,
        alerts_with_incomplete_provenance=incomplete_provenance,
    )

    # --- Package ID ------------------------------------------------------
    package_id = _compute_package_id(incident_dict, package_alerts, tuple(evidence_items),
                                      tuple(pkg_diagnostics), tuple(chrono))

    return InvestigationPackage(
        package_version=PACKAGE_VERSION,
        package_id=package_id,
        generated_at=gen,
        incident=incident_dict,
        alerts=tuple(package_alerts),
        evidence=tuple(evidence_items),
        diagnostics=tuple(pkg_diagnostics),
        chronology=tuple(chrono),
        coverage=coverage,
    )
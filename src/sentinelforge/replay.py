"""Deterministic detection replay and evaluation helpers."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .alerts import ALLOWED_SEVERITIES, Alert
from .detection.engine import DetectionEngine
from .events import SecurityEvent
from .ingestion.pipeline import ingest_file


def evidence_id(event: SecurityEvent) -> str:
    """Return a stable identifier for one evidence event."""
    if event.event_id:
        return str(event.event_id)
    return hashlib.sha256(event.raw.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class ReplayResult:
    events: tuple[SecurityEvent, ...]
    alerts: tuple[Alert, ...]
    diagnostics: tuple[Mapping[str, Any], ...]
    elapsed_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_count": len(self.events),
            "alert_count": len(self.alerts),
            "alerts": [alert.to_dict() for alert in self.alerts],
            "explanations": [explain_alert(alert) for alert in self.alerts],
            "diagnostics": list(self.diagnostics),
            "timing": {"event_count": len(self.events), "alert_count": len(self.alerts),
                        "elapsed_seconds": self.elapsed_seconds},
        }


@dataclass(frozen=True)
class ExpectedAlert:
    rule_id: str
    severity: str
    count: int = 1
    alert_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvaluationResult:
    expected_alert_count: int
    actual_alert_count: int
    matched_alerts: tuple[dict[str, Any], ...]
    missing_expected_alerts: tuple[dict[str, Any], ...]
    unexpected_alerts: tuple[dict[str, Any], ...]
    rule_breakdown: tuple[dict[str, Any], ...]
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float

    def to_dict(self) -> dict[str, Any]:
        return {"expected_alert_count": self.expected_alert_count, "actual_alert_count": self.actual_alert_count,
                "matched_alerts": list(self.matched_alerts), "missing_expected_alerts": list(self.missing_expected_alerts),
                "unexpected_alerts": list(self.unexpected_alerts), "rule_breakdown": list(self.rule_breakdown),
                "metrics": {"true_positives": self.true_positives, "false_positives": self.false_positives,
                             "false_negatives": self.false_negatives, "precision": self.precision, "recall": self.recall}}


def replay_events(events: Sequence[SecurityEvent], engine: DetectionEngine | None = None) -> ReplayResult:
    """Run the existing DetectionEngine without mutating the input sequence."""
    started = time.perf_counter()
    copied = tuple(events)
    alerts = tuple((engine or DetectionEngine()).detect(copied))
    elapsed = time.perf_counter() - started
    return ReplayResult(copied, alerts, (), elapsed)


def replay_file(path: str | Path, source: str, engine: DetectionEngine | None = None) -> ReplayResult:
    """Ingest one explicitly selected supported input and replay detection."""
    started = time.perf_counter()
    result = ingest_file(Path(path), source=source)
    replay = replay_events(result.events, engine)
    return ReplayResult(replay.events, replay.alerts,
                        tuple(item.to_dict() for item in result.diagnostics),
                        time.perf_counter() - started)


def load_expected(path: str | Path) -> tuple[ExpectedAlert, ...]:
    """Load and deterministically normalize the explicit expected-result schema."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
        raise ValueError("expected results must be an object with an alerts list")
    merged: dict[tuple[str, str], ExpectedAlert] = {}
    for item in payload["alerts"]:
        if (not isinstance(item, dict) or not isinstance(item.get("rule_id"), str) or not item["rule_id"].strip()
                or not isinstance(item.get("severity"), str) or item["severity"] not in ALLOWED_SEVERITIES):
            raise ValueError("each expected alert requires a non-empty rule_id and supported severity")
        count = item.get("count", 1)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("expected alert count must be a non-negative integer")
        key = (item["rule_id"], item["severity"])
        prior = merged.get(key)
        raw_ids = item.get("alert_ids", [])
        raw_evidence = item.get("evidence_ids", [])
        if not isinstance(raw_ids, list) or not all(isinstance(value, str) and value for value in raw_ids):
            raise ValueError("alert_ids must be a list of non-empty strings")
        if not isinstance(raw_evidence, list) or not all(isinstance(value, str) and value for value in raw_evidence):
            raise ValueError("evidence_ids must be a list of non-empty strings")
        if raw_ids and count != len(set(raw_ids)):
            raise ValueError("alert_ids count must equal count")
        if raw_evidence and count != 1:
            raise ValueError("evidence_ids currently identify one alert instance")
        ids = tuple(sorted(set(raw_ids)))
        evidence = tuple(sorted(set(raw_evidence)))
        if prior is None:
            merged[key] = ExpectedAlert(*key, count, ids, evidence)
        else:
            merged[key] = ExpectedAlert(*key, prior.count + count,
                                        tuple(sorted(set(prior.alert_ids + ids))),
                                        tuple(sorted(set(prior.evidence_ids + evidence))))
    return tuple(merged[key] for key in sorted(merged))


def _alert_shape(alert: Alert) -> dict[str, Any]:
    return {"alert_id": alert.alert_id, "rule_id": alert.rule_id, "severity": alert.severity,
            "evidence_ids": [evidence_id(event) for event in alert.evidence]}


def evaluate(alerts: Sequence[Alert], expected: Sequence[ExpectedAlert]) -> EvaluationResult:
    """Compare stable rule/severity/count properties, optionally honoring IDs."""
    actual = sorted(alerts, key=lambda item: (item.rule_id, item.severity, item.alert_id))
    remaining = list(actual)
    matched: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    expected_total = sum(item.count for item in expected)
    for item in expected:
        candidates = [alert for alert in remaining if alert.rule_id == item.rule_id and alert.severity == item.severity]
        if item.alert_ids:
            candidates = [alert for alert in candidates if alert.alert_id in item.alert_ids]
        if item.evidence_ids:
            candidates = [alert for alert in candidates
                          if item.evidence_ids == tuple(sorted(evidence_id(event) for event in alert.evidence))]
        selected = candidates[:item.count]
        for alert in selected:
            remaining.remove(alert)
            matched.append(_alert_shape(alert))
        if len(selected) < item.count:
            missing.append({"rule_id": item.rule_id, "severity": item.severity, "count": item.count - len(selected)})
    unexpected = tuple(_alert_shape(alert) for alert in remaining)
    rules = sorted({(item.rule_id, item.severity) for item in expected} | {(a.rule_id, a.severity) for a in actual})
    breakdown = []
    matched_counts = {}
    for item in matched:
        key = (item["rule_id"], item["severity"])
        matched_counts[key] = matched_counts.get(key, 0) + 1
    for rule_id, severity in rules:
        exp = sum(item.count for item in expected if (item.rule_id, item.severity) == (rule_id, severity))
        act = sum(1 for alert in actual if (alert.rule_id, alert.severity) == (rule_id, severity))
        breakdown.append({"rule_id": rule_id, "severity": severity, "expected": exp, "actual": act,
                          "matched": matched_counts.get((rule_id, severity), 0)})
    tp = len(matched)
    fp = len(unexpected)
    fn = expected_total - tp
    return EvaluationResult(expected_total, len(actual), tuple(matched), tuple(missing), unexpected, tuple(breakdown),
                             tp, fp, fn, tp / (tp + fp) if tp + fp else 0.0,
                             tp / (tp + fn) if tp + fn else 0.0)


def explain_alert(alert: Alert) -> dict[str, Any]:
    """Expose a deterministic, evidence-derived explanation without inference."""
    ids = tuple(evidence_id(event) for event in sorted(alert.evidence, key=lambda item: (item.timestamp, item.raw)))
    return {"rule_id": alert.rule_id, "severity": alert.severity, "triggering_event_ids": ids,
            "evidence_ids": ids, "text": alert.description}

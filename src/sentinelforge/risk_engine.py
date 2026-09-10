"""Deterministic risk scoring from alerts, correlations, and ATT&CK metadata."""

from __future__ import annotations

from typing import List, Sequence

from .alerts import Alert
from .correlation import CorrelationFinding
from .risk import RiskAssessment

_SEVERITY_POINTS = {"low": 10, "medium": 30, "high": 50, "critical": 70}


def assess_risk(alerts: Sequence[Alert], correlations: Sequence[CorrelationFinding]) -> RiskAssessment:
    """Calculate a bounded score using transparent evidence-derived factors."""
    if not alerts:
        raise ValueError("risk assessment requires at least one alert")
    highest_alert = max(alerts, key=lambda alert: _SEVERITY_POINTS[alert.severity])
    score = _SEVERITY_POINTS[highest_alert.severity]
    factors: List[str] = [f"highest alert severity: {highest_alert.severity} (+{score})"]

    correlation_points = min(len(correlations) * 10, 20)
    if correlation_points:
        score += correlation_points
        factors.append(f"supported correlation findings: {len(correlations)} (+{correlation_points})")

    mapping_count = len({mapping.technique_id for alert in alerts for mapping in alert.attack_mappings})
    mapping_points = min(mapping_count * 5, 10)
    if mapping_points:
        score += mapping_points
        factors.append(f"explicit ATT&CK techniques: {mapping_count} (+{mapping_points})")

    score = min(score, 100)
    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"
    explanation = "Risk is a deterministic prioritization score based only on alert severity, supported correlations, and explicit ATT&CK metadata; it is not probability or proof of compromise."
    return RiskAssessment(score, level, tuple(factors), explanation)

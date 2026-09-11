"""Deterministic correlation of existing alert evidence."""

from __future__ import annotations

from datetime import timedelta
from typing import List, Sequence, Tuple

from .alerts import Alert
from .correlation import CorrelationFinding, create_finding, event_evidence_id
from .events import SecurityEvent

AUTH_SEQUENCE_WINDOW_SECONDS = 300
PRIVILEGED_SEQUENCE_WINDOW_SECONDS = 300
EVENT_SEQUENCE_WINDOW_SECONDS = 300


def _events(alert: Alert, event_type: str) -> List[SecurityEvent]:
    return [event for event in alert.evidence if event.event_type == event_type]


def _finding_alerts(alerts: Sequence[Alert], evidence: Sequence[SecurityEvent]) -> Tuple[str, ...]:
    evidence_raw = {event.raw for event in evidence}
    return tuple(sorted(alert.alert_id for alert in alerts
                        if any(event.raw in evidence_raw for event in alert.evidence)))


def correlate_alerts(alerts: Sequence[Alert]) -> List[CorrelationFinding]:
    """Return supported authentication correlations in deterministic order."""
    ordered_alerts = sorted(alerts, key=lambda alert: alert.alert_id)
    findings: List[CorrelationFinding] = []
    failures = [event for alert in ordered_alerts for event in _events(alert, "authentication_failure")]
    successes = [event for alert in ordered_alerts for event in _events(alert, "authentication_success")]
    sudo_events = [event for alert in ordered_alerts for event in _events(alert, "sudo_activity")]

    for success in sorted(successes, key=lambda event: (event.timestamp, event.raw)):
        matching_failures = [event for event in failures
                             if event.username == success.username and event.username
                             and event.timestamp <= success.timestamp
                             and success.timestamp - event.timestamp <= timedelta(seconds=AUTH_SEQUENCE_WINDOW_SECONDS)]
        if matching_failures:
            sequence_by_raw = {event.raw: event for event in matching_failures + [success]}
            sequence = sorted(sequence_by_raw.values(), key=lambda event: (event.timestamp, event.raw))
            involved_alerts = _finding_alerts(ordered_alerts, sequence)
            evidence_ids = tuple(event_evidence_id(event.raw) for event in sequence)
            findings.append(create_finding(
                "AUTHENTICATION_ESCALATION", "Authentication escalation sequence observed.",
                involved_alerts, evidence_ids, sequence[0].timestamp, sequence[-1].timestamp,
                "Failed authentication attempts were followed by success for the same account within 300 seconds; this is not proof of compromise.",
            ))

        matching_sudo = [event for event in sudo_events
                         if event.username == success.username and event.username
                         and event.timestamp >= success.timestamp
                         and event.timestamp - success.timestamp <= timedelta(seconds=PRIVILEGED_SEQUENCE_WINDOW_SECONDS)]
        for sudo_event in matching_sudo:
            sequence = [success, sudo_event]
            involved_alerts = _finding_alerts(ordered_alerts, sequence)
            evidence_ids = tuple(event_evidence_id(event.raw) for event in sequence)
            findings.append(create_finding(
                "AUTHENTICATION_TO_PRIVILEGED_ACTIVITY", "Authentication followed by privileged activity observed.",
                involved_alerts, evidence_ids, success.timestamp, sudo_event.timestamp,
                "Successful authentication was followed by sudo activity for the same account within 300 seconds; this is not proof of misuse.",
            ))

    # DetectionEngine owns relationship matching. Here we only materialize
    # findings from the concrete correlation alerts it emitted.
    descriptions = {
        "AUTHENTICATION_TO_NETWORK_ACTIVITY": "Authentication followed by network activity observed.",
        "AUTHENTICATION_TO_PROCESS_ACTIVITY": "Authentication followed by process activity observed.",
        "NETWORK_TO_PROCESS_ACTIVITY": "Network activity followed by process activity observed.",
        "AUTH_NETWORK_PROCESS_CHAIN": "Authentication, network, and process chain observed.",
    }
    rationales = {
        rule_id: "The DetectionEngine observed the explicit chronological relationship within 300 seconds; this is not proof of compromise."
        for rule_id in descriptions
    }
    for alert in ordered_alerts:
        if alert.rule_id not in descriptions:
            continue
        evidence = tuple(sorted(alert.evidence, key=lambda event: (event.timestamp, event.raw)))
        findings.append(create_finding(
            alert.rule_id, descriptions[alert.rule_id], (alert.alert_id,),
            tuple(event_evidence_id(event.raw) for event in evidence),
            evidence[0].timestamp, evidence[-1].timestamp,
            rationales[alert.rule_id],
        ))

    unique_findings = {finding.correlation_id: finding for finding in findings}
    return sorted(unique_findings.values(), key=lambda finding: finding.correlation_id)

"""Deterministic derivation of incidents from detection alerts."""

from __future__ import annotations

from typing import Dict, FrozenSet, List, Sequence

from .alerts import Alert
from .correlation_engine import correlate_alerts
from .incidents import Incident, create_incident
from .risk_engine import assess_risk


def _alert_context(alert: Alert) -> FrozenSet[str]:
    """Return only context explicitly present in an alert's evidence."""
    context = set()
    for event in alert.evidence:
        if event.username:
            context.add(f"username:{event.username}")
        if event.source_ip:
            context.add(f"source_ip:{event.source_ip}")
    if not context:
        context.add(f"alert:{alert.alert_id}")
    return frozenset(context)


def derive_incidents(alerts: Sequence[Alert]) -> List[Incident]:
    """Group alerts with shared evidence context into deterministic incidents."""
    ordered_alerts = sorted(alerts, key=lambda alert: alert.alert_id)
    contexts = [_alert_context(alert) for alert in ordered_alerts]
    groups: List[List[Alert]] = []
    group_contexts: List[set[str]] = []

    for alert, context in zip(ordered_alerts, contexts):
        matching_groups = [
            index for index, existing_context in enumerate(group_contexts)
            if context.intersection(existing_context)
        ]
        if not matching_groups:
            groups.append([alert])
            group_contexts.append(set(context))
            continue
        first_group = matching_groups[0]
        groups[first_group].append(alert)
        group_contexts[first_group].update(context)
        for group_index in reversed(matching_groups[1:]):
            groups[first_group].extend(groups[group_index])
            group_contexts[first_group].update(group_contexts[group_index])
            del groups[group_index]
            del group_contexts[group_index]

    incidents = []
    for group, group_context in zip(groups, group_contexts):
        incident = create_incident(group, frozenset(group_context))
        correlations = tuple(correlate_alerts(group))
        risk_assessment = assess_risk(group, correlations)
        incident = Incident(
            incident_id=incident.incident_id,
            title=incident.title,
            description=incident.description,
            severity=incident.severity,
            status=incident.status,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
            related_alert_ids=incident.related_alert_ids,
            affected_users=incident.affected_users,
            affected_entities=incident.affected_entities,
            evidence=incident.evidence,
            source_rule_ids=incident.source_rule_ids,
            correlations=correlations,
            risk_assessment=risk_assessment,
        )
        incidents.append(incident)
    return sorted(incidents, key=lambda incident: incident.incident_id)

"""Analysis orchestration and terminal reporting."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from .detection.engine import DetectionEngine
from .incident_engine import derive_incidents
from .ingestion.pipeline import ingest_file
from .investigation_engine import create_investigation
from .observable_engine import extract_observables
from .threat_context_engine import load_context

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
DEFAULT_CONTEXT_PATH = Path("rules/threat_context.json")


def _highest_severity(alerts: list) -> Optional[str]:
    if not alerts:
        return None
    return max((alert.severity for alert in alerts), key=SEVERITY_ORDER.get)


def _filter_alerts(alerts: list, severity: Optional[str]) -> list:
    if severity is None:
        return list(alerts)
    return [alert for alert in alerts if alert.severity == severity]


def _filter_incidents(incidents: list, incident_id: Optional[str], severity: Optional[str]) -> list:
    selected = incidents
    if incident_id is not None:
        selected = [incident for incident in selected if incident.incident_id == incident_id]
    if severity is not None:
        selected = [incident for incident in selected if incident.severity == severity]
    return selected


def analyze_file(path: str, severity: Optional[str] = None,
                 incident_id: Optional[str] = None) -> Dict[str, Any]:
    """Run existing pipeline components and return a filtered structured report."""
    ingestion_result = ingest_file(path)
    events = ingestion_result.events
    diagnostics = ingestion_result.diagnostics
    all_alerts = DetectionEngine().detect(events)
    context = load_context(DEFAULT_CONTEXT_PATH)
    all_incidents = derive_incidents(all_alerts, context)
    all_investigations = [create_investigation(incident) for incident in all_incidents]

    selected_alerts = _filter_alerts(all_alerts, severity)
    selected_incidents = _filter_incidents(all_incidents, incident_id, severity)
    selected_incident_ids = {incident.incident_id for incident in selected_incidents}
    selected_investigations = [investigation for investigation in all_investigations
                               if investigation.incident_id in selected_incident_ids]
    selected_context = {
        (item.observable_type, item.value): item
        for incident in selected_incidents
        for item in incident.threat_context
    }
    return {
        "source": str(path),
        "events": [event.to_dict() for event in events],
        "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics],
        "alerts": [alert.to_dict() for alert in selected_alerts],
        "observables": [observable.to_dict() for observable in extract_observables(events)],
        "threat_context": [item.to_dict() for item in sorted(selected_context.values(), key=lambda item: (item.observable_type, item.value))],
        "incidents": [incident.to_dict() for incident in selected_incidents],
        "investigations": [investigation.to_dict() for investigation in selected_investigations],
    }


def render_human_report(report: Dict[str, Any]) -> str:
    """Render a concise deterministic terminal summary from an analysis report."""
    alerts = report["alerts"]
    incidents = report["incidents"]
    investigations = report["investigations"]
    risk_assessments = [incident["risk_assessment"] for incident in incidents
                        if incident.get("risk_assessment") is not None]
    highest = max((item["severity"] for item in alerts), key=SEVERITY_ORDER.get, default="none")
    techniques = sorted({mapping["technique_id"] for incident in incidents
                         for mapping in incident.get("attack_mappings", [])})
    lines = [
        "SentinelForge analysis",
        f"Source: {report['source']}",
        f"Events: {len(report['events'])}",
        f"Diagnostics: {len(report['diagnostics'])}",
        f"Alerts: {len(alerts)} (highest severity: {highest})",
        f"Correlations: {sum(len(incident.get('correlations', [])) for incident in incidents)}",
        f"Risk: {risk_assessments[0]['score']} ({risk_assessments[0]['level']})" if risk_assessments else "Risk: none",
        f"ATT&CK techniques: {', '.join(techniques) if techniques else 'none'}",
        f"Observables: {len(report['observables'])}",
        f"Threat context matches: {len(report['threat_context'])}",
        f"Incidents: {len(incidents)}",
        f"Investigations: {len(investigations)}",
    ]
    return "\n".join(lines)

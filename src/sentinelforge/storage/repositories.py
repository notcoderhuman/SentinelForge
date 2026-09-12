"""Typed repositories backed by the local SQLite database."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional, TypeVar

from ..alerts import Alert
from ..correlation import CorrelationFinding
from ..evidence import Evidence
from ..events import SecurityEvent
from ..incidents import Incident
from ..investigations import AnalystNote, Investigation, TimelineEntry
from ..risk import RiskAssessment
from ..threat_context import ThreatContext
from .database import Database

T = TypeVar("T")

def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def _event(data: Dict[str, Any]) -> SecurityEvent:
    return SecurityEvent(timestamp=_dt(data["timestamp"]), source=data["source"],
        event_type=data["event_type"], hostname=data.get("hostname"), process=data.get("process"),
        username=data.get("username"), source_ip=data.get("source_ip"), message=data["message"],
        raw=data["raw"], event_id=data.get("event_id"),
        source_port=data.get("source_port"), destination_ip=data.get("destination_ip"),
        destination_port=data.get("destination_port"), protocol=data.get("protocol"),
        process_name=data.get("process_name"), process_id=data.get("process_id"),
        parent_process_id=data.get("parent_process_id"), command_line=data.get("command_line"),
        executable_path=data.get("executable_path"), privilege=data.get("privilege"),
        direction=data.get("direction"), persistence_type=data.get("persistence_type"),
        persistence_action=data.get("persistence_action"), persistence_name=data.get("persistence_name"),
        command=data.get("command"), service_manager=data.get("service_manager"), task_path=data.get("task_path"),
        query=data.get("query"), query_type=data.get("query_type"),
        response_code=data.get("response_code"), resolved_ip=data.get("resolved_ip"),
        query_name=data.get("query_name"), answers=list(data.get("answers", ())),
        path=data.get("path"), action=data.get("action"), file_hash=data.get("file_hash"),
        old_path=data.get("old_path"), size=data.get("size"),
         hive=data.get("hive"), key_path=data.get("key_path"), registry_action=data.get("registry_action"),
         value_name=data.get("value_name"), value_data=data.get("value_data"), value_type=data.get("value_type"),
         old_key_path=data.get("old_key_path"), provider=data.get("provider"),
         system_event_id=data.get("system_event_id"), system_action=data.get("system_action"),
         service_name=data.get("service_name"), service_state=data.get("service_state"))

def _evidence(data: Dict[str, Any]) -> Evidence:
    return Evidence(data["evidence_id"], _event(data["event"]), data["evidence_type"],
        data["source"], _dt(data["timestamp"]), data["relevance"], data["provenance"])

def _correlation(data: Dict[str, Any]) -> CorrelationFinding:
    return CorrelationFinding(data["correlation_id"], data["name"], data["description"],
        tuple(data["related_alert_ids"]), tuple(data["evidence_ids"]), _dt(data["start_time"]),
        _dt(data["end_time"]), data["rationale"])

def _risk(data: Optional[Dict[str, Any]]) -> Optional[RiskAssessment]:
    return None if data is None else RiskAssessment(data["score"], data["level"], tuple(data["factors"]), data["explanation"])

def _contexts(values: Iterable[Dict[str, Any]]) -> tuple[ThreatContext, ...]:
    return tuple(ThreatContext(**item) for item in values)

class AnalysisRepository:
    """Atomic persistence and reconstruction for all analysis domain models."""
    def __init__(self, database: Database) -> None:
        self.db = database

    def save_run(self, run_id: str, run: Any) -> None:
        payload = run.to_dict() if hasattr(run, "to_dict") else (run if isinstance(run, dict) else {"value": run})
        created = payload.get("started_at") or payload.get("created_at") or payload.get("timestamp") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        parsed_created = _dt(created).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        with self.db.transaction() as c:
            c.execute("INSERT OR IGNORE INTO runs VALUES (?, ?, ?)", (run_id, parsed_created, _json(payload)))

    def list_runs(self) -> list[Dict[str, Any]]:
        rows = self.db.connection.execute("SELECT payload FROM runs ORDER BY created_at, run_id").fetchall()
        return [json.loads(row[0]) | {"run_id": json.loads(row[0]).get("run_id")} for row in rows]

    def save_alerts(self, alerts: Iterable[Alert], run_id: Optional[str] = None) -> None:
        with self.db.transaction():
            for alert in alerts:
                self.save_alert(alert, run_id)

    def save_incidents(self, incidents: Iterable[Incident], run_id: Optional[str] = None) -> None:
        with self.db.transaction():
            for incident in incidents:
                self.save_incident(incident, run_id)

    def save_investigations(self, investigations: Iterable[Investigation]) -> None:
        with self.db.transaction():
            for investigation in investigations:
                self.save_investigation(investigation)

    def list_payloads(self, resource: str, severity: Optional[str] = None,
                      filters: Optional[Dict[str, Any]] = None) -> list[Dict[str, Any]]:
        table = {"runs": "runs", "alerts": "alerts", "incidents": "incidents", "investigations": "investigations"}.get(resource)
        if table is None:
            raise ValueError("unsupported resource")
        values: Dict[str, Any] = dict(filters or {})
        if severity is not None:
            values["severity"] = severity
        json_paths = {
            "alerts": {"severity": "$.severity", "rule_id": "$.rule_id", "source": "$.source"},
            "incidents": {"severity": "$.severity", "status": "$.status", "risk_level": "$.risk_assessment.level"},
            "investigations": {"status": "$.status"},
            "runs": {"source": "$.source"},
        }
        allowed = set(json_paths[resource]) | {"run_id", "incident_id", "since", "until", "min_risk_score", "max_risk_score", "limit"}
        unknown = set(values) - allowed
        if unknown:
            raise ValueError("unsupported query parameter")
        clauses: list[str] = []
        params: list[Any] = []
        for key, json_path in json_paths[resource].items():
            if key in values:
                clauses.append(f"json_extract(payload, '{json_path}') = ?")
                params.append(values[key])
        if "run_id" in values:
            clauses.append("run_id = ?")
            params.append(values["run_id"])
        if "incident_id" in values:
            clauses.append("incident_id = ?")
            params.append(values["incident_id"])
        timestamp_column = {"alerts": "timestamp", "incidents": "updated_at", "investigations": "updated_at", "runs": "created_at"}[resource]
        if "since" in values:
            clauses.append(f"{timestamp_column} >= ?")
            params.append(values["since"])
        if "until" in values:
            clauses.append(f"{timestamp_column} <= ?")
            params.append(values["until"])
        if "min_risk_score" in values:
            clauses.append("CAST(json_extract(payload, '$.risk_assessment.score') AS REAL) >= ?")
            params.append(values["min_risk_score"])
        if "max_risk_score" in values:
            clauses.append("CAST(json_extract(payload, '$.risk_assessment.score') AS REAL) <= ?")
            params.append(values["max_risk_score"])
        query = f"SELECT payload FROM {table}"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        legacy_order = ((resource in {"alerts", "incidents"} and set(values) <= {"severity"})
                        or (resource == "runs" and set(values) <= {"limit"}))
        if values and not legacy_order:
            order = {"alerts": "timestamp DESC, alert_id", "incidents": "updated_at DESC, incident_id", "investigations": "updated_at DESC, investigation_id", "runs": "created_at DESC, run_id"}[resource]
            query += f" ORDER BY {order}"
        else:
            query += " ORDER BY rowid"
        if "limit" in values:
            query += " LIMIT ?"
            params.append(values["limit"])
        return [json.loads(row[0]) for row in self.db.connection.execute(query, tuple(params)).fetchall()]

    def get_payload(self, resource: str, entity_id: str) -> Optional[Dict[str, Any]]:
        columns = {"runs": ("runs", "run_id"), "alerts": ("alerts", "alert_id"), "incidents": ("incidents", "incident_id"), "investigations": ("investigations", "investigation_id")}
        table, column = columns.get(resource, (None, None))
        if table is None:
            raise ValueError("unsupported resource")
        row = self.db.connection.execute(f"SELECT payload FROM {table} WHERE {column}=?", (entity_id,)).fetchone()
        return None if row is None else json.loads(row[0])

    def list_alerts_for_run(self, run_id: str) -> list[Alert]:
        rows = self.db.connection.execute("SELECT payload FROM alerts WHERE run_id=? ORDER BY timestamp, alert_id", (run_id,)).fetchall()
        return [self._alert_from_payload(json.loads(row[0])) for row in rows]

    @staticmethod
    def _alert_from_payload(d: Dict[str, Any]) -> Alert:
        return Alert(d["alert_id"], d["rule_id"], d["severity"], _dt(d["timestamp"]), d["title"], d["description"], [_event(x) for x in d["evidence"]], d.get("source", "linux-auth"))

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        row = self.db.connection.execute("SELECT payload FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return None if row is None else json.loads(row[0])

    def save_alert(self, alert: Alert, run_id: Optional[str] = None) -> None:
        payload = alert.to_dict()
        with self.db.transaction() as c:
            c.execute("INSERT OR IGNORE INTO alerts VALUES (?, ?, ?, ?)", (alert.alert_id, run_id, payload["timestamp"], _json(payload)))

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        row = self.db.connection.execute("SELECT payload FROM alerts WHERE alert_id=?", (alert_id,)).fetchone()
        if row is None: return None
        d = json.loads(row[0])
        return Alert(d["alert_id"], d["rule_id"], d["severity"], _dt(d["timestamp"]), d["title"], d["description"], [ _event(x) for x in d["evidence"] ], d.get("source", "linux-auth"))

    def save_incident(self, incident: Incident, run_id: Optional[str] = None) -> None:
        d = incident.to_dict()
        with self.db.transaction() as c:
            c.execute("INSERT OR IGNORE INTO incidents VALUES (?, ?, ?, ?, ?)", (incident.incident_id, run_id, d["created_at"], d["updated_at"], _json(d)))

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        row = self.db.connection.execute("SELECT payload FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if row is None: return None
        d = json.loads(row[0])
        return Incident(d["incident_id"], d["title"], d["description"], d["severity"], d["status"], _dt(d["created_at"]), _dt(d["updated_at"]), tuple(d["related_alert_ids"]), tuple(d["affected_users"]), tuple(d["affected_entities"]), tuple(_event(x) for x in d["evidence"]), tuple(d.get("source_rule_ids", ())), tuple(_correlation(x) for x in d.get("correlations", ())), _risk(d.get("risk_assessment")), _contexts(d.get("threat_context", ())))

    def save_investigation(self, investigation: Investigation) -> None:
        d = investigation.to_dict()
        with self.db.transaction() as c:
            c.execute("INSERT OR IGNORE INTO investigations VALUES (?, ?, ?, ?, ?)", (investigation.investigation_id, investigation.incident_id, d["created_at"], d["updated_at"], _json(d)))
            c.execute("DELETE FROM evidence WHERE investigation_id=?", (investigation.investigation_id,))
            c.execute("DELETE FROM notes WHERE investigation_id=?", (investigation.investigation_id,))
            for item in investigation.evidence:
                p = item.to_dict(); c.execute("INSERT INTO evidence VALUES (?, ?, ?, ?)", (item.evidence_id, investigation.investigation_id, p["timestamp"], _json(p)))
            for item in investigation.analyst_notes:
                p = item.to_dict(); c.execute("INSERT INTO notes VALUES (?, ?, ?, ?)", (item.note_id, investigation.investigation_id, p["timestamp"], _json(p)))

    def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        row = self.db.connection.execute("SELECT payload FROM investigations WHERE investigation_id=?", (investigation_id,)).fetchone()
        if row is None: return None
        d = json.loads(row[0])
        evidence = tuple(_evidence(x) for x in d["evidence"])
        timeline = tuple(TimelineEntry(_dt(x["timestamp"]), x["evidence_id"], x["summary"]) for x in d["timeline"])
        notes = tuple(AnalystNote(x["note_id"], _dt(x["timestamp"]), x["author"], x["content"]) for x in d["analyst_notes"])
        return Investigation(d["investigation_id"], d["incident_id"], d["status"], _dt(d["created_at"]), _dt(d["updated_at"]), evidence, timeline, notes, tuple(d.get("source_rule_ids", ())), tuple(_correlation(x) for x in d.get("correlations", ())), _risk(d.get("risk_assessment")), _contexts(d.get("threat_context", ())))

    def save_note(self, investigation_id: str, note: AnalystNote) -> None:
        with self.db.transaction() as c:
            p = note.to_dict(); c.execute("INSERT OR REPLACE INTO notes VALUES (?, ?, ?, ?)", (note.note_id, investigation_id, p["timestamp"], _json(p)))

    def save_evidence(self, investigation_id: str, evidence: Evidence) -> None:
        with self.db.transaction() as c:
            p = evidence.to_dict(); c.execute("INSERT OR REPLACE INTO evidence VALUES (?, ?, ?, ?)", (evidence.evidence_id, investigation_id, p["timestamp"], _json(p)))

"""Safe parser for newline-delimited system persistence records."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple

from ..events import SecurityEvent
from .linux_auth import ParseDiagnostic

_REQUIRED = ("timestamp", "hostname", "username", "persistence_type", "action", "name")
_ALLOWED_TYPES = frozenset({"service", "scheduled_task", "cron"})
_OPTIONAL_STRINGS = ("command", "service_manager", "task_path", "process_name", "process", "executable_path", "privilege")
_MAX_PROCESS_ID = (2**31) - 1


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty string")
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _optional_text(record: dict, field: str) -> Optional[str]:
    value = record.get(field)
    if value is None:
        return None
    return _text(value, field)


def _process_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_PROCESS_ID:
        raise ValueError(f"process_id must be an integer from 0 to {_MAX_PROCESS_ID}")
    return value


def parse_line(raw_line: str, line_number: int = 1) -> Tuple[Optional[SecurityEvent], Optional[ParseDiagnostic]]:
    raw = raw_line.rstrip("\r\n")
    if not raw.strip():
        return None, ParseDiagnostic(line_number, raw, "missing persistence record")
    try:
        record = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, ParseDiagnostic(line_number, raw, "malformed persistence JSON")
    if not isinstance(record, dict):
        return None, ParseDiagnostic(line_number, raw, "persistence record must be a JSON object")
    missing = [field for field in _REQUIRED if field not in record or record[field] is None]
    if missing:
        return None, ParseDiagnostic(line_number, raw, "persistence record is missing: " + ", ".join(missing))
    try:
        timestamp = _timestamp(record["timestamp"])
        hostname = _text(record["hostname"], "hostname")
        username = _text(record["username"], "username")
        persistence_type = _text(record["persistence_type"], "persistence_type")
        if persistence_type not in _ALLOWED_TYPES:
            raise ValueError("persistence_type must be service, scheduled_task, or cron")
        persistence_action = _text(record["action"], "action")
        persistence_name = _text(record["name"], "name")
        process_id = None if record.get("process_id") is None else _process_id(record["process_id"])
        optional = {field: _optional_text(record, field) for field in _OPTIONAL_STRINGS}
    except (TypeError, ValueError) as exc:
        return None, ParseDiagnostic(line_number, raw, f"invalid persistence record: {exc}")
    process_name = optional["process_name"] or optional["process"]
    return SecurityEvent(
        timestamp=timestamp, source="system_persistence", event_type="system_persistence",
        hostname=hostname, process=process_name, username=username, source_ip=None,
        message=f"Persistence {persistence_action}: {persistence_name} ({persistence_type}) on {hostname}", raw=raw,
        process_name=process_name, process_id=process_id, executable_path=optional["executable_path"], privilege=optional["privilege"],
        persistence_type=persistence_type, persistence_action=persistence_action, persistence_name=persistence_name,
        command=optional["command"], service_manager=optional["service_manager"], task_path=optional["task_path"],
    ), None


def parse_lines(lines: Iterable[str]) -> Tuple[List[SecurityEvent], List[ParseDiagnostic]]:
    events: List[SecurityEvent] = []
    diagnostics: List[ParseDiagnostic] = []
    for line_number, line in enumerate(lines, start=1):
        event, diagnostic = parse_line(line, line_number)
        if event is not None:
            events.append(event)
        if diagnostic is not None:
            diagnostics.append(diagnostic)
    return events, diagnostics


def parse_file(path: str) -> Tuple[List[SecurityEvent], List[ParseDiagnostic]]:
    with open(path, "r", encoding="utf-8", errors="replace") as input_file:
        return parse_lines(input_file)

"""Safe parser for newline-delimited Windows system-event telemetry."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple

from ..events import SecurityEvent
from .linux_auth import ParseDiagnostic

_REQUIRED = ("timestamp", "hostname", "event_id", "provider", "action")
_OPTIONAL_STRINGS = ("username", "process_name", "executable_path", "service_name", "service_state", "command", "message")
_MAX_EVENT_ID = (2**31) - 1
_MAX_PROCESS_ID = (2**31) - 1


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _optional_text(record: dict, field: str) -> Optional[str]:
    value = record.get(field)
    return None if value is None else _text(value, field)


def _bounded_id(value: object, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{field} must be an integer from 0 to {maximum}")
    return value


def parse_line(raw_line: str, line_number: int = 1) -> Tuple[Optional[SecurityEvent], Optional[ParseDiagnostic]]:
    raw = raw_line.rstrip("\r\n")
    if not raw.strip():
        return None, ParseDiagnostic(line_number, raw, "missing Windows system-event record")
    try:
        record = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, ParseDiagnostic(line_number, raw, "malformed Windows system-event JSON")
    if not isinstance(record, dict):
        return None, ParseDiagnostic(line_number, raw, "Windows system-event record must be a JSON object")
    missing = [field for field in _REQUIRED if field not in record or record[field] is None]
    if missing:
        return None, ParseDiagnostic(line_number, raw, "Windows system-event record is missing: " + ", ".join(missing))
    try:
        timestamp = _timestamp(record["timestamp"])
        hostname = _text(record["hostname"], "hostname")
        event_id = _bounded_id(record["event_id"], "event_id", _MAX_EVENT_ID)
        provider = _text(record["provider"], "provider")
        action = _text(record["action"], "action")
        process_id = None if record.get("process_id") is None else _bounded_id(record["process_id"], "process_id", _MAX_PROCESS_ID)
        optional = {field: _optional_text(record, field) for field in _OPTIONAL_STRINGS}
    except (TypeError, ValueError) as exc:
        return None, ParseDiagnostic(line_number, raw, f"invalid Windows system-event record: {exc}")
    identity = json.dumps({"timestamp": timestamp.isoformat(), "hostname": hostname, "event_id": event_id,
                           "provider": provider, "action": action, **optional, "process_id": process_id},
                          sort_keys=True, separators=(",", ":"))
    stable_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    process_name = optional["process_name"]
    message = optional["message"] or f"Windows system event {event_id}: {provider} {action}"
    return SecurityEvent(
        timestamp=timestamp, source="windows_system_event", event_type="windows_system_event",
        hostname=hostname, process=process_name, username=optional["username"], source_ip=None,
        message=message, raw=raw, event_id=stable_id, process_name=process_name,
        process_id=process_id, executable_path=optional["executable_path"], command=optional["command"],
        provider=provider, system_event_id=event_id, system_action=action,
        service_name=optional["service_name"], service_state=optional["service_state"],
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

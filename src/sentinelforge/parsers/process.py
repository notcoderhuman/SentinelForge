"""Safe parser for newline-delimited JSON process execution records."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple

from ..events import SecurityEvent
from .linux_auth import ParseDiagnostic

_REQUIRED = ("timestamp", "hostname", "process_name", "process_id", "username")
_OPTIONAL_STRINGS = ("command_line", "executable_path", "privilege")
_MAX_PROCESS_ID = (2**31) - 1


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty string")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _process_id(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_PROCESS_ID:
        raise ValueError(f"{field} must be an integer from 0 to {_MAX_PROCESS_ID}")
    return value


def parse_line(raw_line: str, line_number: int = 1) -> Tuple[Optional[SecurityEvent], Optional[ParseDiagnostic]]:
    """Parse one JSON object line without evaluating any supplied content."""
    raw = raw_line.rstrip("\r\n")
    if not raw.strip():
        return None, ParseDiagnostic(line_number, raw, "missing process record")
    try:
        record = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, ParseDiagnostic(line_number, raw, "malformed process JSON")
    if not isinstance(record, dict):
        return None, ParseDiagnostic(line_number, raw, "process record must be a JSON object")
    missing = [field for field in _REQUIRED if field not in record or record[field] is None]
    if missing:
        return None, ParseDiagnostic(line_number, raw, "process record is missing: " + ", ".join(missing))
    try:
        timestamp = _timestamp(record["timestamp"])
        hostname = _text(record["hostname"], "hostname")
        process_name = _text(record["process_name"], "process_name")
        process_id = _process_id(record["process_id"], "process_id")
        username = _text(record["username"], "username")
        parent_process_id = record.get("parent_process_id")
        if parent_process_id is not None:
            parent_process_id = _process_id(parent_process_id, "parent_process_id")
        for field in _OPTIONAL_STRINGS:
            if record.get(field) is not None and not isinstance(record[field], str):
                raise ValueError(f"{field} must be a string")
    except (TypeError, ValueError) as exc:
        return None, ParseDiagnostic(line_number, raw, f"invalid process record: {exc}")

    command_line = record.get("command_line")
    executable_path = record.get("executable_path")
    privilege = record.get("privilege")
    return SecurityEvent(
        timestamp=timestamp,
        source="process_execution",
        event_type="process_execution",
        hostname=hostname,
        process=process_name,
        username=username,
        source_ip=None,
        message=f"Process {process_name} (pid {process_id}) executed on {hostname}",
        raw=raw,
        process_name=process_name,
        process_id=process_id,
        parent_process_id=parent_process_id,
        command_line=command_line,
        executable_path=executable_path,
        privilege=privilege,
    ), None


def parse_lines(lines: Iterable[str]) -> Tuple[List[SecurityEvent], List[ParseDiagnostic]]:
    """Parse records in input order, retaining diagnostics instead of aborting."""
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
    """Read and parse an explicitly supplied UTF-8 NDJSON file."""
    with open(path, "r", encoding="utf-8", errors="replace") as input_file:
        return parse_lines(input_file)

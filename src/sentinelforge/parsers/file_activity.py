"""Safe parser for newline-delimited JSON file activity records."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple

from ..events import SecurityEvent
from .linux_auth import ParseDiagnostic

_REQUIRED = ("timestamp", "hostname", "path", "action", "username")
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


def parse_line(raw_line: str, line_number: int = 1) -> Tuple[Optional[SecurityEvent], Optional[ParseDiagnostic]]:
    raw = raw_line.rstrip("\r\n")
    if not raw.strip():
        return None, ParseDiagnostic(line_number, raw, "missing file activity record")
    try:
        record = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, ParseDiagnostic(line_number, raw, "malformed file activity JSON")
    if not isinstance(record, dict):
        return None, ParseDiagnostic(line_number, raw, "file activity record must be a JSON object")
    missing = [field for field in _REQUIRED if field not in record or record[field] is None]
    if missing:
        return None, ParseDiagnostic(line_number, raw, "file activity record is missing: " + ", ".join(missing))
    try:
        timestamp = _timestamp(record["timestamp"])
        values = {field: _text(record[field], field) for field in _REQUIRED[1:]}
        optional_strings = {}
        for field in ("file_hash", "old_path", "process_name", "privilege", "direction"):
            value = record.get(field)
            if value is not None:
                optional_strings[field] = _text(value, field)
            else:
                optional_strings[field] = None
        for field in ("process_id", "parent_process_id"):
            value = record.get(field)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ValueError(f"{field} must be a non-negative integer")
        size = record.get("size")
        if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
            raise ValueError("size must be a non-negative integer")
    except (TypeError, ValueError) as exc:
        return None, ParseDiagnostic(line_number, raw, f"invalid file activity record: {exc}")
    return SecurityEvent(
        timestamp=timestamp, source="file_activity", event_type="file_activity",
        hostname=values["hostname"], process=record.get("process_name"), username=values["username"], source_ip=None,
        message=f"File {values['action']}: {values['path']}", raw=raw,
        path=values["path"], action=values["action"], file_hash=record.get("file_hash"),
        old_path=optional_strings["old_path"], size=size,
        process_id=record.get("process_id"), parent_process_id=record.get("parent_process_id"),
        process_name=optional_strings["process_name"], privilege=optional_strings["privilege"], direction=optional_strings["direction"],
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

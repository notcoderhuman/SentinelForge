"""Safe parser for newline-delimited JSON Windows registry change records."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple

from ..events import SecurityEvent
from .linux_auth import ParseDiagnostic

_REQUIRED = ("timestamp", "hostname", "username", "hive", "key_path", "action")
_HIVE_ALIASES = {
    "HKCU": "HKEY_CURRENT_USER", "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKLM": "HKEY_LOCAL_MACHINE", "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
}
_MAX_TEXT = 4096


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
    value = value.strip()
    if len(value) > _MAX_TEXT:
        raise ValueError(f"{field} exceeds maximum length")
    return value


def _optional_text(value: object, field: str) -> Optional[str]:
    return None if value is None else _text(value, field)


def _hive(value: object) -> str:
    hive = _text(value, "hive").upper()
    try:
        return _HIVE_ALIASES[hive]
    except KeyError as exc:
        raise ValueError("hive must be HKCU/HKEY_CURRENT_USER or HKLM/HKEY_LOCAL_MACHINE") from exc


def _key_path(value: object, field: str = "key_path") -> str:
    path = _text(value, field).replace("/", "\\")
    # Hive is a separate field; embedded hive prefixes are rejected to avoid conflicting identities.
    parts = [part for part in path.split("\\") if part]
    if parts and parts[0].upper() in {"HKCU", "HKLM", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"}:
        raise ValueError(f"{field} must not include a hive prefix")
    # Collapse separators only; path component case is intentionally preserved.
    if not parts:
        raise ValueError(f"{field} must contain a registry path")
    return "\\".join(parts)


def _process_id(value: object) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("process_id must be a non-negative integer")
    return value


def parse_line(raw_line: str, line_number: int = 1) -> Tuple[Optional[SecurityEvent], Optional[ParseDiagnostic]]:
    raw = raw_line.rstrip("\r\n")
    if not raw.strip():
        return None, ParseDiagnostic(line_number, raw, "missing registry change record")
    try:
        record = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, ParseDiagnostic(line_number, raw, "malformed registry change JSON")
    if not isinstance(record, dict):
        return None, ParseDiagnostic(line_number, raw, "registry change record must be a JSON object")
    missing = [field for field in _REQUIRED if field not in record or record[field] is None]
    if missing:
        return None, ParseDiagnostic(line_number, raw, "registry change record is missing: " + ", ".join(missing))
    try:
        timestamp = _timestamp(record["timestamp"])
        hostname = _text(record["hostname"], "hostname")
        username = _text(record["username"], "username")
        hive = _hive(record["hive"])
        key_path = _key_path(record["key_path"])
        action = _text(record["action"], "action")
        process_id = _process_id(record.get("process_id"))
        process_name = _optional_text(record.get("process_name"), "process_name")
        executable_path = _optional_text(record.get("executable_path"), "executable_path")
        privilege = _optional_text(record.get("privilege"), "privilege")
        value_name = _optional_text(record.get("value_name"), "value_name")
        value_data = _optional_text(record.get("value_data"), "value_data")
        value_type = _optional_text(record.get("value_type"), "value_type")
        old_key_path = None if record.get("old_key_path") is None else _key_path(record["old_key_path"], "old_key_path")
    except (TypeError, ValueError) as exc:
        return None, ParseDiagnostic(line_number, raw, f"invalid registry change record: {exc}")
    identity = json.dumps({"timestamp": timestamp.isoformat(), "hostname": hostname,
                           "username": username, "hive": hive, "key_path": key_path,
                           "action": action, "value_name": value_name, "value_data": value_data,
                           "value_type": value_type, "old_key_path": old_key_path,
                           "process_name": process_name, "executable_path": executable_path,
                           "privilege": privilege, "process_id": process_id},
                          sort_keys=True, separators=(",", ":"))
    event_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    detail = f"Registry {action}: {hive}\\{key_path}"
    return SecurityEvent(
        timestamp=timestamp, source="registry_change", event_type="registry_change",
        hostname=hostname, process=process_name, username=username, source_ip=None,
        message=detail, raw=raw, event_id=event_id, process_name=process_name,
        executable_path=executable_path, privilege=privilege, process_id=process_id,
        hive=hive, key_path=key_path, registry_action=action,
        value_name=value_name, value_data=value_data, value_type=value_type,
        old_key_path=old_key_path,
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

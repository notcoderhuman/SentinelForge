"""Safe parser for newline-delimited JSON network connection records."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple

from ..events import SecurityEvent
from .linux_auth import ParseDiagnostic

_REQUIRED = (
    "timestamp",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
)
_OPTIONAL = ("process_name", "username", "hostname", "direction")


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


def _ip(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid IP address") from exc
    return value


def _port(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        raise ValueError(f"{field} must be an integer from 0 to 65535")
    return value


def parse_line(raw_line: str, line_number: int = 1) -> Tuple[Optional[SecurityEvent], Optional[ParseDiagnostic]]:
    """Parse one JSON object line without evaluating any supplied content."""
    raw = raw_line.rstrip("\r\n")
    if not raw.strip():
        return None, ParseDiagnostic(line_number, raw, "missing network record")
    try:
        record = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, ParseDiagnostic(line_number, raw, "malformed network JSON")
    if not isinstance(record, dict):
        return None, ParseDiagnostic(line_number, raw, "network record must be a JSON object")
    missing = [field for field in _REQUIRED if field not in record or record[field] is None]
    if missing:
        return None, ParseDiagnostic(line_number, raw, "network record is missing: " + ", ".join(missing))
    try:
        timestamp = _timestamp(record["timestamp"])
        source_ip = _ip(record["source_ip"], "source_ip")
        destination_ip = _ip(record["destination_ip"], "destination_ip")
        source_port = _port(record["source_port"], "source_port")
        destination_port = _port(record["destination_port"], "destination_port")
        protocol = record["protocol"]
        if not isinstance(protocol, str) or not protocol.strip():
            raise ValueError("protocol must be a non-empty string")
        for field in _OPTIONAL:
            if record.get(field) is not None and not isinstance(record[field], str):
                raise ValueError(f"{field} must be a string")
    except (TypeError, ValueError) as exc:
        return None, ParseDiagnostic(line_number, raw, f"invalid network record: {exc}")

    process_name = record.get("process_name")
    username = record.get("username")
    hostname = record.get("hostname")
    direction = record.get("direction")
    return SecurityEvent(
        timestamp=timestamp,
        source="network_connection",
        event_type="network_connection",
        hostname=hostname,
        process=process_name,
        username=username,
        source_ip=source_ip,
        message=f"{protocol} connection {source_ip}:{source_port} -> {destination_ip}:{destination_port}",
        raw=raw,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        protocol=protocol,
        process_name=process_name,
        direction=direction,
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

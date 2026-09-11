"""Safe parser for newline-delimited JSON DNS query records."""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple

from ..events import SecurityEvent
from .linux_auth import ParseDiagnostic

_REQUIRED = ("timestamp", "hostname", "query", "query_type")
_OPTIONAL_STRINGS = ("hostname", "username", "process_name", "direction")


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


def _resolved_ip(value: object) -> Optional[str]:
    if value is None:
        return None
    text = _text(value, "resolved_ip")
    try:
        ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError("resolved_ip is not a valid IP address") from exc
    return text


def _port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        raise ValueError("source_port must be an integer from 0 to 65535")
    return value


def parse_line(raw_line: str, line_number: int = 1) -> Tuple[Optional[SecurityEvent], Optional[ParseDiagnostic]]:
    raw = raw_line.rstrip("\r\n")
    if not raw.strip():
        return None, ParseDiagnostic(line_number, raw, "missing DNS record")
    try:
        record = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, ParseDiagnostic(line_number, raw, "malformed DNS JSON")
    if not isinstance(record, dict):
        return None, ParseDiagnostic(line_number, raw, "DNS record must be a JSON object")
    missing = [field for field in _REQUIRED if field not in record or record[field] is None]
    if missing:
        return None, ParseDiagnostic(line_number, raw, "DNS record is missing: " + ", ".join(missing))
    try:
        timestamp = _timestamp(record["timestamp"])
        hostname = _text(record["hostname"], "hostname")
        query_value = record.get("query", record.get("query_name"))
        query = _text(query_value, "query")
        query_type = _text(record["query_type"], "query_type")
        response_code = record.get("response_code")
        if response_code is not None:
            response_code = _text(response_code, "response_code")
        answer_values = record.get("answers", [])
        if not isinstance(answer_values, list) or any(not isinstance(item, str) for item in answer_values):
            raise ValueError("answers must be a list of strings")
        resolved_ip = _resolved_ip(record.get("resolved_ip"))
        if resolved_ip is None:
            for answer in answer_values:
                try:
                    resolved_ip = _resolved_ip(answer)
                    break
                except ValueError:
                    continue
        source_ip = record.get("source_ip")
        if source_ip is not None:
            if not isinstance(source_ip, str):
                raise ValueError("source_ip must be a string")
            try:
                ipaddress.ip_address(source_ip)
            except ValueError as exc:
                raise ValueError("source_ip is not a valid IP address") from exc
        source_port = record.get("source_port")
        if source_port is not None:
            source_port = _port(source_port)
        for field in _OPTIONAL_STRINGS:
            if record.get(field) is not None and not isinstance(record[field], str):
                raise ValueError(f"{field} must be a string")
    except (TypeError, ValueError) as exc:
        return None, ParseDiagnostic(line_number, raw, f"invalid DNS record: {exc}")
    username = record.get("username")
    process_name = record.get("process_name")
    direction = record.get("direction")
    return SecurityEvent(
        timestamp=timestamp, source="dns_query", event_type="dns_query",
        hostname=hostname, process=process_name, username=username, source_ip=source_ip,
        message=f"DNS query {query} ({query_type}) -> {response_code}", raw=raw,
        process_name=process_name, direction=direction, source_port=source_port, query=query,
        query_type=query_type, response_code=response_code, resolved_ip=resolved_ip,
        query_name=query, answers=list(answer_values),
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

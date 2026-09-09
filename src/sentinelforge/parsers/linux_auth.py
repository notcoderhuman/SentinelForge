"""Parser for the documented SentinelForge Linux auth fixture format."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple

from ..events import SecurityEvent

LOGGER = logging.getLogger(__name__)
# The controlled fixture uses ISO UTC timestamps and a syslog-like remainder.
LINE_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) "
    r"(?P<hostname>\S+) (?P<process>sshd|sudo)(?:\[(?P<pid>\d+)\])?: "
    r"(?P<message>.+)$"
)
IP_PATTERN = re.compile(r"\b(?:from\s+|rhost=)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")
USER_PATTERNS = (
    re.compile(r"invalid user\s+(?P<user>[A-Za-z0-9_.-]+)", re.IGNORECASE),
    re.compile(r"for\s+(?P<user>[A-Za-z0-9_.-]+)"),
    re.compile(r"user=(?P<user>[A-Za-z0-9_.-]+)"),
)


class ParseDiagnostic:
    """A safe diagnostic for a line that could not become an event."""

    def __init__(self, line_number: int, raw: str, reason: str) -> None:
        self.line_number = line_number
        self.raw = raw
        self.reason = reason

    def to_dict(self) -> dict:
        return {"line_number": self.line_number, "reason": self.reason, "raw": self.raw}


def _parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _classify(process: str, message: str) -> Optional[Tuple[str, Optional[str]]]:
    lowered = message.lower()
    if process == "sudo" and "command=" in lowered:
        return "sudo_activity", None
    if "failed password" in lowered:
        return "authentication_failure", "ssh"
    if "invalid user" in lowered:
        return "authentication_failure", "ssh"
    if "accepted password" in lowered:
        return "authentication_success", "ssh"
    return None


def parse_line(raw_line: str, line_number: int = 1) -> Tuple[Optional[SecurityEvent], Optional[ParseDiagnostic]]:
    """Parse one controlled-format line, returning an event or diagnostic."""
    raw = raw_line.rstrip("\r\n")
    match = LINE_PATTERN.match(raw)
    if not match:
        return None, ParseDiagnostic(line_number, raw, "line does not match supported auth format")
    process = match.group("process")
    message = match.group("message")
    classification = _classify(process, message)
    if classification is None:
        return None, ParseDiagnostic(line_number, raw, "unsupported authentication message")
    event_type, _ = classification
    username = None
    for user_pattern in USER_PATTERNS:
        user_match = user_pattern.search(message)
        if user_match:
            username = user_match.group("user")
            break
    ip_match = IP_PATTERN.search(message)
    event = SecurityEvent(
        timestamp=_parse_timestamp(match.group("timestamp")),
        source="linux-auth",
        event_type=event_type,
        hostname=match.group("hostname"),
        process=process,
        username=username,
        source_ip=ip_match.group("ip") if ip_match else None,
        message=message,
        raw=raw,
    )
    return event, None


def parse_lines(lines: Iterable[str]) -> Tuple[List[SecurityEvent], List[ParseDiagnostic]]:
    """Parse lines without aborting on malformed or unsupported input."""
    events: List[SecurityEvent] = []
    diagnostics: List[ParseDiagnostic] = []
    for line_number, line in enumerate(lines, start=1):
        event, diagnostic = parse_line(line, line_number)
        if event is not None:
            events.append(event)
        if diagnostic is not None:
            diagnostics.append(diagnostic)
            LOGGER.debug("Skipped auth line %s: %s", line_number, diagnostic.reason)
    return events, diagnostics


def parse_file(path: str) -> Tuple[List[SecurityEvent], List[ParseDiagnostic]]:
    """Read an explicitly supplied UTF-8 fixture path and parse it."""
    with open(path, "r", encoding="utf-8", errors="replace") as input_file:
        return parse_lines(input_file)

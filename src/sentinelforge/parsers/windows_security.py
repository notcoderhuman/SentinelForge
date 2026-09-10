"""Parser for a controlled subset of Windows Security Event XML."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Tuple

from ..events import SecurityEvent
from .linux_auth import ParseDiagnostic

SUPPORTED_EVENT_TYPES = {"4624": "authentication_success", "4625": "authentication_failure", "4672": "privileged_logon"}
_WINDOWS_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"


def _text(element: Optional[ET.Element]) -> Optional[str]:
    return element.text.strip() if element is not None and element.text else None


def _find(root: ET.Element, path: str) -> Optional[ET.Element]:
    names = [part.removeprefix("w:") for part in path.split("/")]
    if names and names[0] == root.tag.rsplit("}", 1)[-1]:
        names = names[1:]
    current = root
    for name in names:
        current = next((child for child in current if child.tag.rsplit("}", 1)[-1] == name), None)
        if current is None:
            return None
    return current


def _data(root: ET.Element, name: str) -> Optional[str]:
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "Data" and element.attrib.get("Name") == name:
            return _text(element)
    return None


def _timestamp(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    return parsed.astimezone(timezone.utc)


def _event_id(root: ET.Element) -> Optional[str]:
    return _text(_find(root, "w:Event/w:System/w:EventID"))


def parse_event(raw: str, event_number: int = 1) -> Tuple[Optional[SecurityEvent], Optional[ParseDiagnostic]]:
    """Parse one Windows event XML document without executing embedded content."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None, ParseDiagnostic(event_number, raw, "malformed Windows Security Event XML")
    event_id = _event_id(root)
    event_type = SUPPORTED_EVENT_TYPES.get(event_id or "")
    if event_type is None:
        return None, ParseDiagnostic(event_number, raw, "unsupported Windows Security Event ID")
    timestamp_text = _find(root, "w:Event/w:System/w:TimeCreated")
    timestamp_value = timestamp_text.attrib.get("SystemTime") if timestamp_text is not None else None
    computer = _text(_find(root, "w:Event/w:System/w:Computer"))
    if not timestamp_value or not computer:
        return None, ParseDiagnostic(event_number, raw, "Windows event is missing timestamp or computer")
    username = _data(root, "TargetUserName") or _data(root, "SubjectUserName")
    source_ip = _data(root, "IpAddress")
    if source_ip == "-":
        source_ip = None
    if not username:
        return None, ParseDiagnostic(event_number, raw, "Windows event is missing username")
    provider = _find(root, "w:Event/w:System/w:Provider")
    process = provider.attrib.get("Name") if provider is not None else None
    message = f"Windows Security Event {event_id} for {username}"
    return SecurityEvent(
        timestamp=_timestamp(timestamp_value), source="windows-security", event_type=event_type,
        hostname=computer, process=process, username=username, source_ip=source_ip,
        message=message, raw=raw, event_id=event_id,
    ), None


def parse_events(documents: Iterable[str]) -> Tuple[List[SecurityEvent], List[ParseDiagnostic]]:
    """Parse explicitly supplied XML documents separated by blank lines."""
    events: List[SecurityEvent] = []
    diagnostics: List[ParseDiagnostic] = []
    for index, document in enumerate(documents, start=1):
        if not document.strip():
            continue
        event, diagnostic = parse_event(document, index)
        if event is not None:
            events.append(event)
        if diagnostic is not None:
            diagnostics.append(diagnostic)
    return events, diagnostics


def parse_file(path: str) -> Tuple[List[SecurityEvent], List[ParseDiagnostic]]:
    """Read one local XML fixture and parse its event documents."""
    with open(path, "r", encoding="utf-8", errors="replace") as input_file:
        content = input_file.read()
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return [], [ParseDiagnostic(1, content, "malformed Windows Security Event XML")]
    event_elements = [element for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "Event"]
    if not event_elements:
        event_elements = [root]
    original_events = re.findall(r"<Event(?:\s[^>]*)?>.*?</Event>", content, flags=re.DOTALL)
    events: List[SecurityEvent] = []
    diagnostics: List[ParseDiagnostic] = []
    for index, element in enumerate(event_elements, start=1):
        raw_event = original_events[index - 1] if index <= len(original_events) else ET.tostring(element, encoding="unicode")
        event, diagnostic = parse_event(raw_event, index)
        if event is not None:
            events.append(event)
        if diagnostic is not None:
            diagnostics.append(diagnostic)
    return events, diagnostics

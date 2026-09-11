"""Conservative observable extraction from normalized security events."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List

from .events import SecurityEvent
from .observables import Observable, create_observable

DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_PATTERN = re.compile(r"https?://[^\s]+")
USERNAME_PATTERN = re.compile(r"\b(?:user=|for\s+)([A-Za-z0-9_.-]+)")


def _add_observable(observables: dict[tuple[str, str, str], Observable], event: SecurityEvent,
                    observable_type: str, value: str, provenance: str) -> None:
    observable = create_observable(observable_type, value, event.source,
                                   event.timestamp, provenance)
    observables[(observable.observable_type, observable.value, observable.provenance)] = observable


def extract_observables(events: Iterable[SecurityEvent]) -> List[Observable]:
    """Extract supported observables without modifying source events."""
    extracted: dict[tuple[str, str, str], Observable] = {}
    for event in events:
        for field_name, provenance in (("source_ip", "event.source_ip"), ("destination_ip", "event.destination_ip")):
            address_value = getattr(event, field_name, None)
            if address_value:
                try:
                    address = ipaddress.ip_address(address_value)
                except ValueError:
                    address = None
                if address is not None:
                    address_type = "ipv4" if address.version == 4 else "ipv6"
                    _add_observable(extracted, event, address_type, str(address), provenance)
        if event.username:
            _add_observable(extracted, event, "username", event.username, "event.username")
        if event.event_type == "file_activity" and event.path:
            _add_observable(extracted, event, "file_path", event.path, "event.path")
        query = getattr(event, "query", None)
        if query:
            _add_observable(extracted, event, "domain", query.strip().lower().rstrip("."), "event.query")
        for match in URL_PATTERN.finditer(event.message):
            _add_observable(extracted, event, "url", match.group(0).rstrip(".,"), "event.message")
        message_without_urls = URL_PATTERN.sub("", event.message)
        for match in DOMAIN_PATTERN.finditer(message_without_urls):
            _add_observable(extracted, event, "domain", match.group(0).lower(), "event.message")
        for match in USERNAME_PATTERN.finditer(event.message):
            _add_observable(extracted, event, "username", match.group(1), "event.message")
    return sorted(extracted.values(), key=lambda item: (item.observable_type, item.value, item.timestamp, item.observable_id))

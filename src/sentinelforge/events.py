"""Normalized security event model."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class SecurityEvent:
    """A normalized event while retaining the original source evidence.

    ``timestamp`` must be timezone-aware UTC. Optional fields remain ``None``
    when the source did not provide them; the model never invents values.
    """

    timestamp: datetime
    source: str
    event_type: str
    hostname: Optional[str]
    process: Optional[str]
    username: Optional[str]
    source_ip: Optional[str]
    message: str
    raw: str
    event_id: Optional[str] = None
    # Network-specific normalized attributes.  They are optional so existing
    # source parsers and callers remain backwards compatible.
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None
    executable_path: Optional[str] = None
    privilege: Optional[str] = None
    direction: Optional[str] = None
    # System persistence normalized attributes. Optional for backwards compatibility.
    persistence_type: Optional[str] = None
    persistence_action: Optional[str] = None
    persistence_name: Optional[str] = None
    command: Optional[str] = None
    service_manager: Optional[str] = None
    task_path: Optional[str] = None
    # DNS-specific normalized attributes. Optional for backwards compatibility.
    query: Optional[str] = None
    query_type: Optional[str] = None
    response_code: Optional[str] = None
    resolved_ip: Optional[str] = None
    # DNS source compatibility fields (query_name/answers are source aliases).
    query_name: Optional[str] = None
    answers: list[str] = field(default_factory=list)
    # File activity normalized attributes. Optional for backwards compatibility.
    path: Optional[str] = None
    action: Optional[str] = None
    file_hash: Optional[str] = None
    old_path: Optional[str] = None
    size: Optional[int] = None

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        if not self.source or not self.event_type or not self.message or not self.raw:
            raise ValueError("source, event_type, message, and raw are required")

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly dictionary representation."""
        values = asdict(self)
        values["timestamp"] = self.timestamp.isoformat().replace("+00:00", "Z")
        if self.event_id is None:
            values.pop("event_id")
        for field in ("source_port", "destination_ip", "destination_port", "protocol", "process_name", "process_id", "parent_process_id", "command_line", "executable_path", "privilege", "direction", "persistence_type", "persistence_action", "persistence_name", "command", "service_manager", "task_path", "query", "query_type", "response_code", "resolved_ip", "query_name", "path", "action", "file_hash", "old_path", "size"):
            if values[field] is None or (field in {"path", "action", "file_hash", "old_path", "persistence_type", "persistence_action", "persistence_name", "command", "service_manager", "task_path"} and values[field] == ""):
                values.pop(field)
        if not values["answers"]:
            values.pop("answers")
        return values

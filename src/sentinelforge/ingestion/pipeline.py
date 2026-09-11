"""Orchestration between local readers and source-specific parsers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List, Sequence, Tuple

from ..events import SecurityEvent
from ..parsers.linux_auth import ParseDiagnostic, parse_lines
from ..parsers.network import parse_lines as parse_network_lines
from ..parsers.dns import parse_lines as parse_dns_lines
from ..parsers.process import parse_lines as parse_process_lines
from ..parsers.windows_security import parse_events as parse_windows_events, parse_file as parse_windows_file
from .reader import SourcePath, read_lines, read_sources


LineParser = Callable[[Iterable[str]], Tuple[List[SecurityEvent], List[ParseDiagnostic]]]


def parser_for_source(source: str) -> LineParser:
    """Return an explicitly selected parser for a supported source."""
    if source == "linux_auth":
        return parse_lines
    if source == "windows_security":
        return parse_windows_events
    if source == "network_connection":
        return parse_network_lines
    if source == "process_execution":
        return parse_process_lines
    if source in {"dns_query", "dns"}:
        return parse_dns_lines
    if source == "network":
        return parse_network_lines
    raise ValueError(f"unsupported source: {source}")


@dataclass(frozen=True)
class IngestionResult:
    """Normalized events and diagnostics produced by one ingestion operation."""

    events: List[SecurityEvent]
    diagnostics: List[ParseDiagnostic]


def ingest_lines(lines: Iterable[str], parser: LineParser = parse_lines) -> IngestionResult:
    """Parse supplied lines through a source-specific parser."""
    events, diagnostics = parser(lines)
    return IngestionResult(events=events, diagnostics=diagnostics)


def ingest_file(source_path: SourcePath, parser: LineParser = parse_lines, source: str = "linux_auth") -> IngestionResult:
    """Read one local source and pass its lines to the selected parser."""
    if source == "windows_security":
        events, diagnostics = parse_windows_file(source_path)
        return IngestionResult(events=events, diagnostics=diagnostics)
    if parser is parse_lines and source != "linux_auth":
        parser = parser_for_source(source)
    return ingest_lines(read_lines(source_path), parser=parser)


def ingest_files(source_paths: Sequence[SourcePath], parser: LineParser = parse_lines) -> IngestionResult:
    """Read multiple local sources in order and parse their combined lines."""
    return ingest_lines(read_sources(source_paths), parser=parser)

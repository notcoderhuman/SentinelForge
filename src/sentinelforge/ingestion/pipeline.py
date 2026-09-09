"""Orchestration between local readers and source-specific parsers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List, Sequence, Tuple

from ..events import SecurityEvent
from ..parsers.linux_auth import ParseDiagnostic, parse_lines
from .reader import SourcePath, read_lines, read_sources


LineParser = Callable[[Iterable[str]], Tuple[List[SecurityEvent], List[ParseDiagnostic]]]


@dataclass(frozen=True)
class IngestionResult:
    """Normalized events and diagnostics produced by one ingestion operation."""

    events: List[SecurityEvent]
    diagnostics: List[ParseDiagnostic]


def ingest_lines(lines: Iterable[str], parser: LineParser = parse_lines) -> IngestionResult:
    """Parse supplied lines through a source-specific parser."""
    events, diagnostics = parser(lines)
    return IngestionResult(events=events, diagnostics=diagnostics)


def ingest_file(source_path: SourcePath, parser: LineParser = parse_lines) -> IngestionResult:
    """Read one local source and pass its lines to the selected parser."""
    return ingest_lines(read_lines(source_path), parser=parser)


def ingest_files(source_paths: Sequence[SourcePath], parser: LineParser = parse_lines) -> IngestionResult:
    """Read multiple local sources in order and parse their combined lines."""
    return ingest_lines(read_sources(source_paths), parser=parser)

"""Safe local text-source reading for the ingestion pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator, Union


SourcePath = Union[str, Path]


def read_lines(source_path: SourcePath) -> Iterator[str]:
    """Yield UTF-8 text lines from an explicitly supplied local file.

    Invalid byte sequences are replaced so one damaged line cannot abort the
    whole ingestion operation. The reader does not interpret or execute text.
    """
    path = Path(source_path)
    with path.open("r", encoding="utf-8", errors="replace") as input_file:
        yield from input_file


def read_sources(source_paths: Iterable[SourcePath]) -> Iterator[str]:
    """Yield lines from local files in the caller-provided order."""
    for source_path in source_paths:
        yield from read_lines(source_path)

"""Local source reading and parser orchestration for SentinelForge."""

from .pipeline import IngestionResult, ingest_file, ingest_files, ingest_lines

__all__ = ["IngestionResult", "ingest_file", "ingest_files", "ingest_lines"]

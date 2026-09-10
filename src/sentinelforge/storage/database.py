"""SQLite database boundary for SentinelForge persistence."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Union

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(run_id) ON DELETE SET NULL,
    timestamp TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(run_id) ON DELETE SET NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    note_id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_run ON alerts(run_id);
CREATE INDEX IF NOT EXISTS idx_incidents_run ON incidents(run_id);
CREATE INDEX IF NOT EXISTS idx_investigations_incident ON investigations(incident_id);
CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON evidence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_notes_investigation ON notes(investigation_id);
"""

class Database:
    """Connection owner with foreign keys, schema versioning, and transactions."""
    def __init__(self, path: Union[str, Path] = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self._initialize()

    def _initialize(self) -> None:
        with self.transaction() as conn:
            conn.executescript(_SCHEMA)
            row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            if row is None:
                conn.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
            elif row[0] != SCHEMA_VERSION:
                raise RuntimeError(f"unsupported database schema version: {row[0]}")

    @property
    def schema_version(self) -> int:
        return int(self.connection.execute("SELECT version FROM schema_version").fetchone()[0])

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Commit on success and roll back atomically on failure."""
        nested = self.connection.in_transaction
        savepoint = "sentinelforge_nested"
        try:
            self.connection.execute(f"SAVEPOINT {savepoint}" if nested else "BEGIN")
            yield self.connection
        except Exception:
            if nested:
                self.connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            else:
                self.connection.rollback()
            raise
        else:
            if nested:
                self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            else:
                self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

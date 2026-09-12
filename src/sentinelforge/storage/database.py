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
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'viewer')),
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE, csrf_token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL,
    action TEXT NOT NULL, resource TEXT, resource_id TEXT, details TEXT NOT NULL,
    ip_address TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
"""

class Database:
    """Connection owner with foreign keys, schema versioning, and transactions."""
    def __init__(self, path: Union[str, Path] = ":memory:", *, uri: bool = False) -> None:
        self.path = str(path)
        self.uri = uri or self.path.startswith("file:")
        self.connection = sqlite3.connect(self.path, timeout=5.0, uri=self.uri)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self._initialize()

    def _initialize(self) -> None:
        with self.transaction() as conn:
            conn.executescript(_SCHEMA)
            row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            if row is None:
                conn.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
            elif row[0] == 1:
                # The CREATE IF NOT EXISTS statements above are the additive v2 migration.
                conn.execute("UPDATE schema_version SET version=?", (SCHEMA_VERSION,))
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

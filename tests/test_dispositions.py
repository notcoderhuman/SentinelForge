import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from pathlib import Path

from sentinelforge.alerts import create_alert
from sentinelforge.dispositions import AlertDisposition, MAX_REASON_BYTES
from sentinelforge.events import SecurityEvent
from sentinelforge.storage import AnalysisRepository, Database
from sentinelforge.storage.database import _DISPOSITION_SCHEMA


V1_SCHEMA = """
CREATE TABLE schema_version (version INTEGER NOT NULL);
CREATE TABLE runs (run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(run_id) ON DELETE SET NULL, timestamp TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE incidents (incident_id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(run_id) ON DELETE SET NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE investigations (investigation_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE, timestamp TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE notes (note_id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE, timestamp TEXT NOT NULL, payload TEXT NOT NULL);
CREATE INDEX idx_alerts_run ON alerts(run_id);
CREATE INDEX idx_incidents_run ON incidents(run_id);
CREATE INDEX idx_investigations_incident ON investigations(incident_id);
CREATE INDEX idx_evidence_investigation ON evidence(investigation_id);
CREATE INDEX idx_notes_investigation ON notes(investigation_id);
CREATE TABLE users (user_id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'viewer')), active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE sessions (session_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, csrf_token_hash TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE audit_log (audit_id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(user_id) ON DELETE SET NULL, action TEXT NOT NULL, resource TEXT, resource_id TEXT, details TEXT NOT NULL, ip_address TEXT, created_at TEXT NOT NULL);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);
CREATE INDEX idx_audit_created ON audit_log(created_at);
"""


class DispositionTests(unittest.TestCase):
    def setUp(self):
        self.event = SecurityEvent(datetime(2025, 1, 1, tzinfo=timezone.utc), "x", "x", None, None, "alice", None, "m", "raw")
        self.alert = create_alert("RULE", "low", "title", "description", [self.event])

    def _repository(self):
        db = Database(":memory:")
        db.connection.execute(
            "INSERT INTO users(user_id, username, password_hash, role, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("user-1", "analyst", "hash", "analyst", 1, "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z"),
        )
        repo = AnalysisRepository(db)
        repo.save_run("run-1", {"run_id": "run-1", "started_at": "2025-01-01T00:00:00Z"})
        repo.save_alert(self.alert, "run-1")
        return db, repo

    def _disposition(self, **changes):
        values = dict(
            disposition_id="d-1", alert_id=self.alert.alert_id, incident_id=None,
            actor_user_id="user-1", created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            disposition="benign", reason="Reviewed and expected.", rule_id="RULE",
            rule_fingerprint=None, engine_configuration_fingerprint=None,
            run_id=None, idempotency_key=None,
        )
        values.update(changes)
        return AlertDisposition(**values)

    def test_vocabulary_and_reason_validation(self):
        for value in ("true_positive", "benign", "duplicate", "inconclusive"):
            self.assertEqual(self._disposition(disposition=value).disposition, value)
        with self.assertRaises(ValueError):
            self._disposition(disposition="false_positive")
        with self.assertRaises(ValueError):
            self._disposition(reason="")
        with self.assertRaises(ValueError):
            self._disposition(reason=" \n\t")
        self.assertEqual(len(self._disposition(reason="é" * (MAX_REASON_BYTES // 2)).reason.encode("utf-8")), MAX_REASON_BYTES)
        with self.assertRaises(ValueError):
            self._disposition(reason="é" * (MAX_REASON_BYTES // 2) + "a")
        with self.assertRaises(ValueError):
            self._disposition(reason="a" * (MAX_REASON_BYTES + 1))

    def test_schema_version_table_indexes_and_idempotent_open(self):
        with Database(":memory:") as db:
            self.assertEqual(db.schema_version, 2)
            columns = {row["name"] for row in db.connection.execute("PRAGMA table_info(alert_dispositions)")}
            self.assertEqual(columns, {"disposition_id", "alert_id", "incident_id", "actor_user_id", "created_at", "disposition", "reason", "rule_id", "rule_fingerprint", "engine_configuration_fingerprint", "run_id", "idempotency_key"})
            indexes = {row["name"] for row in db.connection.execute("PRAGMA index_list(alert_dispositions)")}
            self.assertTrue({"uq_alert_dispositions_actor_key", "idx_alert_dispositions_alert_history", "idx_alert_dispositions_incident", "idx_alert_dispositions_rule_provenance"} <= indexes)
        path = Path(tempfile.mktemp(suffix="-legacy.db"))
        try:
            connection = sqlite3.connect(path)
            connection.executescript(V1_SCHEMA)
            connection.execute("INSERT INTO schema_version VALUES (1)")
            connection.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)", ("legacy-user", "legacy", "hash", "viewer", 1, "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z"))
            connection.execute("INSERT INTO runs VALUES (?, ?, ?)", ("legacy-run", "2025-01-01T00:00:00Z", '{"run_id":"legacy-run"}'))
            connection.execute("INSERT INTO alerts VALUES (?, ?, ?, ?)", ("legacy-alert", "legacy-run", "2025-01-01T00:00:00Z", '{"alert_id":"legacy-alert","rule_id":"R"}'))
            connection.commit()
            connection.close()
            with Database(path) as db:
                self.assertEqual(db.schema_version, 2)
                self.assertEqual(db.connection.execute("SELECT payload FROM runs WHERE run_id='legacy-run'").fetchone()[0], '{"run_id":"legacy-run"}')
                self.assertEqual(db.connection.execute("SELECT payload FROM alerts WHERE alert_id='legacy-alert'").fetchone()[0], '{"alert_id":"legacy-alert","rule_id":"R"}')
                self.assertIsNotNone(db.connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alert_dispositions'").fetchone())
            with Database(path) as db:
                self.assertEqual(db.schema_version, 2)
        finally:
            path.unlink(missing_ok=True)

    def test_migration_failure_rolls_back_all_partial_changes(self):
        path = Path(tempfile.mktemp(suffix="-rollback.db"))
        try:
            connection = sqlite3.connect(path)
            connection.executescript(V1_SCHEMA)
            connection.execute("INSERT INTO schema_version VALUES (1)")
            connection.execute("INSERT INTO runs VALUES (?, ?, ?)", ("run", "2025-01-01T00:00:00Z", "original"))
            connection.commit()
            connection.close()
            original_execute = Database._execute_statements

            def fail_after_first_migration_statement(connection, statements):
                if statements == _DISPOSITION_SCHEMA:
                    connection.execute(statements[0])
                    raise sqlite3.OperationalError("controlled migration failure")
                return original_execute(connection, statements)

            with patch.object(Database, "_execute_statements", staticmethod(fail_after_first_migration_statement)):
                with self.assertRaises(sqlite3.OperationalError):
                    Database(path)
            connection = sqlite3.connect(path)
            self.assertEqual(connection.execute("SELECT version FROM schema_version").fetchone()[0], 1)
            self.assertIsNone(connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='alert_dispositions'").fetchone())
            self.assertEqual(connection.execute("SELECT payload FROM runs WHERE run_id='run'").fetchone()[0], "original")
            connection.close()
        finally:
            path.unlink(missing_ok=True)

    def test_foreign_keys_reject_unknown_references(self):
        db, repo = self._repository()
        try:
            base = dict(alert_id=self.alert.alert_id, actor_user_id="user-1", disposition="benign", reason="reason", rule_id="RULE")
            for field, value in (("alert_id", "missing-alert"), ("actor_user_id", "missing-user"), ("incident_id", "missing-incident"), ("run_id", "missing-run")):
                with self.assertRaises(sqlite3.IntegrityError, msg=field):
                    repo.create_disposition(**(base | {field: value}))
        finally:
            db.close()

    def test_equal_timestamp_ordering_uses_disposition_id(self):
        db, repo = self._repository()
        try:
            timestamp = datetime(2025, 1, 1, tzinfo=timezone.utc)
            low = self._disposition(disposition_id="d-1", created_at=timestamp)
            high = self._disposition(disposition_id="d-2", created_at=timestamp, disposition="true_positive")
            repo.save_disposition(high)
            repo.save_disposition(low)
            self.assertEqual(repo.get_current_disposition(self.alert.alert_id).disposition_id, "d-2")
            self.assertEqual([item.disposition_id for item in repo.list_disposition_history(self.alert.alert_id)], ["d-1", "d-2"])
        finally:
            db.close()

    def test_earlier_record_is_unchanged_after_later_append(self):
        db, repo = self._repository()
        try:
            first = repo.save_disposition(self._disposition())
            first_snapshot = first.to_dict()
            repo.save_disposition(self._disposition(disposition_id="d-2", created_at=datetime(2025, 1, 2, tzinfo=timezone.utc), disposition="duplicate", reason="Later review."))
            self.assertEqual(repo.get_disposition(first.disposition_id).to_dict(), first_snapshot)
            self.assertEqual([item.disposition_id for item in repo.list_disposition_history(self.alert.alert_id)], ["d-1", "d-2"])
        finally:
            db.close()

    def test_append_current_history_and_alert_unchanged(self):
        db, repo = self._repository()
        try:
            before = repo.get_payload("alerts", self.alert.alert_id)
            first = repo.save_disposition(self._disposition())
            second = repo.save_disposition(self._disposition(disposition_id="d-2", disposition="true_positive", reason="Later review.", created_at=datetime(2025, 1, 2, tzinfo=timezone.utc), rule_fingerprint="rf", engine_configuration_fingerprint="ef", run_id="run-1", incident_id=None))
            self.assertEqual(repo.get_current_disposition(self.alert.alert_id), second)
            self.assertEqual([item.disposition_id for item in repo.list_disposition_history(self.alert.alert_id)], [first.disposition_id, second.disposition_id])
            self.assertEqual(repo.get_payload("alerts", self.alert.alert_id), before)
            self.assertEqual(repo.get_alert(self.alert.alert_id).alert_id, self.alert.alert_id)
            self.assertEqual(repo.get_disposition("d-1"), first)
        finally:
            db.close()

    def test_nullable_context_and_idempotency_scope(self):
        db, repo = self._repository()
        try:
            repo.save_disposition(self._disposition(idempotency_key="retry"))
            with self.assertRaises(sqlite3.IntegrityError):
                repo.save_disposition(self._disposition(disposition_id="d-2", idempotency_key="retry"))
            db.connection.execute("INSERT INTO users(user_id, username, password_hash, role, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)", ("user-2", "analyst2", "hash", "analyst", 1, "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z"))
            second = repo.save_disposition(self._disposition(disposition_id="d-3", actor_user_id="user-2", idempotency_key="retry", incident_id=None, rule_fingerprint=None, engine_configuration_fingerprint=None, run_id=None))
            self.assertEqual(second.actor_user_id, "user-2")
            self.assertIsNone(second.incident_id)
        finally:
            db.close()

    def test_create_generates_id_and_timestamp_server_side(self):
        db, repo = self._repository()
        try:
            disposition = repo.create_disposition(
                alert_id=self.alert.alert_id, actor_user_id="user-1",
                disposition="inconclusive", reason="Needs more context.",
                rule_id="RULE", idempotency_key="server-key",
            )
            self.assertTrue(disposition.disposition_id)
            self.assertEqual(disposition.created_at.tzinfo, timezone.utc)
            self.assertEqual(disposition.actor_user_id, "user-1")
            self.assertNotEqual(disposition.to_dict()["reason"], disposition.disposition_id)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()

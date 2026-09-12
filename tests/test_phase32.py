"""Phase 32 secure case-management mutation tests."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
from http.client import HTTPConnection
from pathlib import Path

from sentinelforge.alerts import create_alert
from sentinelforge.api.server import SentinelHTTPServer
from sentinelforge.events import SecurityEvent
from sentinelforge.incidents import Incident
from sentinelforge.investigation_engine import create_investigation
from sentinelforge.storage import AnalysisRepository, Database
from sentinelforge.storage.repositories import InvalidCaseTransitionError
from sentinelforge.auth.service import AuthService


class Phase32Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "phase32.db")
        event = SecurityEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc), source="linux-auth",
            event_type="authentication_failure", hostname="host-1", process="sshd",
            username="alice", source_ip=None, message="failed login", raw="raw-event", event_id="event-1",
        )
        alert = create_alert("REPEATED_AUTH_FAILURE", "medium", "Repeated", "Observed", [event])
        self.incident = Incident(
            "incident-1", "Title", "Description", "medium", "open", event.timestamp,
            event.timestamp, (alert.alert_id,), ("alice",), ("host-1",), (event,),
            (alert.rule_id,), (), None, (),
        )
        self.investigation = create_investigation(self.incident)
        with Database(self.path) as db:
            repo = AnalysisRepository(db)
            repo.save_incident(self.incident)
            repo.save_investigation(self.investigation)
            AuthService(db).create_user("admin", "correct horse battery", "admin")
            AuthService(db).create_user("analyst", "correct horse battery", "analyst")
            AuthService(db).create_user("viewer", "correct horse battery", "viewer")
            self.user_ids = {name: AuthService(db).get_user_by_username(name).user_id for name in ("admin", "analyst", "viewer")}

    def tearDown(self):
        self.temp.cleanup()

    def repo(self):
        return AnalysisRepository(self.db)

    def setUpRepo(self):
        self.db = Database(self.path)

    def test_incident_lifecycle_and_noop(self):
        self.setUpRepo()
        try:
            repo = self.repo()
            current = repo.get_incident("incident-1")
            updated, changed = repo.mutate_incident_status("incident-1", "investigating", user_id=self.user_ids["analyst"], ip_address="127.0.0.1")
            self.assertTrue(changed)
            self.assertEqual(updated.status, "investigating")
            same = repo.get_incident("incident-1").updated_at
            updated, changed = repo.mutate_incident_status("incident-1", "investigating", user_id=self.user_ids["analyst"], ip_address="127.0.0.1")
            self.assertFalse(changed)
            self.assertEqual(updated.updated_at, same)
            self.assertEqual(repo.get_incident("incident-1").related_alert_ids, current.related_alert_ids)
            self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM audit_log WHERE action='incident_status_transition'").fetchone()[0], 1)
            with self.assertRaises(ValueError):
                repo.mutate_incident_status("incident-1", "open", user_id=self.user_ids["analyst"], ip_address="x")
        finally:
            self.db.close()

    def test_investigation_transition_preserves_analysis_fields(self):
        with Database(self.path) as db:
            repo = AnalysisRepository(db)
            before = repo.get_investigation(self.investigation.investigation_id).to_dict()
            noop, noop_changed = repo.mutate_investigation_status(self.investigation.investigation_id, "active", user_id=self.user_ids["analyst"], ip_address="x")
            self.assertFalse(noop_changed)
            self.assertEqual(noop.updated_at.isoformat(), before["updated_at"].replace("Z", "+00:00"))
            self.assertEqual(repo.db.connection.execute("SELECT COUNT(*) FROM audit_log WHERE action='investigation_status_transition'").fetchone()[0], 0)
            updated, changed = repo.mutate_investigation_status(self.investigation.investigation_id, "completed", user_id=self.user_ids["analyst"], ip_address="x")
            self.assertTrue(changed)
            self.assertEqual(updated.status, "completed")
            self.assertEqual(updated.evidence, repo.get_investigation(updated.investigation_id).evidence)
            with self.assertRaises(InvalidCaseTransitionError):
                repo.mutate_investigation_status(updated.investigation_id, "active", user_id=self.user_ids["analyst"], ip_address="x")
            after = repo.get_investigation(updated.investigation_id).to_dict()
            for key in ("evidence", "timeline", "analyst_notes", "risk_assessment", "correlations", "threat_context"):
                self.assertEqual(after[key], before[key])

    def test_note_is_atomic_and_consistent_after_reopen(self):
        with Database(self.path) as db:
            repo = AnalysisRepository(db)
            note = repo.append_investigation_note(self.investigation.investigation_id,
                __import__("sentinelforge.investigations", fromlist=["AnalystNote"]).AnalystNote(
                    "note-1", datetime.now(timezone.utc), "analyst", "bounded note"),
                user_id=self.user_ids["analyst"], ip_address="127.0.0.1")
            self.assertEqual(note.analyst_notes[0].content, "bounded note")
        with Database(self.path) as db:
            row = db.connection.execute("SELECT payload FROM investigations WHERE investigation_id=?", (self.investigation.investigation_id,)).fetchone()
            payload = json.loads(row[0])
            normalized = db.connection.execute("SELECT payload FROM notes WHERE investigation_id=?", (self.investigation.investigation_id,)).fetchall()
            self.assertEqual(len(normalized), 1)
            self.assertEqual(payload["analyst_notes"][0]["note_id"], "note-1")
            self.assertEqual(json.loads(normalized[0][0]), payload["analyst_notes"][0])

    def test_concurrent_notes_are_not_lost(self):
        def add(index):
            with Database(self.path) as db:
                from sentinelforge.investigations import AnalystNote
                return AnalysisRepository(db).append_investigation_note(
                    self.investigation.investigation_id,
                    AnalystNote(f"note-{index}", datetime.now(timezone.utc), "analyst", f"note {index}"),
                    user_id=self.user_ids["analyst"], ip_address="127.0.0.1")
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(add, range(6)))
        self.assertEqual(len(results), 6)
        with Database(self.path) as db:
            payload = json.loads(db.connection.execute("SELECT payload FROM investigations WHERE investigation_id=?", (self.investigation.investigation_id,)).fetchone()[0])
            self.assertEqual({x["note_id"] for x in payload["analyst_notes"]}, {f"note-{i}" for i in range(6)})
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM notes WHERE investigation_id=?", (self.investigation.investigation_id,)).fetchone()[0], 6)

    def test_save_investigation_preserves_mutable_state_and_notes(self):
        with Database(self.path) as db:
            repo = AnalysisRepository(db)
            from sentinelforge.investigations import AnalystNote
            repo.append_investigation_note(self.investigation.investigation_id, AnalystNote("note-x", datetime.now(timezone.utc), "analyst", "keep"), user_id=self.user_ids["analyst"], ip_address="x")
            repo.mutate_investigation_status(self.investigation.investigation_id, "completed", user_id=self.user_ids["analyst"], ip_address="x")
            repo.save_investigation(self.investigation)
            loaded = repo.get_investigation(self.investigation.investigation_id)
            self.assertEqual(loaded.status, "completed")
            self.assertEqual([n.note_id for n in loaded.analyst_notes], ["note-x"])

    def _server(self):
        server = SentinelHTTPServer("127.0.0.1", 0, self.path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def _login(self, server, username, password="correct horse battery"):
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        body = json.dumps({"username": username, "password": password}).encode()
        conn.request("POST", "/auth/login", body, {"Content-Type": "application/json", "Content-Length": str(len(body)), "Origin": f"http://127.0.0.1:{server.server_port}"})
        response = conn.getresponse()
        cookies = "; ".join(v.split(";", 1)[0] for k, v in response.getheaders() if k.lower() == "set-cookie")
        csrf = next((v.split(";", 1)[0].split("=", 1)[1] for k, v in response.getheaders() if k.lower() == "set-cookie" and v.startswith("sf_csrf=")), "")
        response.read(); conn.close()
        return cookies, csrf

    def _post(self, server, path, body, cookies="", csrf="", origin=True):
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        raw = json.dumps(body).encode() if body is not None else b"{"
        headers = {"Content-Type": "application/json", "Content-Length": str(len(raw)), "Cookie": cookies}
        if csrf: headers["X-CSRF-Token"] = csrf
        if origin is True: headers["Origin"] = f"http://127.0.0.1:{server.server_port}"
        elif isinstance(origin, str): headers["Origin"] = origin
        conn.request("POST", path, raw, headers)
        response = conn.getresponse(); payload = response.read(); status = response.status; conn.close()
        return status, json.loads(payload) if payload else {}

    def test_http_auth_rbac_csrf_and_actor_binding(self):
        server, thread = self._server()
        try:
            status, _ = self._post(server, "/incidents/incident-1/status", {"status": "investigating"})
            self.assertEqual(status, 401)
            cookies, csrf = self._login(server, "viewer")
            status, _ = self._post(server, "/incidents/incident-1/status", {"status": "investigating"}, cookies, csrf)
            self.assertEqual(status, 403)
            cookies, csrf = self._login(server, "analyst")
            status, payload = self._post(server, "/incidents/incident-1/status", {"status": "investigating", "user_id": "spoof"}, cookies, csrf)
            self.assertEqual(status, 400)
            status, payload = self._post(server, "/incidents/incident-1/status", {"status": "investigating"}, cookies, "")
            self.assertEqual(status, 403)
            status, payload = self._post(server, "/incidents/incident-1/status", {"status": "investigating"}, cookies, csrf, origin=False)
            self.assertEqual(status, 200)
            cookies, csrf = self._login(server, "admin")
            status, payload = self._post(server, "/incidents/incident-1/status", {"status": "resolved"}, cookies, csrf)
            self.assertEqual(status, 200)
            with Database(self.path) as db:
                audit = db.connection.execute("SELECT user_id, action, resource, resource_id, details FROM audit_log WHERE action='incident_status_transition'").fetchall()
                self.assertEqual(len(audit), 2)
                audit = [row for row in audit if row[3] == "incident-1"]
                self.assertEqual(audit[-1][0], AuthService(db).get_user_by_username("admin").user_id)
                self.assertNotIn("spoof", audit[0][4])
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def test_transaction_rollbacks_for_case_mutations(self):
        from sentinelforge.investigations import AnalystNote
        with Database(self.path) as db:
            repo = AnalysisRepository(db)
            before_incident = repo.get_incident("incident-1")
            before_investigation = repo.get_investigation(self.investigation.investigation_id)
            with patch("sentinelforge.storage.auth_repositories.AuthRepository.insert_audit", side_effect=sqlite3.IntegrityError("forced audit failure")):
                with self.assertRaises(sqlite3.IntegrityError):
                    repo.mutate_incident_status("incident-1", "investigating", user_id=self.user_ids["analyst"], ip_address="x")
                with self.assertRaises(sqlite3.IntegrityError):
                    repo.mutate_investigation_status(self.investigation.investigation_id, "completed", user_id=self.user_ids["analyst"], ip_address="x")
                with self.assertRaises(sqlite3.IntegrityError):
                    repo.append_investigation_note(self.investigation.investigation_id, AnalystNote("rollback-note", datetime.now(timezone.utc), "analyst", "must rollback"), user_id=self.user_ids["analyst"], ip_address="x")
            after_incident = repo.get_incident("incident-1")
            after_investigation = repo.get_investigation(self.investigation.investigation_id)
            self.assertEqual(after_incident.status, before_incident.status)
            self.assertEqual(after_incident.updated_at, before_incident.updated_at)
            self.assertEqual(after_investigation.status, before_investigation.status)
            self.assertEqual(after_investigation.updated_at, before_investigation.updated_at)
            self.assertEqual(after_investigation.analyst_notes, ())
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM notes").fetchone()[0], 0)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM audit_log WHERE action LIKE '%transition' OR action LIKE '%note_create'").fetchone()[0], 0)

    def test_http_initialization_lock_is_503(self):
        real_database = __import__("sentinelforge.api.server", fromlist=["Database"]).Database
        calls = {"count": 0}
        def locked_database(path):
            calls["count"] += 1
            if calls["count"] == 1:
                raise sqlite3.OperationalError("database is locked")
            return real_database(path)
        server = SentinelHTTPServer("127.0.0.1", 0, self.path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch("sentinelforge.api.server.Database", side_effect=locked_database):
                conn = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                conn.request("GET", "/health")
                response = conn.getresponse()
                self.assertEqual(response.status, 503)
                self.assertEqual(json.loads(response.read()), {"error": "database temporarily unavailable"})
                conn.close()
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def test_database_timeout_scope(self):
        with Database(self.path) as db:
            self.assertEqual(db.connection.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
            with db.transaction(immediate=True) as conn:
                self.assertEqual(conn.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
                conn.execute("SELECT 1").fetchone()
            self.assertEqual(db.connection.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
            with self.assertRaises(RuntimeError):
                with db.transaction(immediate=True) as conn:
                    self.assertEqual(conn.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
                    raise RuntimeError("rollback")
            self.assertEqual(db.connection.execute("PRAGMA busy_timeout").fetchone()[0], 5000)

    def test_http_lock_contention_is_503_without_sqlite_leak(self):
        server, thread = self._server()
        holder = Database(self.path)
        try:
            cookies, csrf = self._login(server, "analyst")
            holder.connection.execute("BEGIN IMMEDIATE")
            status, payload = self._post(server, "/incidents/incident-1/status", {"status": "investigating"}, cookies, csrf)
            self.assertEqual(status, 503)
            self.assertEqual(payload, {"error": "database temporarily unavailable"})
        finally:
            holder.connection.rollback(); holder.close()
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def test_http_unrelated_database_failure_is_generic_500(self):
        server, thread = self._server()
        try:
            cookies, csrf = self._login(server, "analyst")
            with patch("sentinelforge.storage.repositories.AnalysisRepository.mutate_incident_status", side_effect=sqlite3.OperationalError("no such table: secret_table")):
                status, payload = self._post(server, "/incidents/incident-1/status", {"status": "investigating"}, cookies, csrf)
            self.assertEqual(status, 500)
            self.assertEqual(payload, {"error": "internal server error"})
            self.assertNotIn("secret_table", json.dumps(payload))
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def test_http_security_matrix_and_resources(self):
        server, thread = self._server()
        try:
            cookies, csrf = self._login(server, "analyst")
            iid = self.investigation.investigation_id
            checks = [
                ("/incidents/no-such/status", {"status": "investigating"}, 404),
                ("/investigations/no-such/status", {"status": "completed"}, 404),
                (f"/incidents/incident-1/status", {"status": "closed"}, 409),
                (f"/investigations/{iid}/status", {"status": "bogus"}, 400),
                (f"/incidents/incident-1/status", {"status": "open"}, 200),
            ]
            for path, body, expected in checks:
                self.assertEqual(self._post(server, path, body, cookies, csrf)[0], expected)
            self.assertEqual(self._post(server, f"/investigations/{iid}/notes", {"content": "x" * (16 * 1024)}, cookies, csrf)[0], 201)
            self.assertEqual(self._post(server, f"/investigations/{iid}/notes", {"content": "x" * (16 * 1024 + 1)}, cookies, csrf)[0], 413)
            self.assertEqual(self._post(server, f"/investigations/{iid}/notes", {"content": 42}, cookies, csrf)[0], 400)
            self.assertEqual(self._post(server, f"/investigations/{iid}/notes", ["bad"], cookies, csrf)[0], 400)
            self.assertEqual(self._post(server, f"/investigations/{iid}/notes", {"content": "bad", "extra": 1}, cookies, csrf)[0], 400)
            self.assertEqual(self._post(server, f"/investigations/{iid}/notes", None, cookies, csrf)[0], 400)
            self.assertEqual(self._post(server, f"/investigations/{iid}/notes", {"content": "bad"}, cookies, csrf, origin="http://evil.invalid")[0], 403)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def test_expired_and_inactive_sessions_are_rejected(self):
        server, thread = self._server()
        try:
            cookies, csrf = self._login(server, "analyst")
            token = cookies.split("sf_session=", 1)[1].split(";", 1)[0]
            with Database(self.path) as db:
                db.connection.execute("UPDATE sessions SET expires_at=?", ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),))
                db.connection.commit()
            self.assertEqual(self._post(server, "/incidents/incident-1/status", {"status": "investigating"}, cookies, csrf)[0], 401)
            cookies, csrf = self._login(server, "analyst")
            with Database(self.path) as db:
                uid = AuthService(db).get_user_by_username("analyst").user_id
                db.connection.execute("UPDATE users SET active=0 WHERE user_id=?", (uid,)); db.connection.commit()
            self.assertEqual(self._post(server, "/incidents/incident-1/status", {"status": "investigating"}, cookies, csrf)[0], 401)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def test_real_threaded_http_concurrency_preserves_case_and_notes(self):
        server, thread = self._server()
        try:
            cookies, csrf = self._login(server, "analyst")
            def request(path, body):
                return self._post(server, path, body, cookies, csrf)
            with ThreadPoolExecutor(max_workers=2) as pool:
                incident_results = list(pool.map(lambda target: request("/incidents/incident-1/status", {"status": target}), ("investigating", "resolved")))
            self.assertTrue(all(status in {200, 409} for status, _ in incident_results))
            self.assertEqual(self._post(server, "/incidents/incident-1/status", {"status": "open"}, cookies, csrf)[0], 409)
            with Database(self.path) as db:
                self.assertIn(json.loads(db.connection.execute("SELECT payload FROM incidents WHERE incident_id='incident-1'").fetchone()[0])["status"], {"investigating", "resolved"})
                self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM audit_log WHERE action='incident_status_transition'").fetchone()[0], sum(status == 200 for status, _ in incident_results))
            with ThreadPoolExecutor(max_workers=4) as pool:
                note_results = list(pool.map(lambda i: request(f"/investigations/{self.investigation.investigation_id}/notes", {"content": f"thread-{i}"}), range(4)))
            self.assertTrue(all(status in {201, 409, 503} for status, _ in note_results))
            self.assertGreaterEqual(sum(status == 201 for status, _ in note_results), 1)
            ids = [payload["note"]["note_id"] for status, payload in note_results if status == 201]
            self.assertEqual(len(ids), len(set(ids)))
            with ThreadPoolExecutor(max_workers=2) as pool:
                investigation_results = list(pool.map(lambda _: request(f"/investigations/{self.investigation.investigation_id}/status", {"status": "completed"}), range(2)))
            self.assertTrue(all(status == 200 for status, _ in investigation_results))
            with Database(self.path) as db:
                self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM notes WHERE investigation_id=?", (self.investigation.investigation_id,)).fetchone()[0], sum(status == 201 for status, _ in note_results))
                self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM audit_log WHERE action='investigation_note_create' AND resource_id IN (SELECT note_id FROM notes WHERE investigation_id=?)", (self.investigation.investigation_id,)).fetchone()[0], sum(status == 201 for status, _ in note_results))
                self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM audit_log WHERE action='investigation_status_transition'").fetchone()[0], 1)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def test_http_note_contract_and_completed_rejection(self):
        server, thread = self._server()
        try:
            cookies, csrf = self._login(server, "analyst")
            iid = self.investigation.investigation_id
            status, payload = self._post(server, f"/investigations/{iid}/notes", {"content": "hello"}, cookies, csrf)
            self.assertEqual(status, 201)
            self.assertEqual(payload["note"]["author"], "analyst")
            self.assertEqual(len(payload["note"]["note_id"]), 32)
            status, _ = self._post(server, f"/investigations/{iid}/notes", {"content": " "}, cookies, csrf)
            self.assertEqual(status, 400)
            status, _ = self._post(server, f"/investigations/{iid}/notes", {"content": "x" * (16 * 1024 + 1)}, cookies, csrf)
            self.assertEqual(status, 413)
            status, _ = self._post(server, f"/investigations/{iid}/notes", {"content": "x", "author": "spoof"}, cookies, csrf)
            self.assertEqual(status, 400)
            status, _ = self._post(server, f"/investigations/{iid}/notes", {"content": "{"}, cookies, csrf)
            self.assertEqual(status, 201)
            status, _ = self._post(server, f"/investigations/{iid}/status", {"status": "completed"}, cookies, csrf)
            self.assertEqual(status, 200)
            status, _ = self._post(server, f"/investigations/{iid}/notes", {"content": "late"}, cookies, csrf)
            self.assertEqual(status, 409)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

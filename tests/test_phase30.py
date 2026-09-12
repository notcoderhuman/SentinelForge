"""Phase 30 server-side query and bounded-list regression tests."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from sentinelforge.api.server import ApiOperations
from sentinelforge.storage import AnalysisRepository, Database


class Phase30QueryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = str(Path(self.directory.name) / "query.db")
        with Database(self.path) as db:
            connection = db.connection
            connection.executemany(
                "INSERT INTO runs(run_id, created_at, payload) VALUES (?, ?, ?)",
                [("run-old", "2025-01-01T00:00:00Z", json.dumps({"run_id": "run-old", "source": "linux_auth"})),
                 ("run-new", "2025-01-02T00:00:00Z", json.dumps({"run_id": "run-new", "source": "network_connection"}))],
            )
            connection.executemany(
                "INSERT INTO alerts(alert_id, run_id, timestamp, payload) VALUES (?, ?, ?, ?)",
                [("alert-old", "run-old", "2025-01-01T00:00:00Z", json.dumps({"alert_id": "alert-old", "rule_id": "RULE_OLD", "severity": "low", "source": "linux_auth", "timestamp": "2025-01-01T00:00:00Z"})),
                 ("alert-new", "run-new", "2025-01-02T00:00:00Z", json.dumps({"alert_id": "alert-new", "rule_id": "RULE_NEW", "severity": "high", "source": "network_connection", "timestamp": "2025-01-02T00:00:00Z"}))],
            )
            connection.executemany(
                "INSERT INTO incidents(incident_id, run_id, created_at, updated_at, payload) VALUES (?, ?, ?, ?, ?)",
                [("incident-low", "run-old", "2025-01-01T00:00:00Z", "2025-01-01T01:00:00Z", json.dumps({"incident_id": "incident-low", "severity": "low", "status": "open", "risk_assessment": {"score": 20, "level": "low"}})),
                 ("incident-high", "run-new", "2025-01-02T00:00:00Z", "2025-01-02T01:00:00Z", json.dumps({"incident_id": "incident-high", "severity": "high", "status": "investigating", "risk_assessment": {"score": 80, "level": "critical"}}))],
            )
            connection.executemany(
                "INSERT INTO investigations(investigation_id, incident_id, created_at, updated_at, payload) VALUES (?, ?, ?, ?, ?)",
                [("investigation-old", "incident-low", "2025-01-01T00:00:00Z", "2025-01-01T02:00:00Z", json.dumps({"investigation_id": "investigation-old", "incident_id": "incident-low", "status": "active"})),
                 ("investigation-new", "incident-high", "2025-01-02T00:00:00Z", "2025-01-02T02:00:00Z", json.dumps({"investigation_id": "investigation-new", "incident_id": "incident-high", "status": "completed"}))],
            )
            connection.commit()

    def tearDown(self):
        self.directory.cleanup()

    def list_ids(self, resource, **filters):
        with Database(self.path) as db:
            return [item[f"{resource[:-1]}_id"] for item in AnalysisRepository(db).list_payloads(resource, filters=filters)]

    def test_real_http_query_filters_and_validation(self):
        from sentinelforge.api.server import SentinelHTTPServer
        from sentinelforge.auth.service import AuthService
        with Database(self.path) as db:
            AuthService(db).create_user("admin", "correct horse battery", "admin")
        server = SentinelHTTPServer("127.0.0.1", 0, self.path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            body = json.dumps({"username": "admin", "password": "correct horse battery"}).encode()
            connection.request("POST", "/auth/login", body, {"Content-Type": "application/json", "Content-Length": str(len(body)), "Origin": f"http://127.0.0.1:{server.server_port}"})
            response = connection.getresponse()
            cookies = "; ".join(value.split(";", 1)[0] for key, value in response.getheaders() if key.lower() == "set-cookie")
            response.read()
            for path in ("/alerts?rule_id=RULE_NEW", "/incidents?status=investigating", "/investigations?status=completed", "/runs?source=network_connection"):
                connection.close()
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                connection.request("GET", path, headers={"Cookie": cookies})
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertIsInstance(json.loads(response.read()), list)
            connection.close()
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            connection.request("GET", "/alerts?severity=low&severity=high", headers={"Cookie": cookies})
            self.assertEqual(connection.getresponse().status, 400)
            connection.close()
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            connection.request("GET", "/incidents?status=invalid", headers={"Cookie": cookies})
            self.assertEqual(connection.getresponse().status, 400)
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_default_server_database_is_queryable(self):
        from sentinelforge.api.server import SentinelHTTPServer
        server = SentinelHTTPServer("127.0.0.1", 0)
        try:
            with Database(server.database) as db:
                db.connection.execute("INSERT INTO alerts(alert_id, timestamp, payload) VALUES (?, ?, ?)", ("memory-alert", "2025-01-01T00:00:00Z", json.dumps({"alert_id": "memory-alert", "rule_id": "R", "severity": "low"})))
                db.connection.commit()
            self.assertEqual(server.ops.read("/alerts", {"rule_id": "R"}), ([{"alert_id": "memory-alert", "rule_id": "R", "severity": "low"}], 200))
        finally:
            server.server_close()

    def test_exact_filters_and_combinations(self):
        self.assertEqual(self.list_ids("alerts", rule_id="RULE_NEW"), ["alert-new"])
        self.assertEqual(self.list_ids("alerts", severity="high", source="network_connection", run_id="run-new"), ["alert-new"])
        self.assertEqual(self.list_ids("incidents", status="investigating", risk_level="critical", min_risk_score=80, max_risk_score=80), ["incident-high"])
        self.assertEqual(self.list_ids("investigations", status="completed", incident_id="incident-high"), ["investigation-new"])
        self.assertEqual(self.list_ids("runs", source="network_connection"), ["run-new"])

    def test_time_ranges_are_inclusive_and_filter_before_limit(self):
        self.assertEqual(self.list_ids("alerts", since="2025-01-02T00:00:00Z", until="2025-01-02T00:00:00Z"), ["alert-new"])
        self.assertEqual(self.list_ids("alerts", until="2025-01-01T00:00:00Z"), ["alert-old"])
        self.assertEqual(self.list_ids("alerts", limit=1), ["alert-new"])
        self.assertEqual(self.list_ids("incidents", limit=1), ["incident-high"])
        self.assertEqual(self.list_ids("investigations", limit=1), ["investigation-new"])
        self.assertEqual(self.list_ids("runs", limit=1), ["run-old"])

    def test_no_match_and_invalid_repository_filter_are_safe(self):
        self.assertEqual(self.list_ids("alerts", rule_id="does-not-exist"), [])
        with self.assertRaises(ValueError):
            with Database(self.path) as db:
                AnalysisRepository(db).list_payloads("alerts", filters={"not_allowed": "x"})

    def test_duplicate_query_parameters_are_rejected(self):
        for path, query in (("/alerts", "limit=1&limit=2"), ("/incidents", "severity=low&severity=high"), ("/runs", "unknown=a&unknown=b")):
            with self.assertRaises(ValueError):
                ApiOperations._query(path, query)

    def test_api_query_validation(self):
        valid = ApiOperations._query("/alerts", "severity=high&limit=10&since=2025-01-01T00%3A00%3A00Z")
        self.assertEqual(valid["limit"], 10)
        self.assertEqual(valid["since"], "2025-01-01T00:00:00Z")
        for query in ("unknown=x", "limit=0", "limit=1001", "since=not-time", "severity=bad", "min_risk_score=nope"):
            with self.assertRaises(ValueError):
                ApiOperations._query("/alerts" if "risk" not in query else "/incidents", query)
        with self.assertRaises(ValueError):
            ApiOperations._query("/incidents", "min_risk_score=90&max_risk_score=10")
        with self.assertRaises(ValueError):
            ApiOperations._query("/alerts", "since=2025-01-02T00%3A00%3A00Z&until=2025-01-01T00%3A00%3A00Z")

    def test_utc_normalization_and_offset_bounds(self):
        with Database(self.path) as db:
            db.connection.execute("UPDATE alerts SET timestamp=? WHERE alert_id=?", ("2025-01-02T02:00:00+02:00", "alert-new"))
            db.connection.commit()
            values = AnalysisRepository(db).list_payloads("alerts", filters={"since": "2025-01-02T00:00:00Z", "until": "2025-01-02T00:00:00Z"})
            self.assertEqual(values, [])
            values = AnalysisRepository(db).list_payloads("alerts", filters={"since": "2025-01-02T02:00:00+02:00", "until": "2025-01-02T02:00:00+02:00"})
            self.assertEqual([item["alert_id"] for item in values], ["alert-new"])

    def test_sql_injection_style_values_are_exact_data(self):
        self.assertEqual(self.list_ids("alerts", rule_id="' OR 1=1 --"), [])
        self.assertEqual(self.list_ids("runs", source="network_connection' OR 1=1 --"), [])


if __name__ == "__main__":
    unittest.main()

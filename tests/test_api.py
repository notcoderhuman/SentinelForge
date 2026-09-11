import json
import sqlite3
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

from sentinelforge.api.server import ALLOWED_SOURCES, MAX_BODY_BYTES, SentinelHTTPServer
from sentinelforge.auth.service import AuthService
from sentinelforge.storage import Database


class ThreadSafeAuthServer(SentinelHTTPServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._db.close()
        self._db = None
        self.auth = None

    def server_close(self):
        ThreadingHTTPServer.server_close(self)

    def process_request(self, request, client_address):
        if self.auth is None:
            self._db = Database(self.database)
            self.auth = AuthService(self._db)
        try:
            self.finish_request(request, client_address)
        finally:
            self._db.close()
            self._db = None
            self.auth = None
            self.shutdown_request(request)


class ApiTests(unittest.TestCase):
    def test_source_allowlist_is_explicit_and_network_enabled(self):
        self.assertEqual(ALLOWED_SOURCES, frozenset({"linux_auth", "windows_security", "network_connection", "process_execution", "dns_query", "file_activity", "system_persistence", "registry_change", "registry"}))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "analysis.db")
        with Database(self.database) as db:
            AuthService(db).create_user("admin_test", "correct horse battery", "admin")
        self.server = ThreadSafeAuthServer("127.0.0.1", 0, self.database)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        self.cookies = {}
        self.login()

    def login(self):
        status, body, headers = self.request_with_headers("POST", "/auth/login", {"username": "admin_test", "password": "correct horse battery"})
        self.assertEqual(status, 200)
        for header in headers:
            if header[0].lower() == "set-cookie":
                cookie = header[1].split(";", 1)[0]
                self.cookies[cookie.split("=", 1)[0]] = cookie
        csrf_cookie = next(value.split(";", 1)[0] for key, value in headers if key.lower() == "set-cookie" and value.startswith("sf_csrf="))
        self.csrf = csrf_cookie.split("=", 1)[1]

    def request_with_headers(self, method, path, body=None):
        headers = {"Cookie": "; ".join(self.cookies.values())} if self.cookies else {}
        if body is not None:
            encoded = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(encoded))
        else:
            encoded = None
        if method == "POST" and path != "/auth/login":
            headers["X-CSRF-Token"] = getattr(self, "csrf", "")
            headers["Origin"] = f"http://127.0.0.1:{self.server.server_port}"
        self.connection.request(method, path, encoded, headers)
        response = self.connection.getresponse()
        value = json.loads(response.read().decode()) if response.getheader("Content-Length") != "0" else None
        return response.status, value, response.getheaders()

    def tearDown(self):
        self.connection.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.directory.cleanup()

    def request(self, method, path, body=None):
        headers = {"Cookie": "; ".join(self.cookies.values())} if self.cookies else {}
        encoded = None
        if body is not None:
            encoded = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(encoded))
        else:
            encoded = None
        if method == "POST" and path != "/auth/login":
            headers["X-CSRF-Token"] = getattr(self, "csrf", "")
            headers["Origin"] = f"http://127.0.0.1:{self.server.server_port}"
        self.connection.request(method, path, encoded, headers)
        response = self.connection.getresponse()
        value = json.loads(response.read().decode()) if response.getheader("Content-Length") != "0" else None
        return response.status, value

    def test_health_and_empty_resources(self):
        self.connection.close()
        self.connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        self.cookies = {}
        self.assertEqual(self.request("GET", "/alerts")[0], 401)
        self.login()
        self.assertEqual(self.request("GET", "/health"), (200, {"service": "sentinelforge", "status": "ok"}))
        self.assertEqual(self.request("GET", "/alerts"), (200, []))
        self.assertEqual(self.request("GET", "/runs"), (200, []))

    def test_process_source_is_allowlisted(self):
        self.assertIn("process_execution", ALLOWED_SOURCES)
        self.assertNotIn("process", ALLOWED_SOURCES)

    def test_invalid_source_and_field_are_rejected(self):
        invalid_source = {"path": "fixtures/auth.log", "source": "not-a-source"}
        invalid_field = {"path": "fixtures/auth.log", "source": "process_execution", "unexpected": True}
        self.assertEqual(self.request("POST", "/analyze", invalid_source)[0], 400)
        self.assertEqual(self.request("POST", "/analyze", invalid_field)[0], 400)

    def test_analysis_and_persisted_reads(self):
        status, report = self.request("POST", "/analyze", {"path": "fixtures/auth.log", "source": "linux_auth"})
        self.assertEqual(status, 200)
        self.assertTrue(report["alerts"])
        self.assertEqual(self.request("GET", "/alerts")[0], 200)
        alert_id = report["alerts"][0]["alert_id"]
        self.assertEqual(self.request("GET", "/alerts/does-not-exist"), (404, {"error": "not found"}))
        self.assertEqual(self.request("GET", "/alerts/" + alert_id)[0], 200)
        self.assertEqual(len(self.request("GET", "/runs")[1]), 1)

    def test_invalid_requests(self):
        self.assertEqual(self.request("POST", "/analyze", {"source": "linux_auth"})[0], 400)
        self.assertEqual(self.request("POST", "/analyze", {"path": "fixtures/auth.log", "source": "bad"})[0], 400)
        self.assertEqual(self.request("POST", "/analyze", {"path": "fixtures/auth.log", "source": "network"})[0], 400)
        self.assertEqual(self.request("POST", "/analyze", {"path": "fixtures/auth.log", "source": "network_connection", "unexpected": True})[0], 400)
        self.assertEqual(self.request("GET", "/alerts?severity=bad")[0], 400)
        self.assertEqual(self.request("GET", "/runs?limit=bad")[0], 400)
        self.assertEqual(self.request("PUT", "/health")[0], 405)

    def test_malformed_and_oversized_bodies(self):
        self.connection.request("POST", "/analyze", b"not json", {"Content-Length": "8"})
        response = self.connection.getresponse()
        self.assertEqual(response.status, 400)
        response.read()
        self.connection.close()
        self.connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        oversized = b"{" + b"a" * MAX_BODY_BYTES + b"}"
        self.connection.request("POST", "/analyze", oversized, {"Content-Length": str(len(oversized))})
        response = self.connection.getresponse()
        self.assertEqual(response.status, 413)
        response.read()


if __name__ == "__main__":
    unittest.main()

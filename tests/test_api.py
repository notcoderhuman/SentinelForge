import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from sentinelforge.api.server import MAX_BODY_BYTES, SentinelHTTPServer


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "analysis.db")
        self.server = SentinelHTTPServer("127.0.0.1", 0, self.database)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)

    def tearDown(self):
        self.connection.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.directory.cleanup()

    def request(self, method, path, body=None):
        headers = {}
        encoded = None
        if body is not None:
            encoded = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(encoded))
        self.connection.request(method, path, encoded, headers)
        response = self.connection.getresponse()
        value = json.loads(response.read().decode()) if response.getheader("Content-Length") != "0" else None
        return response.status, value

    def test_health_and_empty_resources(self):
        self.assertEqual(self.request("GET", "/health"), (200, {"service": "sentinelforge", "status": "ok"}))
        self.assertEqual(self.request("GET", "/alerts"), (200, []))
        self.assertEqual(self.request("GET", "/runs"), (200, []))

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

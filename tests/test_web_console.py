import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

from sentinelforge.api.server import SentinelHTTPServer
from sentinelforge.auth.service import AuthService
from sentinelforge.storage import Database


class ThreadSafeWebServer(SentinelHTTPServer):
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


class WebConsoleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "web.db")
        with Database(self.database) as db:
            AuthService(db).create_user("admin_web", "correct horse battery", "admin")
        self.server = ThreadSafeWebServer("127.0.0.1", 0, self.database)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        self.cookies = {}

    def login(self):
        body = json.dumps({"username": "admin_web", "password": "correct horse battery"}).encode()
        self.connection.request("POST", "/auth/login", body, {"Content-Type": "application/json", "Content-Length": str(len(body))})
        response = self.connection.getresponse()
        self.assertEqual(response.status, 200)
        for key, value in response.getheaders():
            if key.lower() == "set-cookie":
                cookie = value.split(";", 1)[0]
                self.cookies[cookie.split("=", 1)[0]] = cookie
        response.read()

    def tearDown(self):
        self.connection.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.directory.cleanup()

    def get(self, path):
        self.connection.request("GET", path)
        response = self.connection.getresponse()
        body = response.read()
        return response.status, response.getheader("Content-Type"), body

    def test_known_assets_are_served(self):
        status, content_type, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn(b"SentinelForge", body)
        self.assertEqual(self.get("/styles.css")[0], 200)
        self.assertEqual(self.get("/app.js")[0], 200)

    def test_unknown_and_traversal_paths_are_not_files(self):
        self.login()
        self.assertEqual(self.get("/README.md")[0], 404)
        self.assertEqual(self.get("/../README.md")[0], 404)
        self.assertEqual(self.get("/src/sentinelforge/api/server.py")[0], 404)


if __name__ == "__main__":
    unittest.main()

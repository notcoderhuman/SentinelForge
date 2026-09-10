import threading
import unittest
from http.client import HTTPConnection

from sentinelforge.api.server import SentinelHTTPServer


class WebConsoleTests(unittest.TestCase):
    def setUp(self):
        self.server = SentinelHTTPServer("127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)

    def tearDown(self):
        self.connection.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

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
        self.assertEqual(self.get("/README.md")[0], 404)
        self.assertEqual(self.get("/../README.md")[0], 404)
        self.assertEqual(self.get("/src/sentinelforge/api/server.py")[0], 404)


if __name__ == "__main__":
    unittest.main()

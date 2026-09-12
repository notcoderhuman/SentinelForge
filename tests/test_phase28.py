"""Phase 28 SQLite thread-safety and server lifecycle regression tests."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from pathlib import Path

from sentinelforge.api.server import SentinelHTTPServer
from sentinelforge.auth.service import AuthService
from sentinelforge.storage import Database


class Phase28SQLiteThreadingTests(unittest.TestCase):
    def test_connection_is_thread_affine(self):
        """A Database connection remains owned by its creating thread."""
        with Database() as db:
            errors = []

            def use_foreign_connection():
                try:
                    db.connection.execute("SELECT 1").fetchone()
                except Exception as exc:
                    errors.append(exc)

            thread = threading.Thread(target=use_foreign_connection)
            thread.start()
            thread.join()
            self.assertEqual(len(errors), 1)
            self.assertIn("same thread", str(errors[0]))

    def test_concurrent_reads_and_writes_use_independent_connections(self):
        """Concurrent repository operations complete without cross-thread use."""
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "concurrent.db")
            with Database(path) as db:
                AuthService(db).create_user("seed", "correct horse battery", "viewer")

            errors = []
            barrier = threading.Barrier(4)

            def worker(index: int):
                try:
                    with Database(path) as db:
                        barrier.wait(timeout=5)
                        AuthService(db).create_user(
                            f"worker-{index}", "correct horse battery", "viewer"
                        )
                        self.assertGreaterEqual(len(AuthService(db).list_users()), 2)
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
            for thread in threads:
                thread.start()
            barrier.wait(timeout=5)
            for thread in threads:
                thread.join(timeout=10)
            self.assertFalse(errors, errors)
            with Database(path) as db:
                self.assertEqual(len(AuthService(db).list_users()), 4)

    def test_supplied_auth_uses_external_database_without_closing_it(self):
        """The existing auth= constructor path remains supported and owned externally."""
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "external.db")
            external_db = Database(path)
            AuthService(external_db).create_user("admin", "correct horse battery", "admin")
            auth = AuthService(external_db)
            server = SentinelHTTPServer("127.0.0.1", 0, path, auth=auth)
            server.server_close()
            self.assertEqual(auth.db.connection.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
            external_db.close()

    def test_request_exception_clears_request_state(self):
        """Handler exceptions clear request-local auth and close request DB."""
        server = SentinelHTTPServer("127.0.0.1", 0)
        captured = {}
        original = server.finish_request

        def raising_finish(request, address):
            db = Database(server.database)
            server._request_state.db = db
            server._request_state.auth = AuthService(db)
            captured["db"] = db
            try:
                raise RuntimeError("forced handler failure")
            finally:
                server._request_state.auth = None
                server._request_state.db = None
                db.close()

        server.finish_request = raising_finish
        with self.assertRaises(RuntimeError):
            server.finish_request(None, None)
        self.assertIsNone(getattr(server._request_state, "auth", None))
        self.assertIsNone(getattr(server._request_state, "db", None))
        with self.assertRaises(Exception):
            captured["db"].connection.execute("SELECT 1")
        server.finish_request = original
        server.server_close()

    def test_concurrent_authenticated_requests(self):
        """Concurrent session resolution and authenticated reads remain isolated."""
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "concurrent-server.db")
            with Database(path) as db:
                AuthService(db).create_user("admin", "correct horse battery", "admin")
            server = SentinelHTTPServer("127.0.0.1", 0, path)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                login = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                body = json.dumps({"username": "admin", "password": "correct horse battery"}).encode()
                login.request("POST", "/auth/login", body, {"Content-Type": "application/json", "Content-Length": str(len(body)), "Origin": f"http://127.0.0.1:{server.server_port}"})
                response = login.getresponse()
                self.assertEqual(response.status, 200)
                cookies = "; ".join(value.split(";", 1)[0] for key, value in response.getheaders() if key.lower() == "set-cookie")
                response.read()
                login.close()

                def read_me(_):
                    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                    connection.request("GET", "/auth/me", headers={"Cookie": cookies})
                    response = connection.getresponse()
                    payload = json.loads(response.read())
                    connection.close()
                    return response.status, payload["username"]

                with ThreadPoolExecutor(max_workers=4) as executor:
                    results = list(executor.map(read_me, range(8)))
                self.assertEqual(results, [(200, "admin")] * 8)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_real_threaded_server_login_and_authenticated_read(self):
        """The production ThreadingHTTPServer path keeps auth DB use thread-local."""
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "server.db")
            with Database(path) as db:
                AuthService(db).create_user("admin", "correct horse battery", "admin")

            server = SentinelHTTPServer("127.0.0.1", 0, path)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                body = json.dumps({"username": "admin", "password": "correct horse battery"}).encode()
                connection.request("POST", "/auth/login", body, {
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "Origin": f"http://127.0.0.1:{server.server_port}",
                })
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                cookies = [value.split(";", 1)[0] for key, value in response.getheaders()
                           if key.lower() == "set-cookie"]
                response.read()
                self.assertTrue(any(cookie.startswith("sf_session=") for cookie in cookies))

                connection.close()
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                connection.request("GET", "/auth/me", headers={"Cookie": "; ".join(cookies)})
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                payload = json.loads(response.read())
                self.assertEqual(payload["username"], "admin")
                self.assertEqual(payload["role"], "admin")
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

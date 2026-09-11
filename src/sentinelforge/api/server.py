"""Loopback HTTP API with authenticated sessions and controlled web assets."""

from __future__ import annotations

import json
import logging
import secrets
import threading
import time
import uuid
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlsplit

from ..application import analyze_request, get_resource, list_resource, list_runs
from ..auth.rbac import Permission, allowed
from ..auth.service import AuthService, AuthenticationError
from ..storage import AuthRepository, Database

LOGGER = logging.getLogger(__name__)
MAX_BODY_BYTES = 64 * 1024
WEB_ROOT = Path(__file__).resolve().parents[3] / "web"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}
ALLOWED_SOURCES = frozenset({"linux_auth", "windows_security", "network_connection"})
ALLOWED_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


def _safe_input_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("path must be a non-empty local path")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("path must remain within the working directory")
    try:
        candidate.resolve().relative_to(Path.cwd().resolve())
    except ValueError as exc:
        raise ValueError("path must remain within the working directory") from exc
    if not candidate.resolve().is_file():
        raise ValueError("input file was not found")
    return str(candidate)


class RateLimiter:
    """Bounded, process-local sliding-window limiter."""

    def __init__(self, limit: int = 10, window: int = 60) -> None:
        self.limit = limit
        self.window = window
        self.values: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            values = [stamp for stamp in self.values.get(key, ())
                      if stamp > now - self.window]
            if len(values) >= self.limit:
                self.values[key] = values
                return False
            values.append(now)
            self.values[key] = values
            if len(self.values) > 10_000:
                self.values = {key: values}
            return True


class ApiOperations:
    """Application-facing operations used by authenticated routes."""

    def __init__(self, database: Optional[str]) -> None:
        self.database = database

    def read(self, path: str, query: dict[str, str]) -> tuple[Any, int]:
        if path == "/runs":
            return list_runs(self.database, self._limit(query.get("limit"))), 200
        resources = {
            "/alerts": "alerts",
            "/incidents": "incidents",
            "/investigations": "investigations",
        }
        for prefix, resource in resources.items():
            if path == prefix:
                return list_resource(self.database, resource, query.get("severity")), 200
            if path.startswith(prefix + "/"):
                identifier = path[len(prefix) + 1:]
                if not identifier or "/" in identifier:
                    return {"error": "not found"}, 404
                value = get_resource(self.database, resource, identifier)
                return (value, 200) if value is not None else ({"error": "not found"}, 404)
        return {"error": "not found"}, 404

    def analyze(self, body: dict[str, Any]) -> dict[str, Any]:
        allowed_fields = {"path", "source", "severity", "incident_id", "database"}
        if set(body) - allowed_fields:
            raise ValueError("unsupported request field")
        source = body.get("source", "linux_auth")
        severity = body.get("severity")
        if source not in ALLOWED_SOURCES:
            raise ValueError("unsupported source")
        if severity is not None and severity not in ALLOWED_SEVERITIES:
            raise ValueError("invalid severity")
        database = body.get("database", self.database)
        if database is not None and (
            not isinstance(database, str) or not database or "\x00" in database
        ):
            raise ValueError("database must be a non-empty path")
        return analyze_request(
            _safe_input_path(body.get("path")),
            source,
            severity,
            body.get("incident_id"),
            database,
        )

    @staticmethod
    def _limit(value: Optional[str]) -> Optional[int]:
        if value is None:
            return None
        try:
            result = int(value)
        except ValueError as exc:
            raise ValueError("limit must be an integer") from exc
        if not 1 <= result <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        return result


class _Handler(BaseHTTPRequestHandler):
    server: "SentinelHTTPServer"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        LOGGER.info("%s %s %s", self.command, self.path.split("?", 1)[0],
                    args[1] if len(args) > 1 else "")

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "script-src 'self'",
        )
        self.send_header("Cache-Control", "no-store")

    def _send(self, status: int, payload: Any,
              cookies: tuple[str, ...] = ()) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                              indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self._security_headers()
        for cookie in cookies:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(encoded)

    def _error(self, status: int, message: str) -> None:
        self._send(status, {"error": message})

    def _cookies(self) -> dict[str, str]:
        jar = SimpleCookie()
        jar.load(self.headers.get("Cookie", ""))
        return {key: morsel.value for key, morsel in jar.items()}

    def _pair(self):
        return self.server.auth.resolve(self._cookies().get("sf_session"))

    def _valid_origin(self) -> bool:
        host = self.headers.get("Host", "")
        hostname = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
        allowed_hosts = {self.server.bind_host, "127.0.0.1", "localhost"}
        if hostname not in allowed_hosts:
            return False
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlsplit(origin)
        origin_host = (parsed.netloc.rsplit(":", 1)[0]
                       if parsed.netloc.count(":") == 1 else parsed.netloc)
        return parsed.scheme in {"http", "https"} and origin_host in allowed_hosts

    def _require(self, permission: Optional[Permission] = None,
                 mutate: bool = False):
        pair = self._pair()
        if pair is None:
            self._error(401, "authentication required")
            return None
        user, session = pair
        if permission and not allowed(user.role, permission):
            self._error(403, "forbidden")
            return None
        csrf = self.headers.get("X-CSRF-Token", "")
        if mutate and (not self._valid_origin()
                       or not self.server.auth.csrf_valid(session, csrf)):
            self._error(403, "request validation failed")
            return None
        return pair

    def _audit(self, action: str, user: Any = None, resource: str = "",
               resource_id: Optional[str] = None,
               outcome: str = "success") -> None:
        try:
            with Database(self.server.database) as db:
                AuthRepository(db).add_audit(
                    audit_id=uuid.uuid4().hex,
                    user_id=user.user_id if user else None,
                    action=action,
                    resource=resource,
                    resource_id=resource_id,
                    details={"outcome": outcome},
                    ip_address=self.client_address[0],
                )
        except Exception:
            LOGGER.exception("audit write failed")

    def _read_body(self) -> dict[str, Any]:
        length = self.headers.get("Content-Length")
        if length is None or not length.isdigit():
            raise ValueError("Content-Length is required")
        if int(length) > MAX_BODY_BYTES:
            raise OverflowError
        try:
            body = json.loads(self.rfile.read(int(length)).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("request body must be valid UTF-8 JSON") from exc
        if not isinstance(body, dict):
            raise ValueError("request body must be a JSON object")
        return body

    def _send_static(self, path: str) -> bool:
        entry = STATIC_FILES.get(path)
        if not entry:
            return False
        try:
            data = (WEB_ROOT / entry[0]).read_bytes()
        except OSError:
            self._error(500, "web console unavailable")
            return True
        self.send_response(200)
        self.send_header("Content-Type", entry[1])
        self.send_header("Content-Length", str(len(data)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)
        return True

    def do_GET(self) -> None:
        try:
            parts = urlsplit(self.path)
            if self._send_static(parts.path):
                return
            if parts.path == "/health":
                self._send(200, {"status": "ok", "service": "sentinelforge"})
                return
            known = {"/auth/me", "/users", "/audit", "/runs", "/alerts",
                     "/incidents", "/investigations"}
            detail_prefixes = ("/alerts", "/incidents", "/investigations")
            if (parts.path not in known
                    and not any(parts.path.startswith(item + "/")
                               for item in detail_prefixes)):
                self._error(404, "not found")
                return
            if parts.path == "/auth/me":
                pair = self._require()
                if pair:
                    user, session = pair
                    self._send(200, user.public_dict() | {
                        "session_expires_at": session.expires_at.isoformat()
                        .replace("+00:00", "Z")
                    })
                return
            if parts.path == "/users":
                pair = self._require(Permission.ADMIN_USERS)
                if pair:
                    self._send(200, [user.public_dict()
                                     for user in self.server.auth.list_users()])
                return
            if parts.path == "/audit":
                pair = self._require(Permission.READ_AUDIT)
                if pair:
                    query = parse_qs(parts.query, keep_blank_values=True)
                    with Database(self.server.database) as db:
                        payload = AuthRepository(db).list_audit(
                            user_id=query.get("user_id", [None])[-1],
                            limit=int(query.get("limit", ["100"])[-1]),
                        )
                    self._send(200, payload)
                return
            pair = self._require(Permission.READ_ANALYSIS)
            if pair is None:
                return
            query = {key: values[-1] for key, values in
                     parse_qs(parts.query, keep_blank_values=True).items()}
            payload, status = self.server.ops.read(parts.path, query)
            self._send(status, payload)
        except ValueError as exc:
            self._error(400, str(exc))
        except Exception:
            LOGGER.exception("unexpected GET failure")
            self._error(500, "internal server error")

    def do_POST(self) -> None:
        try:
            path = urlsplit(self.path).path
            body = self._read_body()
            if path == "/auth/login":
                if not self._valid_origin():
                    self._error(403, "request validation failed")
                    return
                if not self.server.login_limiter.allow(self.client_address[0]):
                    self._error(429, "rate limit exceeded")
                    return
                try:
                    user, session, token = self.server.auth.authenticate(
                        str(body.get("username", "")),
                        str(body.get("password", "")),
                    )
                except AuthenticationError:
                    self._audit("login_failure", outcome="failure")
                    self._error(401, "invalid credentials")
                    return
                self._audit("login", user)
                cookies = (
                    f"sf_session={token}; HttpOnly; SameSite=Lax; Path=/",
                    f"sf_csrf={session.csrf_token}; SameSite=Lax; Path=/",
                )
                self._send(200, user.public_dict() | {"authenticated": True}, cookies)
                return
            if path == "/auth/logout":
                pair = self._require(mutate=True)
                if pair:
                    self.server.auth.revoke(self._cookies().get("sf_session", ""))
                    self._audit("logout", pair[0])
                    self._send(200, {"authenticated": False}, (
                        "sf_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/",
                        "sf_csrf=; Max-Age=0; SameSite=Lax; Path=/",
                    ))
                return
            if path == "/auth/logout-all":
                pair = self._require(mutate=True)
                if pair:
                    self.server.auth.logout_all(pair[0].user_id)
                    self._audit("session_invalidation", pair[0])
                    self._send(200, {"sessions_invalidated": True})
                return
            if path == "/auth/change-password":
                pair = self._require(mutate=True)
                if pair:
                    self.server.auth.change_password(
                        pair[0].user_id,
                        str(body.get("current_password", "")),
                        str(body.get("new_password", "")),
                    )
                    self._audit("password_change", pair[0])
                    self._send(200, {"password_changed": True})
                return
            if path == "/analyze":
                pair = self._require(Permission.RUN_ANALYSIS, mutate=True)
                if pair:
                    self._audit("analyze", pair[0], "analysis")
                    self._send(200, self.server.ops.analyze(body))
                return
            if path == "/users":
                pair = self._require(Permission.ADMIN_USERS, mutate=True)
                if pair:
                    user = self.server.auth.create_user(
                        body["username"], body["password"], body.get("role", "viewer")
                    )
                    self._audit("user_create", pair[0], "user", user.user_id)
                    self._send(201, user.public_dict())
                return
            self._error(404, "not found")
        except OverflowError:
            self._error(413, "request body too large")
        except (KeyError, TypeError, ValueError) as exc:
            self._error(400, str(exc))
        except Exception:
            LOGGER.exception("unexpected POST failure")
            self._error(500, "internal server error")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self._security_headers()
        self.end_headers()

    def do_PUT(self) -> None:
        self._error(405, "method not allowed")

    do_PATCH = do_PUT
    do_DELETE = do_PUT
    do_HEAD = do_PUT


class SentinelHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host: str, port: int,
                 database: Optional[str] = None,
                 auth: Optional[AuthService] = None) -> None:
        self.bind_host = host
        self.database = database or ":memory:"
        self._db = Database(self.database)
        self.auth = auth or AuthService(self._db)
        self.ops = ApiOperations(database)
        self.login_limiter = RateLimiter(10, 60)
        super().__init__((host, port), _Handler)

    def server_close(self) -> None:
        self._db.close()
        super().server_close()


def serve(host: str = "127.0.0.1", port: int = 8765,
          database: Optional[str] = None) -> None:
    server = SentinelHTTPServer(host, port, database)
    LOGGER.info("SentinelForge API listening on http://%s:%d", host, server.server_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("SentinelForge API shutting down")
    finally:
        server.server_close()

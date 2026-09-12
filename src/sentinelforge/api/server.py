"""Loopback HTTP API with authenticated sessions and controlled web assets."""

from __future__ import annotations

import json
import logging
import sqlite3
import math
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
from ..storage import AnalysisRepository, AuthRepository, Database
from ..storage.repositories import CaseConflictError, InvalidCaseTransitionError
from ..investigations import AnalystNote

LOGGER = logging.getLogger(__name__)
MAX_BODY_BYTES = 64 * 1024
WEB_ROOT = Path(__file__).resolve().parents[3] / "web"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}
ALLOWED_SOURCES = frozenset({"linux_auth", "windows_security", "network_connection", "process_execution", "dns_query", "file_activity", "system_persistence", "registry_change", "registry", "windows_system_event"})
ALLOWED_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
ALLOWED_STATUSES = frozenset({"open", "investigating", "resolved", "closed", "active", "completed"})
RESOURCE_STATUSES = {
    "/incidents": frozenset({"open", "investigating", "resolved", "closed"}),
    "/investigations": frozenset({"active", "completed"}),
}
QUERY_LIMIT_MAX = 1000
QUERY_FIELDS = {
    "/alerts": frozenset({"severity", "rule_id", "source", "run_id", "since", "until", "limit"}),
    "/incidents": frozenset({"severity", "status", "risk_level", "min_risk_score", "max_risk_score", "run_id", "since", "until", "limit"}),
    "/investigations": frozenset({"status", "incident_id", "since", "until", "limit"}),
    "/runs": frozenset({"source", "since", "until", "limit"}),
}


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

    def read(self, path: str, query: dict[str, Any]) -> tuple[Any, int]:
        if path == "/runs":
            return list_runs(self.database, filters=query), 200
        resources = {
            "/alerts": "alerts",
            "/incidents": "incidents",
            "/investigations": "investigations",
        }
        for prefix, resource in resources.items():
            if path == prefix:
                return list_resource(self.database, resource, filters=query), 200
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
        if not 1 <= result <= QUERY_LIMIT_MAX:
            raise ValueError(f"limit must be between 1 and {QUERY_LIMIT_MAX}")
        return result

    @staticmethod
    def _timestamp(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        from datetime import datetime, timezone
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be ISO-8601") from exc
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include timezone")
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @classmethod
    def _query(cls, path: str, raw: str) -> dict[str, Any]:
        parsed = parse_qs(raw, keep_blank_values=True)
        repeated = [key for key, items in parsed.items() if len(items) != 1]
        if repeated:
            raise ValueError("query parameters must not be repeated")
        values = {key: items[0] for key, items in parsed.items()}
        unknown = set(values) - QUERY_FIELDS[path]
        if unknown:
            raise ValueError("unsupported query parameter")
        if "limit" in values:
            values["limit"] = cls._limit(values["limit"])
        for key in ("since", "until"):
            if key in values:
                values[key] = cls._timestamp(values[key])
        if "severity" in values and values["severity"] not in ALLOWED_SEVERITIES:
            raise ValueError("invalid severity")
        if "status" in values and values["status"] not in RESOURCE_STATUSES.get(path, ALLOWED_STATUSES):
            raise ValueError("invalid status")
        if "source" in values and values["source"] not in ALLOWED_SOURCES:
            raise ValueError("unsupported source")
        for key in ("rule_id", "run_id", "incident_id"):
            if key in values and (not values[key] or any(char in values[key] for char in "\x00\r\n")):
                raise ValueError(f"invalid {key}")
        if "risk_level" in values and values["risk_level"] not in ALLOWED_SEVERITIES:
            raise ValueError("invalid risk level")
        for key in ("min_risk_score", "max_risk_score"):
            if key in values:
                try:
                    values[key] = float(values[key])
                except ValueError as exc:
                    raise ValueError("risk score must be numeric") from exc
                if not math.isfinite(values[key]):
                    raise ValueError("risk score must be finite")
        if "min_risk_score" in values and "max_risk_score" in values and values["min_risk_score"] > values["max_risk_score"]:
            raise ValueError("minimum risk score exceeds maximum")
        if "since" in values and "until" in values and values["since"] > values["until"]:
            raise ValueError("since exceeds until")
        return values


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
        return self.server.request_auth().resolve(self._cookies().get("sf_session"))

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
                       or not self.server.request_auth().csrf_valid(session, csrf)):
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
                                     for user in self.server.request_auth().list_users()])
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
            query = self.server.ops._query(parts.path, parts.query) if parts.path in QUERY_FIELDS else {}
            if parts.query and parts.path not in QUERY_FIELDS:
                raise ValueError("query parameters are not supported for detail endpoints")
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
                    user, session, token = self.server.request_auth().authenticate(
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
                    self.server.request_auth().revoke(self._cookies().get("sf_session", ""))
                    self._audit("logout", pair[0])
                    self._send(200, {"authenticated": False}, (
                        "sf_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/",
                        "sf_csrf=; Max-Age=0; SameSite=Lax; Path=/",
                    ))
                return
            if path == "/auth/logout-all":
                pair = self._require(mutate=True)
                if pair:
                    self.server.request_auth().logout_all(pair[0].user_id)
                    self._audit("session_invalidation", pair[0])
                    self._send(200, {"sessions_invalidated": True})
                return
            if path == "/auth/change-password":
                pair = self._require(mutate=True)
                if pair:
                    self.server.request_auth().change_password(
                        pair[0].user_id,
                        str(body.get("current_password", "")),
                        str(body.get("new_password", "")),
                    )
                    self._audit("password_change", pair[0])
                    self._send(200, {"password_changed": True})
                return
            if path.startswith("/incidents/") and path.endswith("/status"):
                pair = self._require(Permission.MANAGE_CASES, mutate=True)
                if pair:
                    identifier = path[len("/incidents/"):-len("/status")].strip("/")
                    if not identifier or "/" in identifier or set(body) != {"status"} or not isinstance(body["status"], str):
                        raise ValueError("invalid request")
                    with Database(self.server.database) as db:
                        incident, changed = AnalysisRepository(db).mutate_incident_status(identifier, body["status"], user_id=pair[0].user_id, ip_address=self.client_address[0])
                    if incident is None:
                        self._error(404, "not found")
                    else:
                        self._send(200, {"changed": changed, "incident": incident.to_dict()})
                return
            if path.startswith("/investigations/") and path.endswith("/status"):
                pair = self._require(Permission.MANAGE_CASES, mutate=True)
                if pair:
                    identifier = path[len("/investigations/"):-len("/status")].strip("/")
                    if not identifier or "/" in identifier or set(body) != {"status"} or not isinstance(body["status"], str):
                        raise ValueError("invalid request")
                    with Database(self.server.database) as db:
                        investigation, changed = AnalysisRepository(db).mutate_investigation_status(identifier, body["status"], user_id=pair[0].user_id, ip_address=self.client_address[0])
                    if investigation is None:
                        self._error(404, "not found")
                    else:
                        self._send(200, {"changed": changed, "investigation": investigation.to_dict()})
                return
            if path.startswith("/investigations/") and path.endswith("/notes"):
                pair = self._require(Permission.MANAGE_CASES, mutate=True)
                if pair:
                    identifier = path[len("/investigations/"):-len("/notes")].strip("/")
                    if not identifier or "/" in identifier or set(body) != {"content"}:
                        raise ValueError("invalid request")
                    content = body["content"]
                    if not isinstance(content, str) or not content.strip():
                        raise ValueError("content must be non-empty")
                    if len(content.encode("utf-8")) > 16 * 1024:
                        raise OverflowError
                    from datetime import datetime, timezone
                    note = AnalystNote(uuid.uuid4().hex, datetime.now(timezone.utc), pair[0].username, content)
                    with Database(self.server.database) as db:
                        investigation = AnalysisRepository(db).append_investigation_note(identifier, note, user_id=pair[0].user_id, ip_address=self.client_address[0])
                    if investigation is None:
                        self._error(404, "not found")
                    else:
                        self._send(201, {"note": note.to_dict()})
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
                    user = self.server.request_auth().create_user(
                        body["username"], body["password"], body.get("role", "viewer")
                    )
                    self._audit("user_create", pair[0], "user", user.user_id)
                    self._send(201, user.public_dict())
                return
            self._error(404, "not found")
        except OverflowError:
            self._error(413, "request body too large")
        except (CaseConflictError, InvalidCaseTransitionError) as exc:
            self._error(409, str(exc))
        except sqlite3.IntegrityError:
            self._error(409, "case mutation conflict")
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower():
                self._error(503, "database temporarily unavailable")
            else:
                LOGGER.exception("database operation failed")
                self._error(500, "internal server error")
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


class _InitializationErrorHandler(BaseHTTPRequestHandler):
    """Complete an HTTP exchange when request database setup is locked."""
    def _send_unavailable(self) -> None:
        payload = json.dumps({"error": "database temporarily unavailable"}).encode("utf-8")
        self.send_response(503)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    do_GET = lambda self: self._send_unavailable()
    do_POST = lambda self: self._send_unavailable()
    do_PUT = lambda self: self._send_unavailable()
    do_PATCH = lambda self: self._send_unavailable()
    do_DELETE = lambda self: self._send_unavailable()
    do_HEAD = lambda self: self._send_unavailable()


class SentinelHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host: str, port: int,
                 database: Optional[str] = None,
                 auth: Optional[AuthService] = None) -> None:
        self.bind_host = host
        self._owns_db = auth is None
        if auth is not None:
            if auth.db.path == ":memory:":
                raise ValueError("auth service must use a persistent database for threaded serving")
            if database is not None and str(database) != auth.db.path:
                raise ValueError("database path must match supplied auth service database")
            self.database = auth.db.path
            self._db = auth.db
            self.auth = auth
        else:
            self.database = database or f"file:sentinelforge-{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._db = Database(self.database)
            self.auth = AuthService(self._db)
        self._request_state = threading.local()
        self.ops = ApiOperations(self.database)
        self.login_limiter = RateLimiter(10, 60)
        super().__init__((host, port), _Handler)

    def request_auth(self) -> AuthService:
        """Return the authentication service bound to this request thread."""
        auth = getattr(self._request_state, "auth", None)
        if auth is None:
            raise RuntimeError("request authentication service is unavailable outside a request")
        return auth

    def process_request_thread(self, request, client_address) -> None:
        """Run a request and map initialization lock failures safely."""
        try:
            self.finish_request(request, client_address)
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower():
                raise
            _InitializationErrorHandler(request, client_address, self)
        finally:
            self.shutdown_request(request)

    def finish_request(self, request, client_address) -> None:
        """Bind a short-lived database connection to the handling thread."""
        db = Database(self.database)
        self._request_state.db = db
        self._request_state.auth = AuthService(db)
        try:
            super().finish_request(request, client_address)
        finally:
            self._request_state.auth = None
            self._request_state.db = None
            if self._owns_db:
                db.close()

    def server_close(self) -> None:
        if self._owns_db:
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

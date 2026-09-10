"""Small loopback HTTP API for SentinelForge."""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlsplit

from ..application import analyze_request, get_resource, list_resource, list_runs

LOGGER = logging.getLogger(__name__)
MAX_BODY_BYTES = 64 * 1024
_WEB_ROOT = Path(__file__).resolve().parents[3] / "web"
_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}
_ALLOWED_SOURCES = frozenset({"linux_auth", "windows_security"})
_ALLOWED_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


def _safe_input_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("path must be a non-empty local path")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("path must remain within the working directory")
    resolved = candidate.resolve()
    root = Path.cwd().resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("path must remain within the working directory") from exc
    if not resolved.is_file():
        raise ValueError("input file was not found")
    return str(candidate)


def _safe_database_path(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("database must be a non-empty path")
    return value


class _Handler(BaseHTTPRequestHandler):
    server: "SentinelHTTPServer"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        LOGGER.info("%s %s %s", self.command, self.path.split("?", 1)[0], args[1] if len(args) > 1 else "")

    def _send(self, status: int, payload: Any) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)

    def _error(self, status: int, message: str) -> None:
        self._send(status, {"error": message})

    def _send_static(self, path: str) -> bool:
        entry = _STATIC_FILES.get(path)
        if entry is None:
            return False
        filename, content_type = entry
        try:
            data = (_WEB_ROOT / filename).read_bytes()
        except OSError:
            self._error(500, "web console unavailable")
            return True
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        return True

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        try:
            parts = urlsplit(self.path)
            if self._send_static(parts.path):
                return
            query = parse_qs(parts.query, keep_blank_values=True)
            values = {key: items[-1] for key, items in query.items()}
            payload, status = self.server.api.get(parts.path, values)
            self._send(status, payload)
        except ValueError as exc:
            self._error(400, str(exc))
        except Exception:
            LOGGER.exception("unexpected GET failure")
            self._error(500, "internal server error")

    def do_HEAD(self) -> None:
        self._error(405, "method not allowed")

    def do_POST(self) -> None:
        try:
            length = self.headers.get("Content-Length")
            if length is None or not length.isdigit():
                raise ValueError("Content-Length is required")
            size = int(length)
            if size > MAX_BODY_BYTES:
                self._error(413, "request body too large")
                return
            raw = self.rfile.read(size)
            try:
                body = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("request body must be valid UTF-8 JSON") from exc
            if not isinstance(body, dict):
                raise ValueError("request body must be a JSON object")
            payload, status = self.server.api.post(urlsplit(self.path).path, body)
            self._send(status, payload)
        except ValueError as exc:
            self._error(400, str(exc))
        except Exception:
            LOGGER.exception("unexpected POST failure")
            self._error(500, "internal server error")

    def do_PUT(self) -> None:
        self._error(405, "method not allowed")

    do_PATCH = do_PUT
    do_DELETE = do_PUT


class ApiOperations:
    """Route-independent application operation adapter."""

    def __init__(self, database: Optional[str]) -> None:
        self.database = database

    def get(self, path: str, query: dict[str, str]) -> tuple[Any, int]:
        if path == "/health":
            return {"status": "ok", "service": "sentinelforge"}, 200
        if path == "/runs":
            limit = self._limit(query.get("limit"))
            return list_runs(self.database, limit), 200
        resource_map = {"/alerts": "alerts", "/incidents": "incidents", "/investigations": "investigations"}
        for prefix, resource in resource_map.items():
            if path == prefix:
                return list_resource(self.database, resource, query.get("severity")), 200
            if path.startswith(prefix + "/"):
                entity_id = path[len(prefix) + 1:]
                if not entity_id or "/" in entity_id:
                    return {"error": "not found"}, 404
                value = get_resource(self.database, resource, entity_id)
                return (value, 200) if value is not None else ({"error": "not found"}, 404)
        return {"error": "not found"}, 404

    def post(self, path: str, body: dict[str, Any]) -> tuple[Any, int]:
        if path != "/analyze":
            return {"error": "not found"}, 404
        allowed = {"path", "source", "severity", "incident_id", "database"}
        unknown = set(body) - allowed
        if unknown:
            raise ValueError("unsupported request field")
        database = _safe_database_path(body.get("database", self.database))
        path_value = _safe_input_path(body.get("path"))
        source = body.get("source", "linux_auth")
        if source not in _ALLOWED_SOURCES:
            raise ValueError("unsupported source")
        severity = body.get("severity")
        if severity is not None and severity not in _ALLOWED_SEVERITIES:
            raise ValueError("invalid severity")
        result = analyze_request(path_value, source, severity, body.get("incident_id"), database)
        return result, 200

    @staticmethod
    def _limit(value: Optional[str]) -> Optional[int]:
        if value is None:
            return None
        try:
            limit = int(value)
        except ValueError as exc:
            raise ValueError("limit must be an integer") from exc
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        return limit


class SentinelHTTPServer(ThreadingHTTPServer):
    """Threaded server carrying immutable API configuration."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host: str, port: int, database: Optional[str] = None) -> None:
        self.api = ApiOperations(database)
        super().__init__((host, port), _Handler)


def serve(host: str = "127.0.0.1", port: int = 8765, database: Optional[str] = None) -> None:
    """Serve until interrupted."""
    server = SentinelHTTPServer(host, port, database)
    LOGGER.info("SentinelForge API listening on http://%s:%d", host, server.server_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("SentinelForge API shutting down")
    finally:
        server.server_close()

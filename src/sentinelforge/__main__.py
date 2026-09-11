"""Command-line interface for SentinelForge."""

from __future__ import annotations

import argparse
import getpass
import json
import secrets
from typing import Sequence

from .detection.engine import DetectionEngine
from .incident_engine import derive_incidents
from .ingestion.pipeline import ingest_file
from .investigation_engine import create_investigation
from .observable_engine import extract_observables
from .reporting import analyze_file, render_human_report
from .threat_context_engine import load_context


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SentinelForge defensive log analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("parse", "detect", "incident", "investigate", "observables"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("path", help="path to a documented auth fixture")
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("path", help="path to a documented auth fixture")
    analyze_parser.add_argument("--json", action="store_true", help="emit deterministic JSON")
    analyze_parser.add_argument("--severity", choices=("low", "medium", "high", "critical"))
    analyze_parser.add_argument("--incident", dest="incident_id")
    analyze_parser.add_argument("--source", choices=("linux_auth", "windows_security", "network_connection", "process_execution", "dns_query", "file_activity"), default="linux_auth")
    analyze_parser.add_argument("--database", help="local SQLite database path")
    history_parser = subparsers.add_parser("history")
    history_parser.add_argument("--database", required=True, help="local SQLite database path")
    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument("--database")
    user_parser = subparsers.add_parser("user")
    user_subparsers = user_parser.add_subparsers(dest="user_command", required=True)
    create_admin = user_subparsers.add_parser("create-admin")
    create_admin.add_argument("--database", required=True)
    list_users = user_subparsers.add_parser("list")
    list_users.add_argument("--database", required=True)
    return parser


def _run_existing_command(arguments: argparse.Namespace) -> dict:
    ingestion_result = ingest_file(arguments.path)
    events = ingestion_result.events
    diagnostics = ingestion_result.diagnostics
    if arguments.command == "parse":
        return {"events": [event.to_dict() for event in events],
                "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics]}
    if arguments.command == "observables":
        return {"observables": [observable.to_dict() for observable in extract_observables(events)],
                "threat_context": [], "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics]}
    alerts = DetectionEngine().detect(events)
    if arguments.command == "detect":
        return {"alerts": [alert.to_dict() for alert in alerts],
                "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics]}
    incidents = derive_incidents(alerts, load_context("rules/threat_context.json"))
    if arguments.command == "incident":
        return {"incidents": [incident.to_dict() for incident in incidents],
                "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics]}
    investigations = [create_investigation(incident) for incident in incidents]
    return {"investigations": [investigation.to_dict() for investigation in investigations],
            "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics]}


def main(argv: Sequence[str] | None = None) -> int:
    """Run an existing command or the unified analyst workflow."""
    arguments = _build_parser().parse_args(argv)
    if arguments.command == "analyze":
        report = analyze_file(arguments.path, arguments.severity, arguments.incident_id, arguments.source, arguments.database)
        if arguments.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(render_human_report(report))
        return 0
    if arguments.command == "history":
        from .storage import AnalysisRepository, Database
        with Database(arguments.database) as db:
            print(json.dumps(AnalysisRepository(db).list_runs(), indent=2, sort_keys=True))
        return 0
    if arguments.command == "serve":
        if not 1 <= arguments.port <= 65535:
            raise SystemExit("port must be between 1 and 65535")
        from .api import serve
        serve(arguments.host, arguments.port, arguments.database)
        return 0
    if arguments.command == "user":
        from datetime import datetime, timezone
        from .auth.passwords import hash_password, validate_password
        from .auth.users import User
        from .storage import AuthRepository, Database
        with Database(arguments.database) as db:
            repository = AuthRepository(db)
            if arguments.user_command == "list":
                print(json.dumps([user.public_dict() for user in repository.list_users()], indent=2, sort_keys=True))
                return 0
            if repository.list_users(active_only=True):
                raise SystemExit("an enabled user already exists")
            username = input("Admin username: ").strip()
            password = getpass.getpass("Admin password: ")
            confirmation = getpass.getpass("Confirm admin password: ")
            if password != confirmation:
                raise SystemExit("passwords do not match")
            validate_password(password)
            user = User(secrets.token_urlsafe(16), username, hash_password(password), "admin", datetime.now(timezone.utc), True)
            repository.create_user(user)
            print(json.dumps(user.public_dict(), indent=2, sort_keys=True))
            return 0
    output = _run_existing_command(arguments)
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

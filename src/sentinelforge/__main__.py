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
from .replay import evaluate, explain_alert, load_expected, replay_file
from .investigation_package import build_package


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SentinelForge defensive log analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    source_choices = ("linux_auth", "windows_security", "network_connection", "process_execution", "dns_query", "file_activity", "system_persistence", "registry_change", "registry", "windows_system_event")
    for command in ("parse", "detect", "incident", "investigate", "observables"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("path", help="path to a documented auth fixture")
        command_parser.add_argument("--source", choices=source_choices, default="linux_auth")
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("path", help="path to a documented auth fixture")
    analyze_parser.add_argument("--json", action="store_true", help="emit deterministic JSON")
    analyze_parser.add_argument("--severity", choices=("low", "medium", "high", "critical"))
    analyze_parser.add_argument("--incident", dest="incident_id")
    analyze_parser.add_argument("--source", choices=("linux_auth", "windows_security", "network_connection", "process_execution", "dns_query", "file_activity", "system_persistence", "registry_change", "registry", "windows_system_event"), default="linux_auth")
    analyze_parser.add_argument("--database", help="local SQLite database path")
    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("path")
    replay_parser.add_argument("--source", choices=source_choices, default="linux_auth")
    replay_parser.add_argument("--expected")
    replay_parser.add_argument("--json", action="store_true")
    package_parser = subparsers.add_parser("package")
    package_parser.add_argument("path")
    package_parser.add_argument("--source", choices=source_choices, default="linux_auth")
    package_parser.add_argument("--json", action="store_true")
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

    # ------------------------------------------------------------------
    # Phase 27: analyze-with-llm
    # ------------------------------------------------------------------
    llm_parser = subparsers.add_parser("analyze-with-llm", help="run detection and send package to an LLM analyst for structured assessment")
    llm_parser.add_argument("path", help="path to telemetry fixture file")
    llm_parser.add_argument("--source", choices=source_choices, default="linux_auth",
                            help="telemetry source type")
    llm_parser.add_argument("--provider", default="mock",
                            help="analyst provider: 'mock' (deterministic mock for validation-pipeline testing; its default fake IDs may fail validation against a real package), 'deepseek' (real API, requires DEEPSEEK_API_KEY), or 'none' (offline preview, no network)")
    llm_parser.add_argument("--model", default=None,
                            help="override model name (provider default if omitted)")
    llm_parser.add_argument("--timeout", type=float, default=None,
                            help="API timeout in seconds (provider default if omitted)")
    llm_parser.add_argument("--json", action="store_true",
                            help="emit full structured JSON output")
    llm_parser.add_argument("--strict", action="store_true",
                            help="treat unsupported claim warnings as validation errors")
    return parser


def _run_existing_command(arguments: argparse.Namespace) -> dict:
    ingestion_result = ingest_file(arguments.path, source=arguments.source)
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


def _run_llm_analyze(arguments: argparse.Namespace) -> int:
    """Phase 27 analyze-with-llm command: detect, package, analyze, validate."""
    from .analyst import AnalystProvider, build_analyst_prompt
    from .analyst._validator import validate_assessment
    from .investigation_package import build_package

    # 1. Ingest telemetry
    try:
        result: IngestionResult = ingest_file(arguments.path, source=arguments.source)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"ingestion error: {exc}") from exc

    # 2. Run detection
    try:
        alerts = DetectionEngine().detect(result.events)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"detection error: {exc}") from exc

    # 3. Build canonical InvestigationPackage
    diagnostics = [d.to_dict() for d in result.diagnostics]
    package = build_package(alerts, diagnostics)
    package_dict = package.to_dict()

    # 4. Handle offline mode (provider=none)
    if arguments.provider == "none":
        prompt = build_analyst_prompt(package_dict)
        output = {
            "status": "offline",
            "package_id": package.package_id,
            "alert_count": len(package.alerts),
            "evidence_count": len(package.evidence),
            "diagnostic_count": len(package.diagnostics),
            "provider": "none",
            "prompt_preview": prompt[:500] + ("..." if len(prompt) > 500 else ""),
            "assessment": None,
            "validation": {"valid": True, "errors": [], "warnings": ["No provider was called — offline preview only"]},
        }
        if arguments.json:
            print(json.dumps(output, indent=2, sort_keys=True))
        else:
            print(f"Offline mode — no provider called")
            print(f"Package: {package.package_id}")
            print(f"  Alerts: {len(package.alerts)}")
            print(f"  Evidence: {len(package.evidence)}")
            print(f"  Diagnostics: {len(package.diagnostics)}")
        return 0

    # 5. Configure provider
    config = {}
    if arguments.model:
        config["model"] = arguments.model
    if arguments.timeout:
        config["timeout"] = arguments.timeout

    try:
        provider = AnalystProvider.create(arguments.provider, **config)
    except ValueError as exc:
        raise SystemExit(f"provider error: {exc}") from exc
    except Exception as exc:
        raise SystemExit(f"provider configuration error: {exc}") from exc

    # 6. Send to provider
    try:
        raw_output = provider.analyze(package_dict, **config)
    except Exception as exc:
        output = {
            "status": "provider_error",
            "error": str(exc),
            "package_id": package.package_id,
            "raw_output": None,
            "assessment": None,
        }
        if arguments.json:
            print(json.dumps(output, indent=2, sort_keys=True))
        else:
            print(f"Provider error: {exc}")
        return 1

    # 7. Validate model output
    valid_alert_ids = {a.alert_id for a in package.alerts}
    valid_evidence_ids = {e.evidence_id for e in package.evidence}

    validation, assessment = validate_assessment(
        raw_output,
        package_id=package.package_id,
        valid_alert_ids=valid_alert_ids,
        valid_evidence_ids=valid_evidence_ids,
        strict=arguments.strict,
    )

    # 8. Build final output
    output = {
        "status": "validated" if validation.valid else "invalid",
        "package_id": package.package_id,
        "provider": arguments.provider,
        "model": arguments.model or "default",
        "validation": {
            "valid": validation.valid,
            "errors": validation.errors,
            "warnings": validation.warnings,
        },
        "raw_output": raw_output,
        "assessment": assessment.to_dict() if assessment else None,
    }

    if arguments.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        status = "✓ VALID" if validation.valid else "✗ INVALID"
        print(f"LLM Analyst — {status}")
        print(f"  Package: {package.package_id}")
        print(f"  Provider: {arguments.provider}")
        print(f"  Alerts: {len(package.alerts)}")
        if assessment:
            print(f"  Executive: {assessment.executive_assessment[:120]}...")
        if validation.errors:
            print(f"  Errors: {len(validation.errors)}")
            for err in validation.errors[:5]:
                print(f"    - {err}")
        if validation.warnings:
            print(f"  Warnings: {len(validation.warnings)}")

    return 0 if validation.valid and not output.get("status") == "provider_error" else 1


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
    if arguments.command == "replay":
        try:
            result = replay_file(arguments.path, arguments.source)
            output = result.to_dict()
            if arguments.expected:
                evaluation = evaluate(result.alerts, load_expected(arguments.expected))
                output["evaluation"] = evaluation.to_dict()
                evaluation_failed = evaluation.false_positives > 0 or evaluation.false_negatives > 0
            else:
                evaluation_failed = False
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"replay error: {exc}") from exc
        if arguments.json:
            output["timing"].pop("elapsed_seconds", None)
            print(json.dumps(output, indent=2, sort_keys=True))
        else:
            print(f"Events: {output['event_count']}")
            print(f"Alerts: {output['alert_count']}")
            if "evaluation" in output:
                metrics = output["evaluation"]["metrics"]
                print(f"Evaluation: precision={metrics['precision']:.3f} recall={metrics['recall']:.3f}")
        return 1 if evaluation_failed else 0
    if arguments.command == "package":
        from .ingestion.pipeline import IngestionResult, ingest_file
        try:
            result: IngestionResult = ingest_file(arguments.path, source=arguments.source)
            alerts = DetectionEngine().detect(result.events)
            package = build_package(alerts, [d.to_dict() for d in result.diagnostics])
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"package error: {exc}") from exc
        if arguments.json:
            print(json.dumps(package.to_dict(), indent=2, sort_keys=True))
        else:
            print(f"Package: {package.package_id}")
            print(f"Alerts: {len(package.alerts)}, Evidence items: {len(package.evidence)}, Diagnostics: {len(package.diagnostics)}")
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

    if arguments.command == "analyze-with-llm":
        return _run_llm_analyze(arguments)

    output = _run_existing_command(arguments)
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

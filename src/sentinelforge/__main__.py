"""Command-line interface for SentinelForge."""

from __future__ import annotations

import argparse
import json
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
        report = analyze_file(arguments.path, arguments.severity, arguments.incident_id)
        if arguments.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(render_human_report(report))
        return 0
    output = _run_existing_command(arguments)
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

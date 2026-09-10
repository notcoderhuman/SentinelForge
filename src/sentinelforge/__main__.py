"""Minimal command-line interface for SentinelForge."""

from __future__ import annotations

import argparse
import json
from typing import Sequence

from .detection.engine import DetectionEngine
from .incident_engine import derive_incidents
from .ingestion.pipeline import ingest_file
from .investigation_engine import create_investigation
from .observable_engine import extract_observables
from .threat_context_engine import load_context


def main(argv: Sequence[str] | None = None) -> int:
    """Run ``parse`` or ``detect`` against an explicitly supplied file."""
    parser = argparse.ArgumentParser(description="SentinelForge defensive log analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("parse", "detect", "incident", "investigate", "observables"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("path", help="path to a documented auth fixture")
    arguments = parser.parse_args(argv)
    ingestion_result = ingest_file(arguments.path)
    events = ingestion_result.events
    diagnostics = ingestion_result.diagnostics
    if arguments.command == "parse":
        output = {"events": [event.to_dict() for event in events],
                  "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics]}
    elif arguments.command == "observables":
        output = {"observables": [observable.to_dict() for observable in extract_observables(events)],
                  "threat_context": [], "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics]}
    else:
        alerts = DetectionEngine().detect(events)
        if arguments.command == "detect":
            output = {"alerts": [alert.to_dict() for alert in alerts],
                      "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics]}
        else:
            incidents = derive_incidents(alerts, load_context("rules/threat_context.json"))
            if arguments.command == "incident":
                output = {"incidents": [incident.to_dict() for incident in incidents],
                          "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics]}
            else:
                investigations = [create_investigation(incident) for incident in incidents]
                output = {"investigations": [investigation.to_dict() for investigation in investigations],
                          "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics]}
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Minimal command-line interface for SentinelForge."""

from __future__ import annotations

import argparse
import json
from typing import Sequence

from .detection.engine import DetectionEngine
from .parsers.linux_auth import parse_file


def main(argv: Sequence[str] | None = None) -> int:
    """Run ``parse`` or ``detect`` against an explicitly supplied file."""
    parser = argparse.ArgumentParser(description="SentinelForge defensive log analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("parse", "detect"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("path", help="path to a documented auth fixture")
    arguments = parser.parse_args(argv)
    events, diagnostics = parse_file(arguments.path)
    if arguments.command == "parse":
        output = {"events": [event.to_dict() for event in events],
                  "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics]}
    else:
        alerts = DetectionEngine().detect(events)
        output = {"alerts": [alert.to_dict() for alert in alerts],
                  "diagnostics": [diagnostic.to_dict() for diagnostic in diagnostics]}
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

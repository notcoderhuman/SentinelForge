"""Exact matching against explicitly supplied local threat context."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from .observables import Observable
from .threat_context import ThreatContext


def load_context(path: str | Path) -> List[ThreatContext]:
    """Load local JSON context without executing or interpreting its content."""
    with Path(path).open("r", encoding="utf-8") as input_file:
        document = json.load(input_file)
    return [ThreatContext(
        observable_type=item["type"], value=item["value"],
        context_type=item["context_type"], label=item["label"],
        confidence=item["confidence"], rationale=item["rationale"],
        source=item["source"],
    ) for item in document.get("observables", [])]


def match_context(observables: Iterable[Observable], contexts: Iterable[ThreatContext]) -> List[ThreatContext]:
    """Return exact type/value matches in deterministic order."""
    context_by_key = {(context.observable_type, context.value): context for context in contexts}
    matches = {
        (context.observable_type, context.value): context
        for observable in observables
        for context in [context_by_key.get((observable.observable_type, observable.value))]
        if context is not None
    }
    return [matches[key] for key in sorted(matches)]

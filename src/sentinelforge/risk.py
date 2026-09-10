"""Transparent deterministic risk assessment model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

ALLOWED_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})


@dataclass(frozen=True)
class RiskAssessment:
    """A bounded prioritization score, not a probability or compromise claim."""

    score: int
    level: str
    factors: Tuple[str, ...]
    explanation: str

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 100:
            raise ValueError("risk score must be between 0 and 100")
        if self.level not in ALLOWED_RISK_LEVELS:
            raise ValueError(f"unsupported risk level: {self.level}")
        if not self.factors or not self.explanation:
            raise ValueError("risk factors and explanation are required")

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-friendly risk representation."""
        return {"score": self.score, "level": self.level,
                "factors": list(self.factors), "explanation": self.explanation}

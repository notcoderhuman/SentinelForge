"""Deterministic mock analyst provider for testing.

The mock returns one of several canned responses depending on the scenario
parameter, allowing comprehensive validator testing without network calls.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from . import AnalystProvider


class MockAnalystProvider(AnalystProvider):
    """A deterministic mock provider for unit tests.

    Parameters
    ----------
    scenario:
        One of:
        - "valid" — returns a completely valid assessment
        - "invalid_alert_id" — references a non-existent alert ID
        - "invalid_evidence_id" — references a non-existent evidence ID
        - "malformed_structure" — missing required sections
        - "unsupported_claim" — claims "confirmed compromise"
        - "missing_section" — missing the observed_facts section
        - "wrong_types" — wrong field types for confidence level
        - "package_id_mismatch" — wrong package_id
    """

    def __init__(self, scenario: str = "valid", **kwargs: Any):
        super().__init__()
        self.scenario = scenario
        self._config = kwargs

    def analyze(self, package_dict: Dict[str, Any], **kwargs: Any) -> str:
        """Return a canned JSON response based on the configured scenario."""
        package_id = package_dict.get("package_id", "test-pkg-id")

        scenarios = {
            "valid": self._valid_response(package_id),
            "invalid_alert_id": self._invalid_alert_id(package_id),
            "invalid_evidence_id": self._invalid_evidence_id(package_id),
            "malformed_structure": self._malformed_structure(package_id),
            "unsupported_claim": self._unsupported_claim(package_id),
            "missing_section": self._missing_section(package_id),
            "wrong_types": self._wrong_types(package_id),
            "package_id_mismatch": self._package_id_mismatch(),
        }
        return scenarios.get(self.scenario, self._valid_response(package_id))

    # ------------------------------------------------------------------
    # Canned responses
    # ------------------------------------------------------------------

    @staticmethod
    def _base_response(package_id: str) -> Dict[str, Any]:
        return {
            "package_id": package_id,
            "executive_assessment": "A valid assessment for testing purposes.",
            "observed_facts": [
                {"text": "First observed fact.", "alert_ids": ["mock-alert-1"], "evidence_ids": ["mock-ev-1"]}
            ],
            "supported_relationships": [
                {"text": "First supported relationship.", "alert_ids": ["mock-alert-1"], "evidence_ids": ["mock-ev-1"]}
            ],
            "hypotheses": [
                {"text": "First hypothesis.", "supporting_alert_ids": ["mock-alert-1"],
                 "supporting_evidence_ids": ["mock-ev-1"], "missing_evidence": ["No file read evidence."]}
            ],
            "unknowns": ["File not collected."],
            "confidence": [
                {"text": "Observed fact is directly in evidence.", "level": "high"},
                {"text": "Hypothesis requires confirmation.", "level": "low"},
            ],
            "investigation_priorities": [
                {"text": "Collect file.", "rationale": "Key evidence.", "resolves_uncertainty": "File content."}
            ],
            "analyst_summary": "Test summary.",
        }

    def _valid_response(self, package_id: str) -> str:
        return json.dumps(self._base_response(package_id), indent=2)

    def _invalid_alert_id(self, package_id: str) -> str:
        d = self._base_response(package_id)
        d["observed_facts"][0]["alert_ids"] = ["non-existent-alert-id"]
        d["supported_relationships"][0]["alert_ids"] = ["also-non-existent"]
        return json.dumps(d, indent=2)

    def _invalid_evidence_id(self, package_id: str) -> str:
        d = self._base_response(package_id)
        d["observed_facts"][0]["evidence_ids"] = ["non-existent-evidence"]
        return json.dumps(d, indent=2)

    def _malformed_structure(self, package_id: str) -> str:
        return json.dumps({"package_id": package_id, "summary": "missing everything else"}, indent=2)

    def _unsupported_claim(self, package_id: str) -> str:
        d = self._base_response(package_id)
        d["executive_assessment"] = "Confirmed compromise. Malware identified."
        return json.dumps(d, indent=2)

    def _missing_section(self, package_id: str) -> str:
        d = self._base_response(package_id)
        d.pop("observed_facts")
        return json.dumps(d, indent=2)

    def _wrong_types(self, package_id: str) -> str:
        d = self._base_response(package_id)
        d["confidence"] = [{"text": "wrong level", "level": "critical"}]
        return json.dumps(d, indent=2)

    def _package_id_mismatch(self) -> str:
        return json.dumps(self._base_response("different-package-id"), indent=2)
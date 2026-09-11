"""Deterministic output validation for analyst assessments.

The validator checks raw model output against the canonical schema and
package entity references. It NEVER silently replaces invalid IDs and
flags or rejects unsupported security claims.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from . import (
    AnalystAssessment,
    AnalystConfidence,
    AnalystFact,
    AnalystHypothesis,
    AnalystPriority,
    AnalystRelationship,
    ValidationResult,
)

_VALID_CONFIDENCE_LEVELS = frozenset({"high", "medium", "low"})
_UNSUPPORTED_CLAIM_PATTERNS = [
    (r"(?i)\bconfirmed\s+compromise\b", "Confirmed compromise claim without full package support"),
    (r"(?i)\bmalware\s+confirmed\b", "Malware claim without explicit package evidence"),
    (r"(?i)\battacker\s+identified\b", "Attacker attribution claim without package support"),
    (r"(?i)\bpersistence\s+succeeded\b", "Persistence success claim without explicit evidence"),
    (r"(?i)\bexecution\s+confirmed\b", "Execution confirmed claim without explicit evidence"),
    (r"(?i)\bconfirmed\s+malicious\b", "Confirmed malicious claim"),
    (r"(?i)\bdefinitely\s+compromised\b", "Definitive compromise claim"),
    (r"(?i)\bwithout\s+a\s+doubt\b", "Absolute certainty claim"),
    (r"(?i)\battacker\b.*?\bdefinitely\b", "Definitive attacker claim"),
]

_REQUIRED_SECTIONS = frozenset({
    "executive_assessment",
    "observed_facts",
    "supported_relationships",
    "hypotheses",
    "unknowns",
    "confidence",
    "investigation_priorities",
    "analyst_summary",
    "package_id",
})


def validate_assessment(
    raw_output: str,
    package_id: str,
    valid_alert_ids: Set[str],
    valid_evidence_ids: Set[str],
    strict: bool = False,
) -> Tuple[ValidationResult, Optional[AnalystAssessment]]:
    """Validate raw model output against the schema and package references.

    Parameters
    ----------
    raw_output:
        The raw string returned by the analyst provider.
    package_id:
        The expected package_id.
    valid_alert_ids:
        Set of all valid alert IDs in the package.
    valid_evidence_ids:
        Set of all valid evidence IDs in the package.
    strict:
        If True, unsupported claim warnings become errors.

    Returns
    -------
    (ValidationResult, AnalystAssessment or None)
        The assessment is None when the output cannot be parsed or is invalid.
    """
    errors: List[str] = []
    warnings: List[str] = []

    # --- Step 1: Parse JSON ----------------------------------------------
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        errors.append(f"Invalid JSON in model output: {exc}")
        return ValidationResult(valid=False, errors=errors), None

    if not isinstance(data, dict):
        errors.append("Model output root is not a JSON object")
        return ValidationResult(valid=False, errors=errors), None

    # --- Step 2: Package ID check ----------------------------------------
    actual_package_id = data.get("package_id")
    if actual_package_id != package_id:
        errors.append(
            f"Package ID mismatch: expected '{package_id}', got '{actual_package_id}'"
        )

    # --- Step 3: Required sections ---------------------------------------
    for section in _REQUIRED_SECTIONS:
        if section not in data:
            errors.append(f"Missing required section: '{section}'")

    if errors:
        return ValidationResult(valid=False, errors=errors), None

    reqstr = str  # local alias for type check
    list_str = list

    # --- Step 4: Type checks on required sections ------------------------
    _check_type(data, "executive_assessment", reqstr, errors)
    _check_type(data, "analyst_summary", reqstr, errors)
    _check_type(data, "observed_facts", list_str, errors)
    _check_type(data, "supported_relationships", list_str, errors)
    _check_type(data, "hypotheses", list_str, errors)
    _check_type(data, "unknowns", list_str, errors)
    _check_type(data, "confidence", list_str, errors)
    _check_type(data, "investigation_priorities", list_str, errors)

    if errors:
        return ValidationResult(valid=False, errors=errors), None

    # --- Step 5: Check empty required text --------------------------------
    if not data.get("executive_assessment", "").strip():
        errors.append("executive_assessment is empty")

    if not data.get("analyst_summary", "").strip():
        errors.append("analyst_summary is empty")

    if not data.get("observed_facts"):
        warnings.append("observed_facts list is empty")

    if not data.get("confidence"):
        errors.append("confidence list is empty — at least one confidence statement required")

    if not data.get("investigation_priorities"):
        warnings.append("investigation_priorities list is empty")

    # --- Step 6: Evidence citation validation -----------------------------
    _validate_facts(data, "observed_facts", valid_alert_ids, valid_evidence_ids, errors, warnings)
    _validate_facts(data, "supported_relationships", valid_alert_ids, valid_evidence_ids, errors, warnings)

    for i, hyp in enumerate(data.get("hypotheses", [])):
        _validate_hypothesis(hyp, i, valid_alert_ids, valid_evidence_ids, errors, warnings)

    for i, conf in enumerate(data.get("confidence", [])):
        _validate_confidence(conf, i, errors, warnings)

    for i, pri in enumerate(data.get("investigation_priorities", [])):
        _validate_priority(pri, i, errors, warnings)

    # --- Step 7: Unsupported claim detection ------------------------------
    full_text = json.dumps(data)
    for pattern, message in _UNSUPPORTED_CLAIM_PATTERNS:
        if re.search(pattern, full_text):
            entry = errors if strict else warnings
            entry.append(message)

    # --- Step 8: Build assessment if valid enough -------------------------
    if errors and not strict:
        # Even with errors, return the partial assessment if we can parse it
        pass

    assessment = _build_assessment(data, errors, warnings)

    valid = len(errors) == 0
    return ValidationResult(valid=valid, errors=errors, warnings=warnings), assessment


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _check_type(data: Dict[str, Any], field: str, expected_type: type,
                 errors: List[str]) -> None:
    val = data.get(field)
    if val is None:
        errors.append(f"'{field}' is null/None")
    elif not isinstance(val, expected_type):
        errors.append(f"'{field}' has wrong type: expected {expected_type.__name__}, got {type(val).__name__}")


def _validate_facts(data: Dict[str, Any], section: str,
                     valid_alert_ids: Set[str], valid_evidence_ids: Set[str],
                     errors: List[str], warnings: List[str]) -> None:
    items = data.get(section, [])
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"'{section}[{i}]' is not a dict")
            continue
        if not item.get("text", "").strip():
            warnings.append(f"'{section}[{i}]' text is empty")

        for aid in item.get("alert_ids", []):
            if not isinstance(aid, str):
                errors.append(f"'{section}[{i}]' alert_id is not a string: {aid}")
            elif aid not in valid_alert_ids:
                errors.append(f"'{section}[{i}]' references unknown alert_id: '{aid}'")

        for eid in item.get("evidence_ids", []):
            if not isinstance(eid, str):
                errors.append(f"'{section}[{i}]' evidence_id is not a string: {eid}")
            elif eid not in valid_evidence_ids:
                errors.append(f"'{section}[{i}]' references unknown evidence_id: '{eid}'")


def _validate_hypothesis(hyp: Any, index: int,
                          valid_alert_ids: Set[str], valid_evidence_ids: Set[str],
                          errors: List[str], warnings: List[str]) -> None:
    if not isinstance(hyp, dict):
        errors.append(f"hypotheses[{index}] is not a dict")
        return
    if not hyp.get("text", "").strip():
        warnings.append(f"hypotheses[{index}] text is empty")

    for aid in hyp.get("supporting_alert_ids", []):
        if not isinstance(aid, str):
            errors.append(f"hypotheses[{index}] alert_id is not a string: {aid}")
        elif aid not in valid_alert_ids:
            errors.append(f"hypotheses[{index}] references unknown alert_id: '{aid}'")

    for eid in hyp.get("supporting_evidence_ids", []):
        if not isinstance(eid, str):
            errors.append(f"hypotheses[{index}] evidence_id is not a string: {eid}")
        elif eid not in valid_evidence_ids:
            errors.append(f"hypotheses[{index}] references unknown evidence_id: '{eid}'")

    if not hyp.get("missing_evidence"):
        warnings.append(f"hypotheses[{index}] has empty missing_evidence — should describe what is absent")


def _validate_confidence(conf: Any, index: int,
                          errors: List[str], warnings: List[str]) -> None:
    if not isinstance(conf, dict):
        errors.append(f"confidence[{index}] is not a dict")
        return
    level = conf.get("level")
    if level not in _VALID_CONFIDENCE_LEVELS:
        errors.append(f"confidence[{index}] has unsupported level '{level}'; must be one of {sorted(_VALID_CONFIDENCE_LEVELS)}")
    if not conf.get("text", "").strip():
        warnings.append(f"confidence[{index}] text is empty")


def _validate_priority(pri: Any, index: int,
                        errors: List[str], warnings: List[str]) -> None:
    if not isinstance(pri, dict):
        errors.append(f"investigation_priorities[{index}] is not a dict")
        return
    if not pri.get("text", "").strip():
        warnings.append(f"investigation_priorities[{index}] text is empty")


def _build_assessment(data: Dict[str, Any],
                       errors: List[str],
                       warnings: List[str]) -> Optional[AnalystAssessment]:
    """Attempt to construct an AnalystAssessment from validated (or partially valid) data."""
    try:
        return AnalystAssessment(
            package_id=data.get("package_id", ""),
            executive_assessment=data.get("executive_assessment", ""),
            observed_facts=[_parse_fact(f) for f in data.get("observed_facts", [])],
            supported_relationships=[_parse_rel(r) for r in data.get("supported_relationships", [])],
            hypotheses=[_parse_hyp(h) for h in data.get("hypotheses", [])],
            unknowns=data.get("unknowns", []),
            confidence=[_parse_conf(c) for c in data.get("confidence", [])],
            investigation_priorities=[_parse_pri(p) for p in data.get("investigation_priorities", [])],
            analyst_summary=data.get("analyst_summary", ""),
        )
    except (TypeError, ValueError, KeyError) as exc:
        errors.append(f"Cannot construct AnalystAssessment: {exc}")
        return None


def _parse_fact(d: Any) -> AnalystFact:
    if isinstance(d, dict):
        return AnalystFact(
            text=d.get("text", ""),
            alert_ids=list(d.get("alert_ids", [])),
            evidence_ids=list(d.get("evidence_ids", [])),
        )
    return AnalystFact(text=str(d) if d else "")


def _parse_rel(d: Any) -> AnalystRelationship:
    if isinstance(d, dict):
        return AnalystRelationship(
            text=d.get("text", ""),
            alert_ids=list(d.get("alert_ids", [])),
            evidence_ids=list(d.get("evidence_ids", [])),
        )
    return AnalystRelationship(text=str(d) if d else "")


def _parse_hyp(d: Any) -> AnalystHypothesis:
    if isinstance(d, dict):
        return AnalystHypothesis(
            text=d.get("text", ""),
            supporting_alert_ids=list(d.get("supporting_alert_ids", [])),
            supporting_evidence_ids=list(d.get("supporting_evidence_ids", [])),
            missing_evidence=list(d.get("missing_evidence", [])),
        )
    return AnalystHypothesis(text=str(d) if d else "")


def _parse_conf(d: Any) -> AnalystConfidence:
    if isinstance(d, dict):
        return AnalystConfidence(text=d.get("text", ""), level=d.get("level", "low"))
    return AnalystConfidence(text=str(d) if d else "", level="low")


def _parse_pri(d: Any) -> AnalystPriority:
    if isinstance(d, dict):
        return AnalystPriority(
            text=d.get("text", ""),
            rationale=d.get("rationale", ""),
            resolves_uncertainty=d.get("resolves_uncertainty", ""),
        )
    return AnalystPriority(text=str(d) if d else "")
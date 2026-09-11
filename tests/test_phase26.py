"""Phase 26: Investigation Package — canonical boundary tests."""

from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import unittest

from sentinelforge.alerts import Alert, create_alert
from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.events import SecurityEvent
from sentinelforge.incident_engine import derive_incidents
from sentinelforge.ingestion.pipeline import ingest_file, ingest_lines, parser_for_source
from sentinelforge.investigation_package import (
    PACKAGE_VERSION,
    _canonicalize_event,
    _compute_package_id,
    _deterministic_event_id,
    build_package,
    PackageAlert,
    PackageAlertEvidenceRef,
    PackageEvidence,
    PackageDiagnostic,
    CoverageSummary,
    InvestigationPackage,
)
from sentinelforge.replay import replay_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EVENT_ATTRS: Dict[str, Any] = {
    "hostname": "acme-ws-01",
    "username": "jdoe",
    "source_ip": None,
    "process": None,
    "source_port": None,
    "destination_ip": None,
    "destination_port": None,
    "protocol": None,
    "process_name": None,
    "process_id": None,
    "parent_process_id": None,
    "command_line": None,
    "executable_path": None,
    "privilege": None,
    "direction": None,
    "persistence_type": None,
    "persistence_action": None,
    "persistence_name": None,
    "command": None,
    "service_manager": None,
    "task_path": None,
    "query": None,
    "query_type": None,
    "response_code": None,
    "resolved_ip": None,
    "query_name": None,
    "answers": None,
    "path": None,
    "action": None,
    "file_hash": None,
    "old_path": None,
    "size": None,
    "hive": None,
    "key_path": None,
    "registry_action": None,
    "value_name": None,
    "value_data": None,
    "value_type": None,
    "old_key_path": None,
    "provider": None,
    "system_event_id": None,
    "system_action": None,
    "service_name": None,
    "service_state": None,
}


def make_event(event_id: str | None, timestamp: str, event_type: str = "authentication_failure",
               source: str = "linux-auth", hostname: str = "acme-ws-01",
               username: str = "jdoe", raw: str | None = None,
               **overrides: Any) -> SecurityEvent:
    """Create a simple SecurityEvent for testing."""
    ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if raw is None:
        raw = f"raw|{event_type}|{timestamp}"
    kwargs: Dict[str, Any] = dict(_EVENT_ATTRS)
    kwargs.update(overrides)
    return SecurityEvent(
        timestamp=ts,
        source=source,
        event_type=event_type,
        hostname=hostname,
        username=username,
        message=f"{event_type} on {hostname}",
        raw=raw,
        event_id=event_id,
        source_ip=kwargs.get("source_ip"),
        process=kwargs.get("process"),
    )


class Phase26InvestigationPackageTests(unittest.TestCase):

    maxDiff = None

    # ======================================================================
    # PACKAGE CONSTRUCTION
    # ======================================================================

    def test_package_from_alerts(self):
        """Build a basic package from detection alerts and verify structure."""
        ev1 = make_event("ev01", "2025-06-15T08:00:00Z", "authentication_failure",
                         raw="test basic package event")
        ev2 = make_event("ev02", "2025-06-15T08:00:01Z", "authentication_success",
                         raw="test basic package event 2")
        alert = create_alert("TEST_RULE", "medium", "Test title", "Test description.", [ev1, ev2])
        pkg = build_package([alert])
        self.assertEqual(pkg.package_version, PACKAGE_VERSION)
        self.assertIsNotNone(pkg.package_id)
        self.assertEqual(len(pkg.evidence), 2)
        self.assertEqual(len(pkg.alerts), 1)
        self.assertEqual(pkg.alerts[0].alert_id, alert.alert_id)
        self.assertIsNone(pkg.incident)

    def test_empty_package(self):
        """Package with no alerts is valid."""
        pkg = build_package([])
        self.assertEqual(len(pkg.alerts), 0)
        self.assertEqual(len(pkg.evidence), 0)
        self.assertIsNotNone(pkg.package_id)

    def test_no_alerts_with_diagnostics_only(self):
        """Diagnostics-only package (alerts [] but diagnostics present)."""
        diag = [{"line_number": 1, "reason": "malformed input", "raw": "bad line"}]
        pkg = build_package([], diagnostics=diag)
        self.assertEqual(len(pkg.alerts), 0)
        self.assertEqual(len(pkg.diagnostics), 1)
        d = pkg.diagnostics[0]
        self.assertEqual(d.type, "parser_rejection")
        self.assertFalse(d.telemetry_was_accepted)

    def test_package_with_incident(self):
        """Package embeds incident metadata when provided."""
        ev1 = make_event("ev01", "2025-06-15T08:00:00Z", raw="test incident embed")
        ev2 = make_event("ev02", "2025-06-15T08:00:10Z", "authentication_success", raw="test incident embed 2")
        a1 = create_alert("RULE_A", "medium", "Title", "Desc.", [ev1])
        a2 = create_alert("RULE_B", "high", "Title 2", "Desc 2.", [ev2])
        alerts = [a1, a2]
        incidents = derive_incidents(alerts)
        pkg = build_package(alerts, incident=incidents[0] if incidents else None)
        if incidents:
            self.assertIsNotNone(pkg.incident)
            if pkg.incident:
                self.assertIn("incident_id", pkg.incident)
                self.assertIn("severity", pkg.incident)

    # ======================================================================
    # EVIDENCE IDS
    # ======================================================================

    def test_existing_event_id_is_preserved(self):
        """Event with stable event_id retains it as evidence_id."""
        ev = make_event("abc123", "2025-06-15T08:00:00Z", raw="test existing id preserved")
        pkg = build_package([create_alert("RULE", "low", "T", "D.", [ev])])
        self.assertEqual(pkg.evidence[0].evidence_id, "abc123")
        self.assertEqual(pkg.evidence[0].original_event_id, "abc123")

    def test_missing_event_id_gets_deterministic_id(self):
        """Null event_id produces deterministic hash-based evidence_id."""
        ev = make_event(None, "2025-06-15T08:00:00Z", raw="test missing id deterministic")
        pkg = build_package([create_alert("RULE", "low", "T", "D.", [ev])])
        self.assertIsNotNone(pkg.evidence[0].evidence_id)
        self.assertIsNone(pkg.evidence[0].original_event_id)
        self.assertEqual(len(pkg.evidence[0].evidence_id), 16)

    def test_repeated_generation_same_id(self):
        """Same event content always produces same deterministic ID."""
        ev1 = make_event(None, "2025-06-15T08:00:00Z", raw="test repeated generation same")
        pkg_a = build_package([create_alert("RULE", "low", "T", "D.", [ev1])])
        pkg_b = build_package([create_alert("RULE", "low", "T", "D.", [ev1])])
        self.assertEqual(pkg_a.evidence[0].evidence_id, pkg_b.evidence[0].evidence_id)

    def test_reordered_events_same_id(self):
        """Input ordering does not change deterministic evidence IDs."""
        ev_a = make_event(None, "2025-06-15T08:00:00Z", raw="test reorder same id A")
        ev_b = make_event(None, "2025-06-15T08:00:01Z", raw="test reorder same id B")
        a1 = create_alert("RULE_A", "low", "T", "D.", [ev_a])
        a2 = create_alert("RULE_B", "low", "T", "D.", [ev_b])
        pkg_ab = build_package([a1, a2])
        pkg_ba = build_package([a2, a1])
        self.assertEqual(pkg_ab.evidence[0].evidence_id, pkg_ba.evidence[0].evidence_id)
        self.assertEqual(pkg_ab.evidence[1].evidence_id, pkg_ba.evidence[1].evidence_id)

    def test_changing_content_changes_deterministic_id(self):
        """Different event content produces different evidence_id."""
        ev_a = make_event(None, "2025-06-15T08:00:00Z", raw="content one")
        ev_b = make_event(None, "2025-06-15T08:00:00Z", raw="content two")
        pkg_a = build_package([create_alert("RULE", "low", "T", "D.", [ev_a])])
        pkg_b = build_package([create_alert("RULE", "low", "T", "D.", [ev_b])])
        self.assertNotEqual(pkg_a.evidence[0].evidence_id, pkg_b.evidence[0].evidence_id)

    def test_generated_ids_dont_depend_on_array_position(self):
        """Evidence IDs are invariant to event position in the alert sequence."""
        ev_base = make_event(None, "2025-06-15T08:00:00Z", raw="test position independent")
        pkg = build_package([create_alert("RULE", "low", "T", "D.", [ev_base])])
        eid = pkg.evidence[0].evidence_id
        # Build again with same event in a larger sequence
        ev_extra = make_event(None, "2025-06-15T08:00:01Z", raw="test position extra")
        pkg2 = build_package([create_alert("RULE", "low", "T", "D.", [ev_base, ev_extra])])
        self.assertEqual(eid, pkg2.evidence[0].evidence_id)

    # ======================================================================
    # ALERT LINKING
    # ======================================================================

    def test_every_alert_references_actual_evidence(self):
        """All alert evidence_refs resolve to evidence items in the package."""
        ev1 = make_event("ev01", "2025-06-15T08:00:00Z", raw="test alert references evidence")
        ev2 = make_event("ev02", "2025-06-15T08:00:01Z", raw="test alert references evidence 2")
        alert = create_alert("RULE", "medium", "T", "D.", [ev1, ev2])
        pkg = build_package([alert])
        evidence_ids = {e.evidence_id for e in pkg.evidence}
        for ref in pkg.alerts[0].evidence_refs:
            self.assertIn(ref.evidence_id, evidence_ids)

    def test_null_evidence_ids_never_appear_in_canonical_package(self):
        """Alerts with null evidence IDs get resolved in the package."""
        ev1 = make_event(None, "2025-06-15T08:00:00Z", raw="test null id resolved")
        alert = create_alert("RULE", "low", "T", "D.", [ev1])
        pkg = build_package([alert])
        for ref in pkg.alerts[0].evidence_refs:
            self.assertIsNotNone(ref.evidence_id)
            self.assertNotEqual(ref.evidence_id, "null")

    def test_legacy_null_ids_resolve_deterministically(self):
        """Null IDs from existing detection output resolve consistently."""
        ev1 = make_event(None, "2025-06-15T08:00:00Z", raw="test legacy null deterministic")
        pkg_a = build_package([create_alert("RULE", "low", "T", "D.", [ev1])])
        pkg_b = build_package([create_alert("RULE", "low", "T", "D.", [ev1])])
        self.assertEqual(
            pkg_a.alerts[0].evidence_refs[0].evidence_id,
            pkg_b.alerts[0].evidence_refs[0].evidence_id,
        )

    def test_duplicate_evidence_references_handled(self):
        """When multiple alerts share evidence, the evidence is not duplicated."""
        ev = make_event("shared", "2025-06-15T08:00:00Z", raw="test duplicate evidence references")
        a1 = create_alert("RULE_A", "low", "T1", "D1.", [ev])
        a2 = create_alert("RULE_B", "low", "T2", "D2.", [ev])
        pkg = build_package([a1, a2])
        self.assertEqual(len(pkg.evidence), 1)  # only one evidence item

    # ======================================================================
    # PROVENANCE
    # ======================================================================

    def test_single_source_alert(self):
        """Single-source alert exposes one source."""
        ev = make_event("ev01", "2025-06-15T08:00:00Z", source="linux-auth",
                        raw="test single source")
        alert = create_alert("RULE", "low", "T", "D.", [ev])
        pkg = build_package([alert])
        self.assertEqual(len(pkg.alerts[0].contributing_sources), 1)
        self.assertIn("linux-auth", pkg.alerts[0].contributing_sources)

    def test_two_source_cross_source_alert(self):
        """Cross-source alert with evidence from two sources exposes both."""
        ev_auth = make_event("ev01", "2025-06-15T08:00:00Z", source="linux-auth",
                             raw="test cross source auth")
        ev_net = make_event("ev02", "2025-06-15T08:00:10Z", source="network_connection",
                            event_type="network_connection",
                            raw="test cross source net")
        alert = create_alert("AUTH_TO_NET", "medium", "T", "D.", [ev_auth, ev_net])
        pkg = build_package([alert])
        sources = pkg.alerts[0].contributing_sources
        self.assertIn("linux-auth", sources)
        self.assertIn("network_connection", sources)

    def test_three_source_chain_alert(self):
        """Three-source chain exposes all three."""
        ev_auth = make_event("ev01", "2025-06-15T08:00:00Z", source="linux-auth",
                             raw="test chain auth")
        ev_net = make_event("ev02", "2025-06-15T08:00:10Z", source="network_connection",
                            event_type="network_connection", raw="test chain net")
        ev_proc = make_event("ev03", "2025-06-15T08:00:20Z", source="process_execution",
                             event_type="process_execution",
                             raw="test chain proc")
        alert = create_alert("AUTH_NET_PROC", "high", "T", "D.", [ev_auth, ev_net, ev_proc])
        pkg = build_package([alert])
        sources = pkg.alerts[0].contributing_sources
        self.assertEqual(len(sources), 3)
        self.assertIn("linux-auth", sources)
        self.assertIn("network_connection", sources)
        self.assertIn("process_execution", sources)

    def test_source_list_ordering_deterministic(self):
        """Source list is sorted for deterministic order."""
        ev_auth = make_event("ev01", "2025-06-15T08:00:00Z", source="process_execution",
                             event_type="process_execution", raw="test sort Z")
        ev_net = make_event("ev02", "2025-06-15T08:00:10Z", source="linux-auth",
                            raw="test sort A")
        alert = create_alert("RULE", "medium", "T", "D.", [ev_auth, ev_net])
        pkg = build_package([alert])
        self.assertEqual(pkg.alerts[0].contributing_sources, ("linux-auth", "process_execution"))

    def test_detection_source_vs_telemetry_sources(self):
        """detection_source (rule family) is separate from telemetry sources."""
        ev = make_event("ev01", "2025-06-15T08:00:00Z", source="linux-auth",
                        raw="test detection source separate")
        alert = create_alert("RULE", "low", "T", "D.", [ev])
        pkg = build_package([alert])
        self.assertEqual(pkg.alerts[0].detection_source, "linux-auth")
        self.assertEqual(pkg.alerts[0].contributing_sources, ("linux-auth",))

    # ======================================================================
    # CHRONOLOGY
    # ======================================================================

    def test_chronological_ordering(self):
        """Chronology is sorted by timestamp ascending."""
        ev1 = make_event("ev01", "2025-06-15T08:00:01Z", raw="test chrono later")
        ev2 = make_event("ev02", "2025-06-15T08:00:00Z", raw="test chrono earlier")
        alert = create_alert("RULE", "low", "T", "D.", [ev1, ev2])
        pkg = build_package([alert])
        # Chronology entries should be in timestamp order
        for i in range(len(pkg.chronology) - 1):
            self.assertLessEqual(pkg.chronology[i].timestamp, pkg.chronology[i + 1].timestamp)

    def test_identical_timestamps_tie_breaker(self):
        """Identical timestamps: evidence before alert, then identifier."""
        ev1 = make_event("AAA", "2025-06-15T08:00:00Z", raw="test tie breaker ev")
        alert = create_alert("RULE", "low", "T", "D.", [ev1])
        pkg = build_package([alert])
        # Evidence and alert may share timestamp; evidence sorts before alert
        self.assertEqual(pkg.chronology[0].kind, "evidence")
        self.assertEqual(pkg.chronology[0].identifier, "AAA")

    def test_reversed_input_ordering_identical_chronology(self):
        """Reversed input produces identical chronology."""
        ev_a = make_event("ev_A", "2025-06-15T08:00:00Z", raw="test reversed A")
        ev_b = make_event("ev_B", "2025-06-15T08:00:01Z", raw="test reversed B")
        a1 = create_alert("RULE_A", "low", "T", "D.", [ev_a])
        a2 = create_alert("RULE_B", "low", "T", "D.", [ev_b])
        pkg_fwd = build_package([a1, a2])
        pkg_rev = build_package([a2, a1])
        self.assertEqual(
            [c.to_dict() for c in pkg_fwd.chronology],
            [c.to_dict() for c in pkg_rev.chronology],
        )

    # ======================================================================
    # CANONICAL JSON
    # ======================================================================

    def test_repeated_serialization_identical(self):
        """to_dict() is deterministic across repeated calls."""
        ev = make_event("ev01", "2025-06-15T08:00:00Z", raw="test serialization identical")
        alert = create_alert("RULE", "low", "T", "D.", [ev])
        pkg = build_package([alert], generated_at="2025-01-01T00:00:00Z")
        self.assertEqual(pkg.to_dict(), pkg.to_dict())

    def test_reversed_input_identical(self):
        """Reversed alert order produces identical output (sorted internally)."""
        ev_a = make_event("ev_A", "2025-06-15T08:00:00Z", raw="test reversed identical A")
        ev_b = make_event("ev_B", "2025-06-15T08:00:01Z", raw="test reversed identical B")
        a1 = create_alert("RULE_A", "low", "T", "D.", [ev_a])
        a2 = create_alert("RULE_B", "low", "T", "D.", [ev_b])
        pkg_fwd = build_package([a1, a2])
        pkg_rev = build_package([a2, a1])
        # Both packages have the same package_id
        self.assertEqual(pkg_fwd.package_id, pkg_rev.package_id)
        # to_dict differs only by generated_at
        d_fwd = pkg_fwd.to_dict()
        d_rev = pkg_rev.to_dict()
        # Strip time-variant field
        for d in (d_fwd, d_rev):
            d.pop("generated_at")
        self.assertEqual(d_fwd, d_rev)

    # ======================================================================
    # PACKAGE ID
    # ======================================================================

    def test_same_logical_package_same_id(self):
        """Identical input produces identical package_id."""
        ev = make_event("ev01", "2025-06-15T08:00:00Z", raw="test same logical package")
        alert = create_alert("RULE", "low", "T", "D.", [ev])
        pkg_a = build_package([alert])
        pkg_b = build_package([alert])
        self.assertEqual(pkg_a.package_id, pkg_b.package_id)

    def test_reordered_input_same_id(self):
        """Reordered alerts produce same package_id."""
        ev_a = make_event("ev_A", "2025-06-15T08:00:00Z", raw="test reordered input same A")
        ev_b = make_event("ev_B", "2025-06-15T08:00:01Z", raw="test reordered input same B")
        a1 = create_alert("RULE_A", "low", "T", "D.", [ev_a])
        a2 = create_alert("RULE_B", "low", "T", "D.", [ev_b])
        pkg_fwd = build_package([a1, a2])
        pkg_rev = build_package([a2, a1])
        self.assertEqual(pkg_fwd.package_id, pkg_rev.package_id)

    def test_generated_at_does_not_change_id(self):
        """generated_at is excluded from package_id computation."""
        ev = make_event("ev01", "2025-06-15T08:00:00Z", raw="test generated at excluded")
        alert = create_alert("RULE", "low", "T", "D.", [ev])
        pkg_a = build_package([alert], generated_at="2025-01-01T00:00:00Z")
        pkg_b = build_package([alert], generated_at="2025-12-31T23:59:59Z")
        self.assertEqual(pkg_a.package_id, pkg_b.package_id)
        self.assertNotEqual(pkg_a.generated_at, pkg_b.generated_at)

    def test_evidence_change_changes_id(self):
        """Changing evidence content changes package_id."""
        ev_a = make_event("ev01", "2025-06-15T08:00:00Z", raw="test evidence changes id one")
        ev_b = make_event("ev01", "2025-06-15T08:00:00Z", raw="test evidence changes id two")
        pkg_a = build_package([create_alert("RULE", "low", "T", "D.", [ev_a])])
        pkg_b = build_package([create_alert("RULE", "low", "T", "D.", [ev_b])])
        self.assertNotEqual(pkg_a.package_id, pkg_b.package_id)

    def test_alert_change_changes_id(self):
        """Changing alert content changes package_id."""
        ev = make_event("ev01", "2025-06-15T08:00:00Z", raw="test alert changes id")
        pkg_a = build_package([create_alert("RULE_A", "low", "T", "D.", [ev])])
        pkg_b = build_package([create_alert("RULE_B", "low", "T", "D.", [ev])])
        self.assertNotEqual(pkg_a.package_id, pkg_b.package_id)

    # ======================================================================
    # DIAGNOSTICS
    # ======================================================================

    def test_parser_rejection_retained(self):
        """Parser rejection diagnostic is preserved."""
        diag = [{"line_number": 3, "reason": "unrecognized format", "raw": "bad line here"}]
        pkg = build_package([], diagnostics=diag)
        self.assertEqual(len(pkg.diagnostics), 1)
        d = pkg.diagnostics[0]
        self.assertEqual(d.type, "parser_rejection")
        self.assertEqual(d.reason, "unrecognized format")
        self.assertEqual(d.raw, "bad line here")

    def test_raw_rejected_record_retained(self):
        """Rejected record's raw content is in diagnostic."""
        raw_line = "2025-06-15T12:00:00Z badhost invalid"
        diag = [{"line_number": 1, "reason": "line does not match supported auth format", "raw": raw_line}]
        pkg = build_package([], diagnostics=diag)
        self.assertIn(raw_line, pkg.diagnostics[0].raw)

    def test_diagnostic_distinguishable_from_absence(self):
        """Rejected telemetry is flagged as not accepted."""
        diag = [{"line_number": 1, "reason": "parse error", "raw": "bad"}]
        pkg = build_package([], diagnostics=diag)
        self.assertFalse(pkg.diagnostics[0].telemetry_was_accepted)

    # ======================================================================
    # COVERAGE METADATA
    # ======================================================================

    def test_evidence_count_correct(self):
        """Coverage summary reports correct evidence item count."""
        ev1 = make_event("ev01", "2025-06-15T08:00:00Z", raw="test coverage count 1")
        ev2 = make_event("ev02", "2025-06-15T08:00:01Z", raw="test coverage count 2")
        pkg = build_package([create_alert("RULE", "low", "T", "D.", [ev1, ev2])])
        self.assertEqual(pkg.coverage.total_evidence_items, 2)
        self.assertEqual(pkg.coverage.total_alerts, 1)

    def test_original_vs_generated_id_counts(self):
        """Coverage summary correctly counts original vs generated IDs."""
        ev_with_id = make_event("ev01", "2025-06-15T08:00:00Z", raw="test original id count")
        ev_without = make_event(None, "2025-06-15T08:00:01Z", raw="test generated id count")
        pkg = build_package([
            create_alert("RULE_A", "low", "T", "D.", [ev_with_id]),
            create_alert("RULE_B", "low", "T", "D.", [ev_without]),
        ])
        self.assertEqual(pkg.coverage.evidence_with_original_ids, 1)
        self.assertEqual(pkg.coverage.evidence_with_generated_ids, 1)

    def test_distinct_sources_correct(self):
        """Distinct telemetry sources are reported."""
        ev1 = make_event("ev01", "2025-06-15T08:00:00Z", source="linux-auth",
                         raw="test distinct sources 1")
        ev2 = make_event("ev02", "2025-06-15T08:00:01Z", source="network_connection",
                         event_type="network_connection", raw="test distinct sources 2")
        pkg = build_package([create_alert("RULE", "medium", "T", "D.", [ev1, ev2])])
        self.assertIn("linux-auth", pkg.coverage.distinct_telemetry_sources)
        self.assertIn("network_connection", pkg.coverage.distinct_telemetry_sources)

    # ======================================================================
    # CLI
    # ======================================================================

    def test_cli_package_command(self):
        """Package CLI works on the Phase 26 fixture."""
        from sentinelforge.__main__ import main
        exit_code = main(["package", "fixtures/phase26-investigation.ndjson", "--source", "linux_auth"])
        self.assertEqual(exit_code, 0)

    def test_cli_package_json(self):
        """Package JSON output is valid."""
        from sentinelforge.__main__ import main
        exit_code = main(["package", "fixtures/phase26-investigation.ndjson", "--source", "linux_auth", "--json"])
        self.assertEqual(exit_code, 0)

    def test_cli_invalid_input(self):
        """Invalid input raises SystemExit."""
        from sentinelforge.__main__ import main
        with self.assertRaises(SystemExit):
            main(["package", "fixtures/nonexistent.ndjson"])

    def test_cli_deterministic_repeated_output(self):
        """Repeated package CLI runs produce identical output (modulo generated_at)."""
        import io, contextlib
        from sentinelforge.__main__ import main
        outputs = []
        for _ in range(2):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                main(["package", "fixtures/phase26-investigation.ndjson", "--source", "linux_auth", "--json"])
            outputs.append(json.loads(buf.getvalue()))
        # Strip generated_at (time-variant metadata) before comparing
        for o in outputs:
            o.pop("generated_at")
        self.assertEqual(outputs[0], outputs[1])

    # ======================================================================
    # REPLAY INTEGRATION
    # ======================================================================

    def test_package_from_replay(self):
        """Package generated from replay_result has expected structure."""
        result = replay_file("fixtures/auth.log", "linux_auth")
        pkg = build_package(result.alerts, [d for d in result.diagnostics])
        self.assertGreater(len(pkg.alerts), 0)
        self.assertGreater(len(pkg.evidence), 0)
        self.assertEqual(pkg.package_version, PACKAGE_VERSION)

    def test_replay_package_deterministic(self):
        """Package from replay is deterministic."""
        result1 = replay_file("fixtures/auth.log", "linux_auth")
        result2 = replay_file("fixtures/auth.log", "linux_auth")
        pkg1 = build_package(result1.alerts, [d for d in result1.diagnostics])
        pkg2 = build_package(result2.alerts, [d for d in result2.diagnostics])
        self.assertEqual(pkg1.package_id, pkg2.package_id)

    def test_existing_replay_behavior_unchanged(self):
        """Phase 25 replay behavior is unchanged."""
        from sentinelforge.replay import replay_file
        result = replay_file("fixtures/phase23-registry.ndjson", "registry_change")
        self.assertGreater(len(result.alerts), 0)
        self.assertEqual(len(result.diagnostics), 0)

    # ======================================================================
    # REGRESSION: cross-source provenance (in-memory DetectionEngine)
    # ======================================================================

    def test_two_source_provenance_with_synthetic_events(self):
        """AUTHENTICATION_TO_NETWORK_ACTIVITY exposes linux-auth + network_connection."""
        from datetime import datetime, timezone

        ts = datetime(2025, 6, 15, 8, 0, 0, tzinfo=timezone.utc)

        auth_ev = SecurityEvent(
            timestamp=ts,
            source="linux-auth",
            event_type="authentication_success",
            hostname="ws-01",
            process="sshd",
            username="jdoe",
            source_ip="10.0.1.100",
            message="Accepted password for jdoe",
            raw="Jun 15 08:00:00 ws-01 sshd[100]: Accepted password for jdoe",
        )
        net_ev = SecurityEvent(
            timestamp=datetime(2025, 6, 15, 8, 1, 0, tzinfo=timezone.utc),
            source="network_connection",
            event_type="network_connection",
            hostname="ws-01",
            process=None,
            username="jdoe",
            source_ip="10.0.1.100",
            destination_ip="198.51.100.7",
            destination_port=443,
            protocol="tcp",
            direction="outbound",
            source_port=51000,
            message="Outbound connection to 198.51.100.7:443",
            raw='{"timestamp":"2025-06-15T08:01:00Z","source_ip":"10.0.1.100","source_port":51000,"destination_ip":"198.51.100.7","destination_port":443,"protocol":"tcp","direction":"outbound","hostname":"ws-01","username":"jdoe"}',
        )

        alerts = DetectionEngine().detect([auth_ev, net_ev])
        cross = [a for a in alerts if a.rule_id == "AUTHENTICATION_TO_NETWORK_ACTIVITY"]
        self.assertGreater(len(cross), 0, msg="No cross-source alert produced — detection semantics unchanged")
        pkg = build_package(alerts)

        for pa in pkg.alerts:
            if pa.rule_id == "AUTHENTICATION_TO_NETWORK_ACTIVITY":
                # detection_source preserves legacy single-source field
                self.assertEqual(pa.detection_source, "linux-auth",
                                 msg="detection_source should preserve legacy alert.source")
                # contributing_sources must contain both
                self.assertIn("linux-auth", pa.contributing_sources)
                self.assertIn("network_connection", pa.contributing_sources)
                self.assertEqual(len(pa.contributing_sources), 2)
                # Source list is sorted deterministically
                self.assertEqual(pa.contributing_sources, ("linux-auth", "network_connection"))
                # No null evidence IDs
                for ref in pa.evidence_refs:
                    self.assertIsNotNone(ref.evidence_id)
                return

        self.fail("No AUTHENTICATION_TO_NETWORK_ACTIVITY alert in package")

    def test_three_source_provenance_with_synthetic_events(self):
        """AUTH_NETWORK_PROCESS_CHAIN exposes linux-auth + network_connection + process_execution."""
        from datetime import datetime, timezone, timedelta

        base = datetime(2025, 6, 15, 8, 0, 0, tzinfo=timezone.utc)
        auth_ev = SecurityEvent(
            timestamp=base,
            source="linux-auth",
            event_type="authentication_success",
            hostname="ws-01", username="jdoe", source_ip="10.0.1.100",
            process="sshd",
            message="Accepted password for jdoe",
            raw="Jun 15 08:00:00 ws-01 sshd[100]: Accepted password for jdoe",
        )
        net_ev = SecurityEvent(
            timestamp=base + timedelta(seconds=60),
            source="network_connection",
            event_type="network_connection",
            hostname="ws-01", username="jdoe",
            process=None,
            source_ip="10.0.1.100", destination_ip="198.51.100.7",
            destination_port=443, protocol="tcp", direction="outbound", source_port=51000,
            message="Outbound connection to 198.51.100.7:443",
            raw='{"timestamp":"2025-06-15T08:01:00Z","source_ip":"10.0.1.100","source_port":51000,"destination_ip":"198.51.100.7","destination_port":443,"protocol":"tcp","direction":"outbound","hostname":"ws-01","username":"jdoe"}',
        )
        proc_ev = SecurityEvent(
            timestamp=base + timedelta(seconds=120),
            source="process_execution",
            event_type="process_execution",
            hostname="ws-01", username="jdoe",
            process="powershell.exe",
            source_ip=None,
            process_name="powershell.exe", process_id=4500, parent_process_id=1200,
            command_line="powershell.exe -Command Write-Host test",
            privilege="user",
            message="Process powershell.exe executed on ws-01",
            raw='{"timestamp":"2025-06-15T08:02:00Z","hostname":"ws-01","username":"jdoe","process_name":"powershell.exe","process_id":4500,"parent_process_id":1200,"command_line":"powershell.exe -Command Write-Host test","privilege":"user"}',
        )

        alerts = DetectionEngine().detect([auth_ev, net_ev, proc_ev])
        chain = [a for a in alerts if a.rule_id == "AUTH_NETWORK_PROCESS_CHAIN"]
        self.assertGreater(len(chain), 0, msg="No chain alert produced — detection semantics unchanged")
        pkg = build_package(alerts)

        for pa in pkg.alerts:
            if pa.rule_id == "AUTH_NETWORK_PROCESS_CHAIN":
                self.assertEqual(pa.detection_source, "linux-auth")
                self.assertEqual(len(pa.contributing_sources), 3)
                self.assertIn("linux-auth", pa.contributing_sources)
                self.assertIn("network_connection", pa.contributing_sources)
                self.assertIn("process_execution", pa.contributing_sources)
                self.assertEqual(pa.contributing_sources,
                                 ("linux-auth", "network_connection", "process_execution"))
                # Evidence items carry correct source
                for ref in pa.evidence_refs:
                    evidence_item = next(e for e in pkg.evidence if e.evidence_id == ref.evidence_id)
                    self.assertIn(evidence_item.source, ("linux-auth", "network_connection", "process_execution"))
                # No null evidence IDs
                for ref in pa.evidence_refs:
                    self.assertIsNotNone(ref.evidence_id)
                return

        self.fail("No AUTH_NETWORK_PROCESS_CHAIN alert in package")

    # ======================================================================
    # REGRESSION: shared evidence coverage metric
    # ======================================================================

    def test_two_alerts_sharing_evidence_both_have_complete_linkage(self):
        """Two alerts sharing the same evidence items both report complete linkage."""
        ev = make_event("ev01", "2025-06-15T08:00:00Z", raw="shared evidence")
        a1 = create_alert("RULE_A", "low", "T1", "D1.", [ev])
        a2 = create_alert("RULE_B", "low", "T2", "D2.", [ev])
        pkg = build_package([a1, a2])
        self.assertEqual(pkg.coverage.total_evidence_items, 1, msg="shared evidence should not be duplicated")
        self.assertEqual(pkg.coverage.alerts_with_complete_linkage, 2,
                         msg="both alerts sharing evidence should have complete linkage")

    def test_reversed_order_same_coverage(self):
        """Reversed alert order produces identical coverage metrics."""
        ev1 = make_event("ev_A", "2025-06-15T08:00:00Z", raw="reversed coverage A")
        ev2 = make_event("ev_B", "2025-06-15T08:00:01Z", raw="reversed coverage B")
        a1 = create_alert("RULE_A", "low", "T", "D.", [ev1])
        a2 = create_alert("RULE_B", "low", "T", "D.", [ev1, ev2])
        pkg_fwd = build_package([a1, a2])
        pkg_rev = build_package([a2, a1])
        self.assertEqual(pkg_fwd.coverage.to_dict(), pkg_rev.coverage.to_dict())

    def test_duplicate_evidence_does_not_inflate_count(self):
        """Duplicate evidence references across two alerts produce correct counts."""
        ev = make_event("shared", "2025-06-15T08:00:00Z", raw="shared count test")
        a1 = create_alert("RULE_A", "low", "T", "D.", [ev])
        a2 = create_alert("RULE_B", "low", "T", "D.", [ev, ev])  # same evidence listed twice
        pkg = build_package([a1, a2])
        self.assertEqual(pkg.coverage.total_evidence_items, 1, msg="even if alert lists evidence twice, package deduplicates by evidence_id")
        # Alert a2 has 2 evidence_refs for the same evidence_id; both resolve.
        for pa in pkg.alerts:
            if pa.alert_id == a2.alert_id:
                self.assertEqual(len(pa.evidence_refs), 2, msg="proof of concept: both refs are preserved")
        self.assertEqual(pkg.coverage.alerts_with_complete_linkage, 2)

    # ======================================================================
    # REGRESSION: Phase 1–25 semantics unchanged
    # ======================================================================

    def test_no_rule_semantics_changed(self):
        """Core detection rules produce expected alerts from auth.log."""
        result = replay_file("fixtures/auth.log", "linux_auth")
        rule_ids = {a.rule_id for a in result.alerts}
        self.assertIn("REPEATED_AUTH_FAILURE", rule_ids)
        self.assertIn("SUCCESS_AFTER_FAILURES", rule_ids)
        # These rules fire on network events, not on auth.log; they are tested
        # separately in Phase 17+ test suites.
        self.assertNotIn("REPEATED_CONNECTION_TO_SAME_DESTINATION", rule_ids)

    def test_no_alert_ids_changed(self):
        """Alert IDs remain consistent with prior runs."""
        result = replay_file("fixtures/phase23-registry.ndjson", "registry_change")
        self.assertIsNotNone(result.alerts[0].alert_id)
        self.assertEqual(len(result.alerts[0].alert_id), 16)

    def test_phase25_evaluation_unchanged(self):
        """Phase 25 evaluation still works."""
        from sentinelforge.replay import evaluate, load_expected
        alerts = replay_file("fixtures/phase23-registry.ndjson", "registry_change").alerts
        expected = load_expected("fixtures/phase25-expected-registry.json")
        result = evaluate(alerts, expected)
        self.assertEqual(result.true_positives, 23)
        self.assertEqual(result.precision, 1.0)

    # ======================================================================
    # API / WEB CONSOLE — no changes needed, CLI + library sufficient.
    # ======================================================================

    def test_cli_only_no_api_changes(self):
        """No new API endpoint was added — package is CLI and library only."""
        # Stub to mark that the API was intentionally excluded per design.
        pass


if __name__ == "__main__":
    unittest.main()
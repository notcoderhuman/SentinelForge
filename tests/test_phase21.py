"""Phase 21 focused coverage for file-activity parsing and detections."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.ingestion.pipeline import ingest_file, ingest_lines, parser_for_source
from sentinelforge.storage import AnalysisRepository, Database
from sentinelforge.threat_context import ThreatContext


FIXTURE = Path("fixtures/phase21-file-activity.ndjson")
BASE = datetime(2025, 1, 21, tzinfo=timezone.utc)
FILE_RULES = {
    "REPEATED_FILE_ACTIVITY",
    "HOST_MODIFIES_MANY_DISTINCT_FILES",
    "EXECUTABLE_FILE_CREATED",
    "FILE_ACTIVITY_ON_SENSITIVE_PATH",
}


def file_line(seconds=0, *, host="host-a", user="alice", path="/var/tmp/item.txt",
              action="modify", optional=True, **extra):
    record = {
        "timestamp": (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": host,
        "username": user,
        "path": path,
        "action": action,
    }
    if optional:
        record.update({"file_hash": "sha256-test", "old_path": "/var/tmp/old.txt", "size": 12})
    record.update(extra)
    return json.dumps(record, separators=(",", ":"))


class Phase21FileParserTests(unittest.TestCase):
    def test_fixture_uses_active_parser_and_preserves_raw_fields(self):
        result = ingest_file(FIXTURE, source="file_activity")
        self.assertEqual(len(result.events), 11)
        self.assertFalse(result.diagnostics)
        event = result.events[0]
        self.assertEqual(event.source, "file_activity")
        self.assertEqual(event.event_type, "file_activity")
        self.assertEqual(event.hostname, "file-host")
        self.assertEqual(event.username, "alice")
        self.assertEqual(event.path, "/var/tmp/cache.db")
        self.assertEqual(event.action, "modify")
        self.assertEqual(event.file_hash, "sha256-a")
        self.assertEqual(event.size, 10)
        self.assertEqual(json.loads(event.raw)["path"], "/var/tmp/cache.db")

    def test_optional_fields_are_absent_without_invention(self):
        record = json.loads(file_line(optional=False))
        result = ingest_lines([json.dumps(record)], parser=parser_for_source("file_activity"))
        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertIsNone(event.file_hash)
        self.assertIsNone(event.old_path)
        self.assertIsNone(event.size)

    def test_malformed_missing_and_numeric_validation_are_diagnostics(self):
        valid = json.loads(file_line())
        missing = dict(valid); missing.pop("username")
        bad_size = dict(valid); bad_size["size"] = True
        bad_optional = dict(valid); bad_optional["file_hash"] = 7
        bad_timestamp = dict(valid); bad_timestamp["timestamp"] = "2025-01-21T00:00:00"
        result = ingest_lines([
            "not-json", json.dumps(missing), json.dumps(bad_size),
            json.dumps(bad_optional), json.dumps(bad_timestamp), json.dumps(valid),
        ], parser=parser_for_source("file_activity"))
        self.assertEqual(len(result.events), 1)
        self.assertEqual([d.line_number for d in result.diagnostics], [1, 2, 3, 4, 5])

    def test_source_selection_and_alias_are_explicit(self):
        self.assertIsNotNone(parser_for_source("file_activity"))
        self.assertIsNotNone(parser_for_source("file"))
        with self.assertRaises(ValueError):
            parser_for_source("file-events")

    def test_file_events_round_trip_through_persistence(self):
        event = ingest_file(FIXTURE, source="file_activity").events[0]
        with tempfile.TemporaryDirectory() as directory:
            with Database(Path(directory) / "phase21.db") as db:
                repository = AnalysisRepository(db)
                # Saving an alert exercises the same event serialization boundary.
                from sentinelforge.alerts import create_alert
                alert = create_alert("TEST_FILE", "low", "test", "test", [event])
                repository.save_alert(alert)
                restored = repository.get_alert(alert.alert_id).evidence[0]
        self.assertEqual(restored.path, event.path)
        self.assertEqual(restored.action, event.action)
        self.assertEqual(restored.file_hash, event.file_hash)
        self.assertEqual(restored.size, event.size)


class Phase21FileDetectionTests(unittest.TestCase):
    def test_active_parser_detection_path_emits_all_four_rules(self):
        events = ingest_file(FIXTURE, source="file_activity").events
        context = [ThreatContext("file_path", "/etc/shadow", "suspicious", "fixture", 90,
                                 "exact local test context", "phase21")]
        rules = {alert.rule_id for alert in DetectionEngine().detect(events, context)}
        self.assertTrue(FILE_RULES.issubset(rules))

    def test_sensitive_path_is_exact_and_partial_mismatch_is_not_enough(self):
        context = [ThreatContext("file_path", "/etc/shadow", "suspicious", "fixture", 90,
                                 "exact only", "phase21")]
        exact = ingest_lines([file_line(path="/etc/shadow", action="read")],
                             parser=parser_for_source("file_activity")).events
        partial = ingest_lines([file_line(path="/etc/shadow.bak", action="read")],
                               parser=parser_for_source("file_activity")).events
        self.assertIn("FILE_ACTIVITY_ON_SENSITIVE_PATH",
                      {a.rule_id for a in DetectionEngine().detect(exact, context)})
        self.assertNotIn("FILE_ACTIVITY_ON_SENSITIVE_PATH",
                         {a.rule_id for a in DetectionEngine().detect(partial, context)})

    def test_wrong_action_does_not_trigger_executable_creation(self):
        context = [ThreatContext("file_path", "/tmp/dropper.sh", "suspicious", "fixture", 90,
                                 "exact", "phase21")]
        modified = ingest_lines([file_line(path="/tmp/dropper.sh", action="modify")],
                                parser=parser_for_source("file_activity")).events
        self.assertNotIn("EXECUTABLE_FILE_CREATED",
                         {a.rule_id for a in DetectionEngine().detect(modified, context)})

    def test_many_files_requires_modifying_actions(self):
        lines = [file_line(i * 10, path=f"/tmp/{i}.txt", action="read") for i in range(5)]
        events = ingest_lines(lines, parser=parser_for_source("file_activity")).events
        self.assertNotIn("HOST_MODIFIES_MANY_DISTINCT_FILES", {a.rule_id for a in DetectionEngine().detect(events)})

    def test_missing_identities_do_not_create_group_matches(self):
        lines = [file_line(i * 10, host=None, path=f"/tmp/{i}.txt") for i in range(5)]
        records = [json.loads(line) for line in lines]
        for record in records:
            record.pop("hostname")
        events = ingest_lines([json.dumps(r) for r in records],
                              parser=parser_for_source("file_activity")).events
        rules = {a.rule_id for a in DetectionEngine().detect(events)}
        self.assertNotIn("HOST_MODIFIES_MANY_DISTINCT_FILES", rules)

    def test_120_second_boundary_inclusive_and_121_excluded(self):
        at = [file_line(i * 30, path="/var/tmp/repeat.txt") for i in range(5)]
        outside = [file_line(i * 30, path="/var/tmp/repeat.txt") for i in range(4)]
        outside.append(file_line(121, path="/var/tmp/repeat.txt"))
        parser = parser_for_source("file_activity")
        self.assertIn("REPEATED_FILE_ACTIVITY", {a.rule_id for a in DetectionEngine().detect(ingest_lines(at, parser=parser).events)})
        self.assertNotIn("REPEATED_FILE_ACTIVITY", {a.rule_id for a in DetectionEngine().detect(ingest_lines(outside, parser=parser).events)})

    def test_reversed_input_and_duplicates_are_deterministic_and_suppressed(self):
        events = ingest_file(FIXTURE, source="file_activity").events
        first = DetectionEngine().detect(events)
        second = DetectionEngine().detect(list(reversed(events)))
        self.assertEqual([(a.rule_id, a.alert_id, [e.raw for e in a.evidence]) for a in first],
                         [(a.rule_id, a.alert_id, [e.raw for e in a.evidence]) for a in second])
        duplicates = ingest_lines([file_line(i * 10, path="/tmp/same.txt") for i in range(5)],
                                  parser=parser_for_source("file_activity")).events
        self.assertNotIn("HOST_MODIFIES_MANY_DISTINCT_FILES",
                         {a.rule_id for a in DetectionEngine().detect(duplicates)})

    def test_file_activity_isolated_from_phase19_dns_network_and_process_rules(self):
        events = ingest_file(FIXTURE, source="file_activity").events
        rules = {a.rule_id for a in DetectionEngine().detect(events)}
        self.assertFalse(rules & {"AUTHENTICATION_TO_NETWORK_ACTIVITY", "NETWORK_TO_PROCESS_ACTIVITY",
                                  "AUTH_NETWORK_PROCESS_CHAIN", "REPEATED_DNS_QUERY",
                                  "PRIVILEGED_PROCESS_EXECUTION", "REPEATED_PROCESS_EXECUTION"})

    def test_existing_sources_regressions_remain_parseable(self):
        self.assertTrue(ingest_file(Path("fixtures/dns-phase20.ndjson"), source="dns_query").events)
        self.assertTrue(ingest_file(Path("fixtures/network-phase17.ndjson"), source="network_connection").events)
        self.assertTrue(ingest_file(Path("fixtures/process-phase18.ndjson"), source="process_execution").events)


if __name__ == "__main__":
    unittest.main()

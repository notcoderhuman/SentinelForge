"""Phase 22 focused coverage for system-persistence telemetry."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.ingestion.pipeline import ingest_file, ingest_lines, parser_for_source
from sentinelforge.storage import AnalysisRepository, Database
from sentinelforge.threat_context import ThreatContext


FIXTURE = Path("fixtures/phase22-system-persistence.ndjson")
BASE = datetime(2025, 1, 22, tzinfo=timezone.utc)
PERSISTENCE_RULES = {
    "SERVICE_CREATED_OR_UPDATED",
    "SCHEDULED_TASK_CREATED_OR_UPDATED",
    "SERVICE_STARTED_AFTER_CREATION",
    "SCHEDULED_TASK_CREATED_WITH_COMMAND",
}


def persistence_line(seconds=0, *, host="persist-host", user="alice",
                     persistence_type="service", action="create", name="Updater",
                     optional=True, **extra):
    record = {
        "timestamp": (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": host, "username": user, "persistence_type": persistence_type,
        "action": action, "name": name,
    }
    if optional:
        record.update({"command": "/usr/local/bin/updater --run", "service_manager": "systemd",
                       "task_path": "\\Tasks\\Updater", "process_name": "updater",
                       "executable_path": "/usr/local/bin/updater", "privilege": "root",
                       "process_id": 1001})
    record.update(extra)
    return json.dumps(record, separators=(",", ":"))


class Phase22PersistenceParserTests(unittest.TestCase):
    def test_fixture_uses_active_parser_and_preserves_raw_fields(self):
        result = ingest_file(FIXTURE, source="system_persistence")
        self.assertEqual(len(result.events), 11)
        self.assertFalse(result.diagnostics)
        event = result.events[0]
        self.assertEqual(event.source, "system_persistence")
        self.assertEqual(event.event_type, "system_persistence")
        self.assertEqual(event.hostname, "persist-host")
        self.assertEqual(event.username, "alice")
        self.assertEqual(event.persistence_type, "service")
        self.assertEqual(event.persistence_action, "create")
        self.assertEqual(event.persistence_name, "Updater")
        self.assertEqual(event.command, "/usr/local/bin/updater --run")
        self.assertEqual(event.service_manager, "systemd")
        self.assertEqual(event.process_id, 1001)
        self.assertEqual(json.loads(event.raw)["name"], "Updater")

    def test_process_alias_is_preserved(self):
        record = json.loads(persistence_line(optional=False))
        record["process"] = "legacy-process"
        event = ingest_lines([json.dumps(record)], parser=parser_for_source("system_persistence")).events[0]
        self.assertEqual(event.process, "legacy-process")
        self.assertEqual(event.process_name, "legacy-process")

    def test_optional_fields_are_none_without_invention(self):
        record = json.loads(persistence_line(optional=False))
        event = ingest_lines([json.dumps(record)], parser=parser_for_source("system_persistence")).events[0]
        for field in ("command", "service_manager", "task_path", "process_name", "executable_path", "privilege", "process_id"):
            self.assertIsNone(getattr(event, field))

    def test_malformed_missing_and_numeric_diagnostics_are_nonfatal(self):
        valid = json.loads(persistence_line())
        missing = dict(valid); missing.pop("name")
        bad_id = dict(valid); bad_id["process_id"] = True
        bad_type = dict(valid); bad_type["persistence_type"] = "registry"
        bad_timestamp = dict(valid); bad_timestamp["timestamp"] = "2025-01-22T00:00:00"
        bad_optional = dict(valid); bad_optional["command"] = 42
        result = ingest_lines(["not-json", json.dumps(missing), json.dumps(bad_id),
                               json.dumps(bad_type), json.dumps(bad_timestamp),
                               json.dumps(bad_optional), json.dumps(valid)],
                              parser=parser_for_source("system_persistence"))
        self.assertEqual(len(result.events), 1)
        self.assertEqual([d.line_number for d in result.diagnostics], [1, 2, 3, 4, 5, 6])

    def test_source_selection_is_explicit_and_aliases_are_limited(self):
        self.assertIsNotNone(parser_for_source("system_persistence"))
        self.assertIsNotNone(parser_for_source("system_persistence"))
        with self.assertRaises(ValueError):
            parser_for_source("system-persistence")

    def test_persistence_fields_round_trip_through_sqlite(self):
        event = ingest_file(FIXTURE, source="system_persistence").events[0]
        with tempfile.TemporaryDirectory() as directory:
            with Database(Path(directory) / "phase22.db") as db:
                repository = AnalysisRepository(db)
                from sentinelforge.alerts import create_alert
                alert = create_alert("TEST_PERSISTENCE", "low", "test", "test", [event])
                repository.save_alert(alert)
                restored = repository.get_alert(alert.alert_id).evidence[0]
        for field in ("persistence_type", "persistence_action", "persistence_name", "command",
                      "service_manager", "task_path", "process_name", "executable_path", "privilege", "process_id"):
            self.assertEqual(getattr(restored, field), getattr(event, field), field)


class Phase22PersistenceDetectionTests(unittest.TestCase):
    def test_fixture_path_emits_all_four_rules(self):
        events = ingest_file(FIXTURE, source="system_persistence").events
        rules = {alert.rule_id for alert in DetectionEngine().detect(events)}
        self.assertTrue(PERSISTENCE_RULES.issubset(rules))

    def test_service_and_task_identity_and_action_boundaries(self):
        parser = parser_for_source("system_persistence")
        service = ingest_lines([persistence_line(persistence_type="service", action="create")], parser=parser).events
        task = ingest_lines([persistence_line(persistence_type="scheduled_task", action="create", name="Task")], parser=parser).events
        stopped = ingest_lines([persistence_line(persistence_type="service", action="delete")], parser=parser).events
        self.assertIn("SERVICE_CREATED_OR_UPDATED", {a.rule_id for a in DetectionEngine().detect(service)})
        self.assertIn("SCHEDULED_TASK_CREATED_OR_UPDATED", {a.rule_id for a in DetectionEngine().detect(task)})
        self.assertNotIn("SERVICE_CREATED_OR_UPDATED", {a.rule_id for a in DetectionEngine().detect(stopped)})

    def test_scheduled_task_command_rule_requires_command(self):
        parser = parser_for_source("system_persistence")
        with_command = ingest_lines([persistence_line(persistence_type="cron", command="/bin/job")], parser=parser).events
        without_command = ingest_lines([persistence_line(persistence_type="cron", command=None, optional=False)], parser=parser).events
        self.assertIn("SCHEDULED_TASK_CREATED_WITH_COMMAND", {a.rule_id for a in DetectionEngine().detect(with_command)})
        self.assertNotIn("SCHEDULED_TASK_CREATED_WITH_COMMAND", {a.rule_id for a in DetectionEngine().detect(without_command)})

    def test_identity_and_chronology_boundaries(self):
        parser = parser_for_source("system_persistence")
        created = persistence_line(0, action="create", name="Daemon")
        started_at = persistence_line(300, action="start", name="Daemon")
        started_late = persistence_line(301, action="start", name="Daemon")
        self.assertIn("SERVICE_STARTED_AFTER_CREATION", {a.rule_id for a in DetectionEngine().detect(ingest_lines([created, started_at], parser=parser).events)})
        self.assertNotIn("SERVICE_STARTED_AFTER_CREATION", {a.rule_id for a in DetectionEngine().detect(ingest_lines([created, started_late], parser=parser).events)})
        mismatch = persistence_line(10, action="start", name="Daemon", user="bob")
        self.assertNotIn("SERVICE_STARTED_AFTER_CREATION", {a.rule_id for a in DetectionEngine().detect(ingest_lines([created, mismatch], parser=parser).events)})

    def test_duplicate_entries_do_not_duplicate_relationship_alerts(self):
        parser = parser_for_source("system_persistence")
        lines = [persistence_line(0, action="create", name="Daemon"), persistence_line(30, action="start", name="Daemon")]
        events = ingest_lines(lines + lines, parser=parser).events
        alerts = DetectionEngine().detect(events)
        self.assertEqual([a.rule_id for a in alerts].count("SERVICE_STARTED_AFTER_CREATION"), 1)

    def test_missing_identity_does_not_create_relationship_matches(self):
        records = [json.loads(persistence_line(0, action="create", name="Daemon")), json.loads(persistence_line(30, action="start", name="Daemon"))]
        records[1].pop("username")
        events = ingest_lines([json.dumps(item) for item in records], parser=parser_for_source("system_persistence")).events
        self.assertNotIn("SERVICE_STARTED_AFTER_CREATION", {a.rule_id for a in DetectionEngine().detect(events)})

    def test_reversal_is_deterministic_and_prior_sources_regress(self):
        events = ingest_file(FIXTURE, source="system_persistence").events
        first = DetectionEngine().detect(events)
        second = DetectionEngine().detect(list(reversed(events)))
        self.assertEqual([(a.rule_id, a.alert_id, [e.raw for e in a.evidence]) for a in first],
                         [(a.rule_id, a.alert_id, [e.raw for e in a.evidence]) for a in second])
        self.assertTrue(ingest_file(Path("fixtures/phase21-file-activity.ndjson"), source="file_activity").events)
        self.assertTrue(ingest_file(Path("fixtures/dns-phase20.ndjson"), source="dns_query").events)
        self.assertTrue(ingest_file(Path("fixtures/network-phase17.ndjson"), source="network_connection").events)
        self.assertTrue(ingest_file(Path("fixtures/process-phase18.ndjson"), source="process_execution").events)

    def test_persistence_events_do_not_trigger_phase19_relationships(self):
        events = ingest_file(FIXTURE, source="system_persistence").events
        rules = {a.rule_id for a in DetectionEngine().detect(events)}
        self.assertFalse(rules & {"AUTHENTICATION_TO_NETWORK_ACTIVITY", "NETWORK_TO_PROCESS_ACTIVITY",
                                  "AUTH_NETWORK_PROCESS_CHAIN", "REPEATED_DNS_QUERY",
                                  "PRIVILEGED_PROCESS_EXECUTION", "REPEATED_PROCESS_EXECUTION"})


if __name__ == "__main__":
    unittest.main()

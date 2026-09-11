import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.ingestion.pipeline import ingest_file, ingest_lines, parser_for_source
from sentinelforge.storage import AnalysisRepository, Database

BASE = datetime(2025, 1, 24, tzinfo=timezone.utc)
FIXTURE = Path("fixtures/phase24-windows-system.ndjson")


def line(seconds=0, **kwargs):
    record = {"timestamp": (BASE + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z"),
              "hostname": "win-host", "event_id": 7036, "provider": "Service Control Manager",
              "action": "state_change", "service_name": "ExampleSvc", "service_state": "running"}
    record.update(kwargs)
    return json.dumps(record, separators=(",", ":"))


class Phase24ParserTests(unittest.TestCase):
    def test_fixture_and_routing(self):
        result = ingest_file(FIXTURE, source="windows_system_event")
        self.assertEqual(len(result.events), 4)
        self.assertFalse(result.diagnostics)
        event = result.events[0]
        self.assertEqual(event.source, "windows_system_event")
        self.assertEqual(event.provider, "Service Control Manager")
        self.assertEqual(event.system_event_id, 7036)
        self.assertIsNotNone(parser_for_source("windows_system_event"))

    def test_optional_strings_and_diagnostics(self):
        valid = json.loads(line(username=" alice ", process_name=" proc.exe ", command=" cmd "))
        result = ingest_lines([json.dumps(valid), "not-json", json.dumps({**valid, "event_id": -1}), json.dumps({**valid, "process_id": True})], parser=parser_for_source("windows_system_event"))
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].username, "alice")
        self.assertEqual(result.events[0].command, "cmd")
        self.assertEqual(len(result.diagnostics), 3)

    def test_missing_required_and_legacy_windows_security_unchanged(self):
        record = json.loads(line())
        record.pop("provider")
        self.assertEqual(len(ingest_lines([json.dumps(record)], parser=parser_for_source("windows_system_event")).events), 0)
        self.assertEqual(len(ingest_file(Path("fixtures/windows-security.xml"), source="windows_security").events), 3)


class Phase24DetectionTests(unittest.TestCase):
    def test_state_stopped_and_command_rules(self):
        events = ingest_lines([line(service_state="running"), line(10, service_state="stopped"), line(20, action="configuration_change", command="sc config ExampleSvc start=auto")], parser=parser_for_source("windows_system_event")).events
        rules = {alert.rule_id for alert in DetectionEngine().detect(events)}
        self.assertTrue({"WINDOWS_SERVICE_STATE_CHANGE", "WINDOWS_SERVICE_STOPPED", "WINDOWS_SYSTEM_EVENT_WITH_COMMAND"}.issubset(rules))

    def test_start_after_stop_boundaries_and_identity(self):
        events = ingest_lines([line(0, service_state="stopped"), line(300, service_state="running")], parser=parser_for_source("windows_system_event")).events
        self.assertIn("WINDOWS_SERVICE_START_AFTER_STOP", {a.rule_id for a in DetectionEngine().detect(events)})
        late = ingest_lines([line(0, service_state="stopped"), line(301, service_state="running")], parser=parser_for_source("windows_system_event")).events
        self.assertNotIn("WINDOWS_SERVICE_START_AFTER_STOP", {a.rule_id for a in DetectionEngine().detect(late)})
        pending = ingest_lines([line(0, service_state="stopped"), line(1, service_state="start_pending")], parser=parser_for_source("windows_system_event")).events
        self.assertNotIn("WINDOWS_SERVICE_START_AFTER_STOP", {a.rule_id for a in DetectionEngine().detect(pending)})

    def test_reversal_duplicate_and_independent_services(self):
        events = ingest_lines([line(0, service_state="stopped"), line(1, service_state="running"), line(0, service_name="OtherSvc", service_state="stopped"), line(1, service_name="OtherSvc", service_state="running")], parser=parser_for_source("windows_system_event")).events
        forward = DetectionEngine().detect(events)
        reverse = DetectionEngine().detect(list(reversed(events)))
        self.assertEqual([(a.rule_id, a.alert_id) for a in forward], [(a.rule_id, a.alert_id) for a in reverse])
        self.assertEqual(len([a for a in forward if a.rule_id == "WINDOWS_SERVICE_START_AFTER_STOP"]), 2)

    def test_unrelated_provider_and_missing_identity_ignored(self):
        events = ingest_lines([line(provider="Other Provider", service_state="running"), line(service_name=None, service_state="stopped"), line(provider="ServiceMonitorX", service_state="stopped")], parser=parser_for_source("windows_system_event")).events
        self.assertFalse(DetectionEngine().detect(events))

    def test_persistence_round_trip(self):
        event = ingest_file(FIXTURE, source="windows_system_event").events[0]
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as handle:
            path = handle.name
        try:
            with Database(path) as db:
                repo = AnalysisRepository(db)
                alerts = DetectionEngine().detect([event])
                repo.save_alerts(alerts)
                restored = repo.get_alert(alerts[0].alert_id)
                self.assertEqual(restored.evidence[0].provider, event.provider)
                self.assertEqual(restored.evidence[0].system_event_id, event.system_event_id)
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

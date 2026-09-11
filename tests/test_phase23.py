"""Phase 23 focused coverage for Windows Registry run-key telemetry."""

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.registry import DEFAULT_RULE_REGISTRY, RuleRegistry
from sentinelforge.ingestion.pipeline import ingest_file, ingest_lines, parser_for_source
from sentinelforge.storage import AnalysisRepository, Database

FIXTURE = Path("fixtures/phase23-registry.ndjson")
BASE = datetime(2025, 1, 23, tzinfo=timezone.utc)
RUN_HIVES = {"HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"}
RUN_KEYS = {
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
}
REGISTRY_RULES = {
    "REGISTRY_VALUE_MODIFIED",
    "REGISTRY_KEY_DELETED",
    "REGISTRY_RUN_KEY_MODIFICATION",
    "REGISTRY_ACTIVITY_BY_MANY_PROCESSES",
}


def registry_line(seconds=0, *, host="reg-host", user="alice", hive="HKCU",
                  key_path=r"Software\Microsoft\Windows\CurrentVersion\Run",
                  action="set_value", value_name="Updater", value_data=r"C:\Temp\updater.exe",
                  value_type="REG_SZ", **extra):
    record = {"timestamp": (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "hostname": host, "username": user, "hive": hive, "key_path": key_path,
              "action": action, "value_name": value_name, "value_data": value_data,
              "value_type": value_type}
    record.update(extra)
    return json.dumps(record, separators=(",", ":"))


class Phase23RegistryParserTests(unittest.TestCase):
    def test_fixture_parser_normalizes_and_preserves_registry_fields(self):
        result = ingest_file(FIXTURE, source="registry")
        self.assertEqual(len(result.events), 12)
        self.assertFalse(result.diagnostics)
        event = result.events[0]
        self.assertEqual(event.source, "registry_change")
        self.assertEqual(event.event_type, "registry_change")
        self.assertEqual(event.hive, "HKEY_CURRENT_USER")
        self.assertIn(event.key_path, RUN_KEYS)
        self.assertEqual(event.registry_action, "set_value")
        self.assertEqual(event.value_name, "Updater")
        self.assertEqual(event.value_data, r"C:\Users\alice\AppData\Roaming\updater.exe")
        self.assertEqual(event.value_type, "REG_SZ")
        self.assertEqual(json.loads(event.raw)["key_path"], event.key_path)

    def test_aliases_are_explicit_and_unknown_sources_rejected(self):
        self.assertIsNotNone(parser_for_source("registry"))
        self.assertIsNotNone(parser_for_source("registry_change"))
        with self.assertRaises(ValueError):
            parser_for_source("registry-events")

    def test_normalization_accepts_action_alias_but_does_not_invent_optional_values(self):
        record = json.loads(registry_line())
        record["action"] = record.pop("registry_action", record["action"])
        record.pop("value_data")
        event = ingest_lines([json.dumps(record)], parser=parser_for_source("registry_change")).events[0]
        self.assertEqual(event.registry_action, "set_value")
        self.assertIsNone(event.value_data)

    def test_malformed_missing_timezone_and_wrong_types_are_nonfatal_diagnostics(self):
        valid = json.loads(registry_line())
        missing = dict(valid); missing.pop("key_path")
        bad_hive = dict(valid); bad_hive["hive"] = "HKEY_NOT_A_HIVE"
        bad_time = dict(valid); bad_time["timestamp"] = "2025-01-23T00:00:00"
        bad_value = dict(valid); bad_value["value_name"] = 7
        result = ingest_lines(["not-json", json.dumps(missing), json.dumps(bad_hive),
                               json.dumps(bad_time), json.dumps(bad_value), json.dumps(valid)],
                              parser=parser_for_source("registry"))
        self.assertEqual(len(result.events), 1)
        self.assertEqual([d.line_number for d in result.diagnostics], [1, 2, 3, 4, 5])

    def test_exact_run_key_paths_and_hives_are_required(self):
        parser = parser_for_source("registry")
        for hive in ("HKCU", "HKLM"):
            for key in RUN_KEYS:
                event = ingest_lines([registry_line(hive=hive, key_path=key)], parser=parser).events[0]
                self.assertIn(event.hive, RUN_HIVES)
                self.assertIn(event.key_path, RUN_KEYS)
        near_miss = ingest_lines([registry_line(key_path=r"Software\Microsoft\Windows\CurrentVersion\RunServices")], parser=parser)
        self.assertEqual(len(near_miss.events), 1)
        self.assertNotIn("REGISTRY_RUN_KEY_MODIFICATION", {a.rule_id for a in DetectionEngine().detect(near_miss.events)})

    def test_registry_fields_round_trip_through_sqlite(self):
        event = ingest_file(FIXTURE, source="registry_change").events[0]
        with tempfile.TemporaryDirectory() as directory:
            with Database(Path(directory) / "phase23.db") as db:
                repository = AnalysisRepository(db)
                from sentinelforge.alerts import create_alert
                alert = create_alert("TEST_REGISTRY", "low", "test", "test", [event])
                repository.save_alert(alert)
                restored = repository.get_alert(alert.alert_id).evidence[0]
        for field in ("hive", "key_path", "registry_action", "value_name", "value_data", "value_type"):
            self.assertEqual(getattr(restored, field), getattr(event, field), field)


class Phase23RegistryDetectionTests(unittest.TestCase):
    def test_fixture_emits_all_four_registry_rules(self):
        events = ingest_file(FIXTURE, source="registry").events
        rules = {alert.rule_id for alert in DetectionEngine().detect(events)}
        self.assertTrue(REGISTRY_RULES.issubset(rules))

    def test_wrong_hive_or_near_run_path_does_not_match(self):
        parser = parser_for_source("registry")
        lines = [registry_line(i * 10, hive="HKCU", key_path=next(iter(RUN_KEYS))) for i in range(5)]
        self.assertTrue(DetectionEngine().detect(ingest_lines(lines, parser=parser).events))
        bad = [registry_line(i * 10, hive="HKCR", key_path=r"Software\Microsoft\Windows\CurrentVersion\RunServices") for i in range(5)]
        self.assertFalse(DetectionEngine().detect(ingest_lines(bad, parser=parser).events))

    def test_many_process_boundaries_require_explicit_identity(self):
        parser = parser_for_source("registry")
        records = [json.loads(registry_line(i * 10, value_name=f"v{i}")) for i in range(5)]
        for record in records[:2]:
            record.pop("hostname")
        events = ingest_lines([json.dumps(r) for r in records], parser=parser).events
        rules = {a.rule_id for a in DetectionEngine().detect(events)}
        self.assertNotIn("REGISTRY_RUN_KEY_ACTIVITY", rules)

    def test_determinism_duplicates_and_input_reversal(self):
        events = ingest_file(FIXTURE, source="registry").events
        encode = lambda alerts: [(a.rule_id, a.alert_id, [e.raw for e in a.evidence]) for a in alerts]
        self.assertEqual(encode(DetectionEngine().detect(events)), encode(DetectionEngine().detect(list(reversed(events)))))
        duplicate_events = ingest_lines([registry_line(i * 10) for i in range(5)] * 2, parser=parser_for_source("registry")).events
        alerts = DetectionEngine().detect(duplicate_events)
        self.assertEqual(len({a.alert_id for a in alerts}), len(alerts))

    def test_registry_isolated_from_prior_telemetry_and_rule_registry_is_sorted(self):
        events = ingest_file(FIXTURE, source="registry").events
        rules = {a.rule_id for a in DetectionEngine().detect(events)}
        self.assertFalse(rules & {"SSH_BRUTE_FORCE", "REPEATED_DNS_QUERY", "REPEATED_FILE_ACTIVITY",
                                  "PRIVILEGED_PROCESS_EXECUTION", "AUTH_NETWORK_PROCESS_CHAIN"})
        self.assertEqual([r.rule_id for r in DEFAULT_RULE_REGISTRY.all()], sorted(r.rule_id for r in DEFAULT_RULE_REGISTRY.all()))
        with self.assertRaises(ValueError):
            RuleRegistry([DEFAULT_RULE_REGISTRY.get("REGISTRY_ACTIVITY_BY_MANY_PROCESSES"), DEFAULT_RULE_REGISTRY.get("REGISTRY_ACTIVITY_BY_MANY_PROCESSES")])

    def test_phase1_to_22_sources_still_parse_and_source_selection_is_persistent(self):
        for path, source in (("fixtures/auth.log", "linux_auth"), ("fixtures/windows-security.xml", "windows_security"),
                             ("fixtures/network-phase17.ndjson", "network_connection"), ("fixtures/process-phase18.ndjson", "process_execution"),
                             ("fixtures/dns-phase20.ndjson", "dns_query"), ("fixtures/phase21-file-activity.ndjson", "file_activity"),
                             ("fixtures/phase22-system-persistence.ndjson", "system_persistence")):
            self.assertTrue(ingest_file(Path(path), source=source).events)


if __name__ == "__main__":
    unittest.main()

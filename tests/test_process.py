import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.rules import RuleConfig
from sentinelforge.ingestion.pipeline import ingest_file, ingest_lines, parser_for_source
from sentinelforge.parsers.process import parse_lines


FIXTURE = Path("fixtures/process-phase18.ndjson")


def record(timestamp, *, host="host-a", user="alice", name="worker", pid=100,
           ppid=1, privilege="user", **extra):
    if hasattr(timestamp, "isoformat"):
        timestamp = timestamp.isoformat().replace("+00:00", "Z")
    value = {
        "timestamp": timestamp,
        "hostname": host, "username": user, "process_name": name,
        "process_id": pid, "parent_process_id": ppid,
        "command_line": name, "executable_path": "/usr/bin/" + name,
        "privilege": privilege,
    }
    value.update(extra)
    return json.dumps(value)


class ProcessParserTests(unittest.TestCase):
    def test_fixture_normalizes_fields_and_has_no_diagnostics(self):
        result = ingest_file(FIXTURE, source="process_execution")
        self.assertEqual(len(result.events), 8)
        self.assertFalse(result.diagnostics)
        event = result.events[1]
        self.assertEqual(event.source, "process_execution")
        self.assertEqual(event.event_type, "process_execution")
        self.assertEqual(event.process_name, "curl")
        self.assertEqual(event.process_id, 101)
        self.assertEqual(event.parent_process_id, 100)
        self.assertEqual(event.privilege, "user")
        self.assertEqual(json.loads(event.raw)["command_line"], "curl https://example.test/a")

    def test_mixed_records_are_retained_as_events_or_diagnostics(self):
        lines = [
            record("2025-01-01T00:00:00+00:00"),
            "not-json",
            record("2025-01-01T00:00:02+00:00", pid=101, privilege=None),
            json.dumps({"timestamp": "2025-01-01T00:00:03Z", "process_id": 2}),
        ]
        result = ingest_lines(lines, parser=parse_lines)
        self.assertEqual(len(result.events), 2)
        self.assertEqual([d.line_number for d in result.diagnostics], [2, 4])
        self.assertTrue(all(d.raw for d in result.diagnostics))

    def test_invalid_timestamp_and_pid_are_diagnostics(self):
        invalid_timestamp = json.loads(record("2025-01-01T00:00:00+00:00"))
        invalid_timestamp["timestamp"] = "bad"
        lines = [
            json.dumps(invalid_timestamp),
            json.dumps({**json.loads(record("2025-01-01T00:00:01+00:00")), "process_id": -1}),
            json.dumps({**json.loads(record("2025-01-01T00:00:02+00:00")), "process_id": "12"}),
        ]
        result = ingest_lines(lines, parser=parse_lines)
        self.assertFalse(result.events)
        self.assertEqual(len(result.diagnostics), 3)
        self.assertTrue(any("invalid process record" in d.reason for d in result.diagnostics))
        self.assertTrue(any("process_id" in d.reason or "pid" in d.reason for d in result.diagnostics))

    def test_privilege_explicit_missing_and_unknown_are_preserved(self):
        base = json.loads(record("2025-01-01T00:00:00+00:00"))
        missing = dict(base); missing.pop("privilege")
        unknown = dict(base); unknown["privilege"] = "mystery"
        events, diagnostics = parse_lines([json.dumps(base), json.dumps(missing), json.dumps(unknown)])
        self.assertFalse(diagnostics)
        self.assertEqual([event.privilege for event in events], ["user", None, "mystery"])

    def test_source_selection_is_explicit(self):
        self.assertIsNotNone(parser_for_source("process_execution"))
        with self.assertRaises(ValueError):
            parser_for_source("processes")


class ProcessDetectionTests(unittest.TestCase):
    def process_alerts(self, lines, config=None):
        return self.detect(lines, config)

    def test_privilege_values_and_case_insensitive_matching(self):
        base = datetime(2025, 1, 1, tzinfo=timezone.utc)
        alerts = self.process_alerts([
            record(base, privilege="root", pid=1),
            record(base + timedelta(seconds=1), privilege="admin", pid=2),
            record(base + timedelta(seconds=2), privilege="PRIVILEGED", pid=3),
        ])
        self.assertEqual(
            sum(alert.rule_id == "PRIVILEGED_PROCESS_EXECUTION" for alert in alerts), 3
        )
        non_privileged = self.process_alerts([
            record(base, privilege=None),
            record(base + timedelta(seconds=1), privilege="unknown"),
        ])
        self.assertFalse(any(alert.rule_id == "PRIVILEGED_PROCESS_EXECUTION"
                             for alert in non_privileged))

    def test_repeated_process_threshold_window_and_determinism(self):
        base = datetime(2025, 1, 1, tzinfo=timezone.utc)
        five = [record(base + timedelta(seconds=index * 30), name="worker", pid=100 + index)
                for index in range(5)]
        four = five[:4]
        self.assertTrue(any(alert.rule_id == "REPEATED_PROCESS_EXECUTION"
                            for alert in self.process_alerts(five)))
        self.assertFalse(any(alert.rule_id == "REPEATED_PROCESS_EXECUTION"
                             for alert in self.process_alerts(four)))
        boundary = [record(base + timedelta(seconds=index * 30), name="worker", pid=200 + index)
                    for index in range(5)]
        outside = [record(base + timedelta(seconds=index * 30), name="worker", pid=300 + index)
                   for index in range(4)]
        outside.append(record(base + timedelta(seconds=121), name="worker", pid=304))
        self.assertTrue(any(alert.rule_id == "REPEATED_PROCESS_EXECUTION"
                            for alert in self.process_alerts(boundary)))
        self.assertFalse(any(alert.rule_id == "REPEATED_PROCESS_EXECUTION"
                             for alert in self.process_alerts(outside)))
        reversed_alerts = self.process_alerts(list(reversed(five)))
        self.assertEqual(
            [(alert.rule_id, alert.alert_id) for alert in self.process_alerts(five)],
            [(alert.rule_id, alert.alert_id) for alert in reversed_alerts],
        )

    def detect(self, lines, config=None):
        events, diagnostics = parse_lines(lines)
        self.assertFalse(diagnostics)
        return DetectionEngine(config=config).detect(events)

    def test_parent_child_threshold_counts_distinct_child_pids(self):
        base = datetime(2025, 1, 1, tzinfo=timezone.utc)
        lines = [record((base + timedelta(seconds=i * 10)).isoformat(), ppid=77, pid=pid)
                 for i, pid in enumerate((201, 202, 203))]
        alerts = self.detect(lines, RuleConfig(process_parent_child_threshold=3))
        self.assertTrue(any("PARENT" in alert.rule_id or "CHILD" in alert.rule_id for alert in alerts))

    def test_user_threshold_counts_distinct_processes(self):
        base = datetime(2025, 1, 1, tzinfo=timezone.utc)
        lines = [record((base + timedelta(seconds=i * 10)).isoformat(), user="alice", name=name, pid=300+i)
                 for i, name in enumerate(("one", "two", "three"))]
        alerts = self.detect(lines, RuleConfig(user_process_threshold=3))
        self.assertTrue(any("USER" in alert.rule_id or "PROCESS" in alert.rule_id for alert in alerts))

    def test_same_pid_or_process_name_does_not_satisfy_distinct_threshold(self):
        base = datetime(2025, 1, 1, tzinfo=timezone.utc)
        lines = [record((base + timedelta(seconds=i * 10)).isoformat(), ppid=77, pid=201,
                        name="same", user="alice") for i in range(3)]
        alerts = self.detect(lines, RuleConfig(process_parent_child_threshold=3, user_process_threshold=3))
        self.assertFalse(alerts)

    def test_host_and_user_are_separate_grouping_dimensions(self):
        base = datetime(2025, 1, 1, tzinfo=timezone.utc)
        lines = [record((base + timedelta(seconds=i * 10)).isoformat(), host="host-a" if i < 2 else "host-b",
                        user="alice" if i != 1 else "bob", name=f"p{i}", pid=400+i, ppid=9)
                 for i in range(3)]
        alerts = self.detect(lines, RuleConfig(process_parent_child_threshold=3, user_process_threshold=3))
        self.assertFalse(alerts)

    def test_window_boundary_and_reversed_input_are_deterministic(self):
        base = datetime(2025, 1, 1, tzinfo=timezone.utc)
        lines = [record((base + timedelta(seconds=i * 60)).isoformat(), ppid=88, pid=500+i)
                 for i in range(3)]
        config = RuleConfig(process_parent_child_threshold=3, parent_process_children_window_seconds=120)
        first = self.detect(lines, config)
        reversed_events, _ = parse_lines(list(reversed(lines)))
        second = DetectionEngine(config=config).detect(reversed_events)
        self.assertEqual([(a.rule_id, a.alert_id) for a in first], [(a.rule_id, a.alert_id) for a in second])
        outside = lines[:2] + [record((base + timedelta(seconds=121)).isoformat(), ppid=88, pid=502)]
        self.assertFalse(self.detect(outside, config))

    def test_regression_sources_remain_parseable(self):
        self.assertTrue(ingest_file(Path("fixtures/network-phase17.ndjson"), source="network_connection").events)
        self.assertTrue(ingest_file(Path("fixtures/auth.log"), source="linux_auth").events)
        self.assertTrue(ingest_file(Path("fixtures/windows-phase12.xml"), source="windows_security").events)


if __name__ == "__main__":
    unittest.main()

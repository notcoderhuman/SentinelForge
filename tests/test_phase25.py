import json
import tempfile
import unittest
from pathlib import Path

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.ingestion.pipeline import ingest_file
from sentinelforge.replay import ExpectedAlert, evaluate, explain_alert, load_expected, replay_events, replay_file


class Phase25ReplayTests(unittest.TestCase):
    def test_replay_reuses_engine_and_is_deterministic(self):
        result = replay_file("fixtures/phase23-registry.ndjson", "registry_change")
        reversed_events = replay_events(tuple(reversed(result.events)))
        self.assertEqual([(a.rule_id, a.alert_id) for a in result.alerts], [(a.rule_id, a.alert_id) for a in reversed_events.alerts])
        self.assertEqual(list(result.alerts), DetectionEngine().detect(result.events))

    def test_empty_and_invalid_input(self):
        self.assertEqual(replay_events(()).alerts, ())
        with self.assertRaises(FileNotFoundError):
            replay_file("fixtures/missing.ndjson", "registry_change")

    def test_expected_evaluation_and_duplicate_definitions(self):
        alerts = replay_file("fixtures/phase23-registry.ndjson", "registry_change").alerts
        expected = load_expected("fixtures/phase25-expected-registry.json")
        result = evaluate(alerts, expected)
        self.assertEqual(result.true_positives, 23)
        self.assertEqual(result.false_positives, 0)
        self.assertEqual(result.false_negatives, 0)
        self.assertEqual(result.precision, 1.0)
        self.assertEqual(result.recall, 1.0)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as handle:
            json.dump({"alerts": [{"rule_id": "X", "severity": "low", "count": 1}, {"rule_id": "X", "severity": "low", "count": 2}]}, handle)
            path = handle.name
        try:
            self.assertEqual(load_expected(path)[0].count, 3)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_id_and_evidence_filters_are_enforced(self):
        alerts = replay_file("fixtures/phase23-registry.ndjson", "registry_change").alerts
        first = alerts[0]
        self.assertEqual(evaluate(alerts, (ExpectedAlert(first.rule_id, first.severity, 1, (first.alert_id,), tuple(sorted([first.evidence[0].event_id]))),)).true_positives, 1)
        self.assertEqual(evaluate(alerts, (ExpectedAlert(first.rule_id, first.severity, 1, ("wrong",), ()),)).true_positives, 0)

    def test_missing_unexpected_and_zero_denominators(self):
        alerts = replay_file("fixtures/phase23-registry.ndjson", "registry_change").alerts
        result = evaluate(alerts, (ExpectedAlert("REGISTRY_KEY_DELETED", "medium", 2),))
        self.assertEqual(result.true_positives, 1)
        self.assertEqual(result.false_negatives, 1)
        self.assertGreater(result.false_positives, 0)
        zero = evaluate((), ())
        self.assertEqual((zero.precision, zero.recall), (0.0, 0.0))

    def test_explanation_is_concrete_and_deterministic(self):
        alert = replay_file("fixtures/phase23-registry.ndjson", "registry_change").alerts[0]
        explanation = explain_alert(alert)
        self.assertEqual(explanation["rule_id"], alert.rule_id)
        self.assertEqual(list(explanation["evidence_ids"]), [alert.evidence[0].event_id])
        self.assertNotIn("malware", explanation["text"].lower())

    def test_major_family_replay_paths(self):
        for path, source in (("fixtures/auth.log", "linux_auth"), ("fixtures/network-phase17.ndjson", "network_connection"),
                             ("fixtures/process-phase18.ndjson", "process_execution"), ("fixtures/dns-phase20.ndjson", "dns_query"),
                             ("fixtures/phase21-file-activity.ndjson", "file_activity"), ("fixtures/phase22-system-persistence.ndjson", "system_persistence"),
                             ("fixtures/phase23-registry.ndjson", "registry_change"), ("fixtures/phase24-windows-system.ndjson", "windows_system_event")):
            self.assertIsNotNone(replay_file(path, source))


if __name__ == "__main__":
    unittest.main()

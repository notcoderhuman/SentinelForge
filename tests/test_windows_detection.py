import unittest
from pathlib import Path

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.registry import DEFAULT_RULE_REGISTRY
from sentinelforge.ingestion.pipeline import ingest_file


class WindowsDetectionTests(unittest.TestCase):
    def test_privileged_logon_detection_and_registry(self):
        events = ingest_file(Path("fixtures/windows-phase12.xml"), source="windows_security").events
        alerts = DetectionEngine().detect(events)
        privileged = [alert for alert in alerts if alert.rule_id == "WINDOWS_PRIVILEGED_LOGON"]
        self.assertEqual(len(privileged), 1)
        self.assertEqual(privileged[0].severity, "low")
        self.assertEqual(privileged[0].evidence[0].event_id, "4672")
        self.assertEqual(privileged[0].alert_id, DetectionEngine().detect(events)[0].alert_id)
        self.assertEqual(DEFAULT_RULE_REGISTRY.get("WINDOWS_PRIVILEGED_LOGON").detection_window_seconds, 300)

    def test_non_windows_privileged_event_is_not_matched(self):
        events = ingest_file(Path("fixtures/windows-phase12.xml"), source="windows_security").events
        copied = events[-1].__class__(events[-1].timestamp, "linux-auth", events[-1].event_type,
                                      events[-1].hostname, events[-1].process, events[-1].username,
                                      events[-1].source_ip, events[-1].message, events[-1].raw, events[-1].event_id)
        self.assertFalse(any(alert.rule_id == "WINDOWS_PRIVILEGED_LOGON" for alert in DetectionEngine().detect([copied])))

    def test_authentication_failure_and_success_are_reused(self):
        events = ingest_file(Path("fixtures/windows-phase12.xml"), source="windows_security").events
        alerts = DetectionEngine().detect(events)
        self.assertFalse(any(alert.rule_id == "REPEATED_AUTH_FAILURE" for alert in alerts))
        self.assertFalse(any(alert.rule_id == "SUCCESS_AFTER_FAILURES" for alert in alerts))

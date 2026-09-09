import unittest
from datetime import datetime, timezone

from sentinelforge.alerts import Alert, create_alert
from sentinelforge.events import SecurityEvent


class AlertTests(unittest.TestCase):
    def test_shape_severity_evidence_and_determinism(self):
        event = SecurityEvent(datetime(2025, 1, 1, tzinfo=timezone.utc), "linux-auth", "authentication_failure", "host", "sshd", "alice", "192.0.2.1", "Failed", "raw")
        first = create_alert("RULE", "medium", "Title", "Description", [event])
        second = create_alert("RULE", "medium", "Title", "Description", [event])
        self.assertEqual(first.alert_id, second.alert_id)
        self.assertEqual(first.to_dict()["severity"], "medium")
        self.assertEqual(first.to_dict()["evidence"][0]["raw"], "raw")

    def test_invalid_severity_rejected(self):
        with self.assertRaises(ValueError):
            Alert("id", "rule", "unknown", datetime.now(timezone.utc), "title", "description", [])

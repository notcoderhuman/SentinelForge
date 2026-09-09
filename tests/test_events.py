import json
import unittest
from datetime import datetime, timezone

from sentinelforge.events import SecurityEvent


class EventModelTests(unittest.TestCase):
    def make_event(self):
        return SecurityEvent(datetime(2025, 1, 1, tzinfo=timezone.utc), "linux-auth", "authentication_failure", "host", "sshd", "alice", "192.0.2.1", "Failed password", "raw")

    def test_valid_event_serializes(self):
        event = self.make_event()
        serialized = event.to_dict()
        self.assertEqual(serialized["timestamp"], "2025-01-01T00:00:00Z")
        self.assertEqual(json.loads(json.dumps(serialized))["raw"], "raw")

    def test_missing_required_field_rejected(self):
        with self.assertRaises(ValueError):
            SecurityEvent(datetime.now(timezone.utc), "", "type", None, None, None, None, "message", "raw")

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            SecurityEvent(datetime(2025, 1, 1), "linux-auth", "type", None, None, None, None, "message", "raw")

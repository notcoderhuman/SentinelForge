import unittest
from datetime import datetime, timezone

from sentinelforge.events import SecurityEvent
from sentinelforge.observable_engine import extract_observables
from sentinelforge.observables import Observable, create_observable
from sentinelforge.threat_context import ThreatContext
from sentinelforge.threat_context_engine import match_context


class ObservableTests(unittest.TestCase):
    def test_extraction_types_order_and_provenance(self):
        event = SecurityEvent(datetime(2025, 1, 1, tzinfo=timezone.utc), "linux-auth", "test", "host", "sshd", "alice", "192.0.2.1", "Visit https://example.test/path and example.test", "raw")
        observables = extract_observables([event, event])
        values = {(item.observable_type, item.value) for item in observables}
        self.assertEqual(values, {("ipv4", "192.0.2.1"), ("username", "alice"), ("url", "https://example.test/path"), ("domain", "example.test")})
        self.assertTrue(all(item.provenance for item in observables))
        self.assertEqual(observables, sorted(observables, key=lambda item: (item.observable_type, item.value, item.timestamp, item.observable_id)))

    def test_validation_and_deterministic_id(self):
        timestamp = datetime(2025, 1, 1, tzinfo=timezone.utc)
        first = create_observable("ipv4", "192.0.2.1", "linux-auth", timestamp, "event.source_ip")
        second = create_observable("ipv4", "192.0.2.1", "linux-auth", timestamp, "event.source_ip")
        self.assertEqual(first.observable_id, second.observable_id)
        with self.assertRaises(ValueError):
            Observable("id", "ipv4", "not-ip", "source", timestamp, "provenance", 101)

    def test_context_exact_matching_and_unknowns(self):
        timestamp = datetime(2025, 1, 1, tzinfo=timezone.utc)
        observable = create_observable("ipv4", "192.0.2.1", "linux-auth", timestamp, "event.source_ip")
        context = ThreatContext("ipv4", "192.0.2.1", "suspicious", "demo", 70, "local rationale", "local-demo")
        self.assertEqual(match_context([observable], [context]), [context])
        self.assertEqual(match_context([create_observable("ipv4", "192.0.2.2", "linux-auth", timestamp, "event.source_ip")], [context]), [])
        with self.assertRaises(ValueError):
            ThreatContext("ipv4", "192.0.2.1", "malicious_guess", "label", 50, "reason", "source")

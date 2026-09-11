import json
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.events import SecurityEvent
from sentinelforge.detection.registry import DEFAULT_RULE_REGISTRY
from sentinelforge.ingestion.pipeline import ingest_file, ingest_lines, parser_for_source
from sentinelforge.threat_context import ThreatContext


FIXTURE = Path("fixtures/network-phase17.ndjson")


class NetworkParserTests(unittest.TestCase):
    def test_fixture_normalizes_network_fields_and_preserves_raw_json(self):
        result = ingest_file(FIXTURE, source="network_connection")
        self.assertEqual(len(result.events), 10)
        self.assertFalse(result.diagnostics)
        event = result.events[0]
        self.assertEqual(event.source, "network_connection")
        self.assertEqual(event.event_type, "network_connection")
        self.assertEqual(event.source_ip, "192.0.2.10")
        self.assertEqual(event.source_port, 41000)
        self.assertEqual(event.destination_ip, "203.0.113.10")
        self.assertEqual(event.destination_port, 443)
        self.assertEqual(event.protocol, "tcp")
        self.assertEqual(event.process_name, "curl")
        self.assertEqual(json.loads(event.raw)["username"], "alice")

    def test_malformed_records_are_diagnostics_and_source_is_explicit(self):
        lines = [
            "not-json",
            json.dumps({"timestamp": "2025-01-01T00:00:00Z"}),
            json.dumps({
                "timestamp": "2025-01-01T00:00:00Z", "source_ip": "192.0.2.1",
                "source_port": 1, "destination_ip": "203.0.113.1",
                "destination_port": 443, "protocol": "tcp",
            }),
        ]
        result = ingest_lines(lines, parser=parser_for_source("network"))
        self.assertEqual(len(result.events), 1)
        self.assertEqual(len(result.diagnostics), 2)
        self.assertEqual([diagnostic.line_number for diagnostic in result.diagnostics], [1, 2])
        with self.assertRaises(ValueError):
            parser_for_source("network-feed")


def network_event(timestamp, *, direction="outbound", source_ip="192.0.2.50", destination_ip="203.0.113.50"):
    return SecurityEvent(
        timestamp=timestamp,
        source="network_connection",
        event_type="network_connection",
        hostname=None,
        process="curl",
        username="alice",
        source_ip=source_ip,
        message=f"tcp connection {source_ip}:40000 -> {destination_ip}:443",
        raw=json.dumps({"timestamp": timestamp.isoformat(), "source_ip": source_ip,
                        "source_port": 40000, "destination_ip": destination_ip,
                        "destination_port": 443, "protocol": "tcp",
                        "direction": direction}) if direction is not None else "{}",
        source_port=40000,
        destination_ip=destination_ip,
        destination_port=443,
        protocol="tcp",
        direction=direction,
    )


class NetworkDetectionTests(unittest.TestCase):
    def test_network_relationship_detections_and_registry_are_deterministic(self):
        events = ingest_file(FIXTURE, source="network_connection").events
        first = DetectionEngine().detect(events)
        second = DetectionEngine().detect(list(reversed(events)))
        expected = {
            "SOURCE_CONTACTS_MANY_DESTINATIONS",
            "DESTINATION_CONTACTED_BY_MANY_SOURCES",
        }
        self.assertTrue(expected.issubset({alert.rule_id for alert in first}))
        self.assertEqual(
            [(alert.rule_id, alert.evidence) for alert in first],
            [(alert.rule_id, alert.evidence) for alert in second],
        )
        self.assertEqual(DEFAULT_RULE_REGISTRY.get("SOURCE_CONTACTS_MANY_DESTINATIONS").detection_window_seconds, 120)
        self.assertEqual(DEFAULT_RULE_REGISTRY.get("REPEATED_CONNECTION_TO_SAME_DESTINATION").evidence_requirements[0].split()[0], "five")

    def test_suspicious_destination_requires_explicit_outbound_context(self):
        base = datetime(2025, 1, 1, tzinfo=timezone.utc)
        context = (ThreatContext("ipv4", "203.0.113.50", "suspicious", "fixture", 50, "test", "fixture"),)
        self.assertEqual(
            [alert.rule_id for alert in DetectionEngine().detect(
                [network_event(base)], context)],
            ["OUTBOUND_CONNECTION_TO_SUSPICIOUS_IP"],
        )
        self.assertFalse(DetectionEngine().detect([network_event(base, direction="INBOUND")], context))
        self.assertFalse(DetectionEngine().detect([network_event(base, direction=None)], context))

    def test_repeated_same_source_destination_threshold_and_window(self):
        base = datetime(2025, 1, 1, tzinfo=timezone.utc)
        at_threshold = [network_event(base + timedelta(seconds=30 * index)) for index in range(5)]
        below_threshold = at_threshold[:4]
        self.assertIn("REPEATED_CONNECTION_TO_SAME_DESTINATION",
                      {alert.rule_id for alert in DetectionEngine().detect(at_threshold)})
        self.assertNotIn("REPEATED_CONNECTION_TO_SAME_DESTINATION",
                         {alert.rule_id for alert in DetectionEngine().detect(below_threshold)})
        boundary = [network_event(base + timedelta(seconds=30 * index)) for index in range(5)]
        outside = [network_event(base + timedelta(seconds=30 * index)) for index in range(4)]
        outside.append(network_event(base + timedelta(seconds=121)))
        self.assertIn("REPEATED_CONNECTION_TO_SAME_DESTINATION",
                      {alert.rule_id for alert in DetectionEngine().detect(boundary)})
        self.assertNotIn("REPEATED_CONNECTION_TO_SAME_DESTINATION",
                         {alert.rule_id for alert in DetectionEngine().detect(outside)})

    def test_network_results_remain_deterministic(self):
        events = ingest_file(FIXTURE, source="network_connection").events
        first = DetectionEngine().detect(events)
        second = DetectionEngine().detect(list(reversed(events)))
        self.assertEqual(
            [(alert.rule_id, alert.alert_id) for alert in first],
            [(alert.rule_id, alert.alert_id) for alert in second],
        )


if __name__ == "__main__":
    unittest.main()

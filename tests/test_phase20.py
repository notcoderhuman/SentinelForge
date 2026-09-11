"""Phase 20 focused coverage for DNS parsing and deterministic detections."""

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.ingestion.pipeline import ingest_file, ingest_lines, parser_for_source
from sentinelforge.threat_context import ThreatContext


FIXTURE = Path("fixtures/dns-phase20.ndjson")
BASE = datetime(2025, 1, 20, tzinfo=timezone.utc)
DNS_RULES = {
    "DNS_QUERY_TO_SUSPICIOUS_DOMAIN",
    "REPEATED_DNS_QUERY",
    "SOURCE_QUERIES_MANY_DOMAINS",
    "DOMAIN_QUERIED_BY_MANY_SOURCES",
}


def dns_line(seconds=0, *, source_ip="192.0.2.10", query="example.test",
             source_port=53000, optional=True, **extra):
    record = {
        "timestamp": (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ip": source_ip,
        "source_port": source_port,
        "hostname": "dns-host",
        "query": query,
        "query_type": "A",
        "response_code": "NOERROR",
    }
    if optional:
        record.update({"answers": ["203.0.113.10"], "username": "alice", "direction": "outbound"})
    record.update(extra)
    return json.dumps(record, separators=(",", ":"))


class Phase20DNSParserTests(unittest.TestCase):
    def test_fixture_uses_production_ingestion_parser_and_preserves_raw(self):
        result = ingest_file(FIXTURE, source="dns_query")
        self.assertEqual(len(result.events), 10)
        self.assertFalse(result.diagnostics)
        event = result.events[0]
        self.assertEqual(event.source, "dns_query")
        self.assertEqual(event.event_type, "dns_query")
        self.assertEqual(event.source_ip, "192.0.2.10")
        self.assertEqual(event.query, "bad.example.test")
        self.assertEqual(event.query_type, "A")
        self.assertEqual(event.response_code, "NOERROR")
        self.assertEqual(event.resolved_ip, "203.0.113.200")
        self.assertEqual(event.source_ip, "192.0.2.10")
        self.assertEqual(event.source_port, 53000)
        self.assertEqual(json.loads(event.raw)["answers"], ["203.0.113.200"])

    def test_optional_answers_and_identity_fields_are_preserved_without_invention(self):
        record = json.loads(dns_line())
        record.pop("answers")
        record.pop("username")
        result = ingest_lines([json.dumps(record)], parser=parser_for_source("dns_query"))
        self.assertEqual(len(result.events), 1)
        self.assertFalse(result.diagnostics)
        event = result.events[0]
        self.assertEqual(event.hostname, "dns-host")
        self.assertIsNone(event.username)
        self.assertEqual(event.answers, [])

    def test_malformed_and_missing_records_become_diagnostics(self):
        result = ingest_lines([
            "not-json",
            "[]",
            json.dumps({"timestamp": "2025-01-20T00:00:00Z"}),
            dns_line(source_ip="not-an-ip"),
            dns_line(),
        ], parser=parser_for_source("dns_query"))
        self.assertEqual(len(result.events), 1)
        self.assertEqual([diagnostic.line_number for diagnostic in result.diagnostics], [1, 2, 3, 4])
        self.assertEqual(len(result.diagnostics), 4)

    def test_source_selection_is_explicit(self):
        self.assertIsNotNone(parser_for_source("dns_query"))
        with self.assertRaises(ValueError):
            parser_for_source("dns-feed")


class Phase20DNSDetectionTests(unittest.TestCase):
    def test_active_parser_detection_path_emits_all_four_dns_rules(self):
        events = ingest_file(FIXTURE, source="dns_query").events
        repeated = ingest_lines(
            [dns_line(i * 10, query="bad.example.test", source_port=53100 + i)
             for i in range(5)], parser=parser_for_source("dns_query")
        ).events
        context = [ThreatContext("domain", "bad.example.test", "suspicious", "fixture", 90,
                                 "explicit local test context", "phase20")]
        source_many = ingest_lines(
            [dns_line(i * 10, query=f"unique-{i}.test", source_port=53200 + i)
             for i in range(5)], parser=parser_for_source("dns_query")
        ).events
        alerts = DetectionEngine().detect(events + repeated + source_many, context)
        rules = {alert.rule_id for alert in alerts}
        self.assertIn("REPEATED_DNS_QUERY", rules)
        self.assertIn("SOURCE_QUERIES_MANY_DOMAINS", rules)
        self.assertIn("DOMAIN_QUERIED_BY_MANY_SOURCES", rules)
        self.assertIn("DNS_QUERY_TO_SUSPICIOUS_DOMAIN", {alert.rule_id for alert in alerts})

    def test_context_is_exact_and_partial_domain_match_is_not_enough(self):
        context = [ThreatContext("domain", "example.test", "suspicious", "fixture", 90,
                                 "exact only", "phase20")]
        exact = ingest_lines([dns_line(query="example.test")], parser=parser_for_source("dns_query")).events
        partial = ingest_lines([dns_line(query="sub.example.test")], parser=parser_for_source("dns_query")).events
        self.assertIn("DNS_QUERY_TO_SUSPICIOUS_DOMAIN",
                      {alert.rule_id for alert in DetectionEngine().detect(exact, context)})
        self.assertNotIn("DNS_QUERY_TO_SUSPICIOUS_DOMAIN",
                         {alert.rule_id for alert in DetectionEngine().detect(partial, context)})

    def test_missing_identities_do_not_create_distinct_source_or_domain_matches(self):
        records = [dns_line(i * 10, source_ip="192.0.2.50", query=name)
                   for i, name in enumerate(("a.test", "b.test", "c.test", "d.test", "e.test"))]
        records = [json.loads(item) for item in records]
        for record in records:
            record.pop("hostname")
        events = ingest_lines([json.dumps(item) for item in records], parser=parser_for_source("dns_query")).events
        rules = {alert.rule_id for alert in DetectionEngine().detect(events)}
        self.assertNotIn("SOURCE_QUERIES_MANY_DOMAINS", rules)
        self.assertNotIn("DOMAIN_QUERIED_BY_MANY_SOURCES", rules)

    def test_inclusive_120_second_boundary_excludes_121_seconds(self):
        context = [ThreatContext("domain", "bad.example.test", "suspicious", "fixture", 90,
                                 "exact", "phase20")]
        at_boundary = [dns_line(i * 30, query="bad.example.test", source_port=53000 + i)
                       for i in range(5)]
        outside = [dns_line(0, query="bad.example.test", source_port=53000 + i) for i in range(4)]
        outside.append(dns_line(121, query="bad.example.test", source_port=53004))
        self.assertIn("REPEATED_DNS_QUERY",
                      {a.rule_id for a in DetectionEngine().detect(
                          ingest_lines(at_boundary, parser=parser_for_source("dns_query")).events, context)})
        self.assertNotIn("REPEATED_DNS_QUERY",
                         {a.rule_id for a in DetectionEngine().detect(
                             ingest_lines(outside, parser=parser_for_source("dns_query")).events, context)})

    def test_ids_evidence_and_alert_order_are_deterministic_under_reversal(self):
        events = ingest_file(FIXTURE, source="dns_query").events
        context = [ThreatContext("domain", "bad.example.test", "suspicious", "fixture", 90,
                                 "exact", "phase20")]
        first = DetectionEngine().detect(events, context)
        second = DetectionEngine().detect(list(reversed(events)), context)
        self.assertEqual(
            [(a.rule_id, a.alert_id, [event.raw for event in a.evidence]) for a in first],
            [(a.rule_id, a.alert_id, [event.raw for event in a.evidence]) for a in second],
        )

    def test_dns_events_do_not_participate_in_existing_network_correlation(self):
        events = ingest_file(FIXTURE, source="dns_query").events
        rules = {alert.rule_id for alert in DetectionEngine().detect(events)}
        self.assertNotIn("AUTHENTICATION_TO_NETWORK_ACTIVITY", rules)
        self.assertNotIn("NETWORK_TO_PROCESS_ACTIVITY", rules)
        self.assertNotIn("AUTH_NETWORK_PROCESS_CHAIN", rules)


if __name__ == "__main__":
    unittest.main()

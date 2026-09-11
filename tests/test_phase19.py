"""Phase 19 focused coverage for cross-source relationships and correlation semantics."""

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinelforge.alerts import create_alert
from sentinelforge.correlation_engine import correlate_alerts
from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.events import SecurityEvent
from sentinelforge.ingestion.pipeline import ingest_file
from sentinelforge.parsers.linux_auth import parse_lines


FIXTURE = Path("fixtures/phase19-cross-source.ndjson")
BASE = datetime(2025, 1, 3, tzinfo=timezone.utc)


def auth_line(seconds, user="alice", source="192.0.2.1", pid=1, kind="failure"):
    timestamp = (BASE + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if kind == "success":
        text = f"Accepted password for {user} from {source} port 22 ssh2"
    else:
        text = f"Failed password for {user} from {source} port 22 ssh2"
    return f"{timestamp} host sshd[{pid}]: {text}"


def event(seconds, event_type, user="alice", raw=None, hostname="host"):
    raw = raw or f"{event_type}:{seconds}:{user}:{hostname}"
    process = "sshd" if event_type not in {"sudo_activity", "process_execution"} else ("sudo" if event_type == "sudo_activity" else "worker")
    return SecurityEvent(BASE + timedelta(seconds=seconds), "linux-auth", event_type,
                         hostname, process, user, "192.0.2.1", event_type, raw)


def cross_alert(rule, item):
    return create_alert(rule, "medium", rule, rule, [item])


class Phase19FixtureAndRelationshipsTests(unittest.TestCase):
    def test_fixture_covers_both_network_relationship_directions(self):
        result = ingest_file(FIXTURE, source="network_connection")
        self.assertEqual(len(result.events), 10)
        self.assertFalse(result.diagnostics)
        alerts = DetectionEngine().detect(result.events)
        rules = {alert.rule_id for alert in alerts}
        self.assertIn("SOURCE_CONTACTS_MANY_DESTINATIONS", rules)
        self.assertIn("DESTINATION_CONTACTED_BY_MANY_SOURCES", rules)

    def test_all_four_relationships_require_matching_identity_and_have_boundaries(self):
        source_accounts = [auth_line(i * 10, user=u) for i, u in enumerate(("alice", "bob", "carol"))]
        account_sources = [auth_line(i * 10, source=f"192.0.2.{i + 1}") for i in range(3)]
        events = parse_lines(source_accounts + account_sources)[0]
        rules = {alert.rule_id for alert in DetectionEngine().detect(events)}
        self.assertIn("SOURCE_TARGETS_MULTIPLE_ACCOUNTS", rules)
        self.assertIn("ACCOUNT_TARGETED_BY_MULTIPLE_SOURCES", rules)

        # The inclusive 120-second relationship window accepts 0..120, not 121.
        exact = parse_lines([auth_line(0, user="a"), auth_line(60, user="b"), auth_line(120, user="c")])[0]
        late = parse_lines([auth_line(0, user="a"), auth_line(60, user="b"), auth_line(121, user="c")])[0]
        self.assertIn("SOURCE_TARGETS_MULTIPLE_ACCOUNTS", {a.rule_id for a in DetectionEngine().detect(exact)})
        self.assertNotIn("SOURCE_TARGETS_MULTIPLE_ACCOUNTS", {a.rule_id for a in DetectionEngine().detect(late)})

        missing = parse_lines([auth_line(0, user="alice"), auth_line(10, user="bob"), auth_line(20, user="carol")])[0]
        missing[0] = missing[0].__class__(missing[0].timestamp, missing[0].source, missing[0].event_type, missing[0].hostname, missing[0].process, None, missing[0].source_ip, missing[0].message, missing[0].raw)
        mismatch = parse_lines([auth_line(0, user="alice", source="192.0.2.1"),
                                auth_line(10, user="bob", source="192.0.2.2"),
                                auth_line(20, user="carol", source="192.0.2.3")])[0]
        self.assertNotIn("SOURCE_TARGETS_MULTIPLE_ACCOUNTS", {a.rule_id for a in DetectionEngine().detect(missing)})
        self.assertNotIn("ACCOUNT_TARGETED_BY_MULTIPLE_SOURCES", {a.rule_id for a in DetectionEngine().detect(mismatch)})

    def test_duplicate_suppression_and_multiple_chains(self):
        # Duplicates do not manufacture three distinct accounts or sources.
        duplicate_accounts = parse_lines([auth_line(0, user="alice")] * 3)[0]
        duplicate_sources = parse_lines([auth_line(0, source="192.0.2.1")] * 3)[0]
        self.assertNotIn("SOURCE_TARGETS_MULTIPLE_ACCOUNTS", {a.rule_id for a in DetectionEngine().detect(duplicate_accounts)})
        self.assertNotIn("ACCOUNT_TARGETED_BY_MULTIPLE_SOURCES", {a.rule_id for a in DetectionEngine().detect(duplicate_sources)})
        first = parse_lines([auth_line(0, user="a"), auth_line(10, user="b"), auth_line(20, user="c"),
                             auth_line(30, user="x", source="192.0.2.9"), auth_line(40, user="x", source="192.0.2.8"),
                             auth_line(50, user="x", source="192.0.2.7")])[0]
        second = parse_lines(list(reversed([auth_line(0, user="a"), auth_line(10, user="b"), auth_line(20, user="c"),
                                            auth_line(30, user="x", source="192.0.2.9"), auth_line(40, user="x", source="192.0.2.8"),
                                            auth_line(50, user="x", source="192.0.2.7")] )))[0]
        self.assertEqual([(a.rule_id, a.alert_id, [e.raw for e in a.evidence]) for a in DetectionEngine().detect(first)],
                         [(a.rule_id, a.alert_id, [e.raw for e in a.evidence]) for a in DetectionEngine().detect(second)])


class Phase19CorrelationTests(unittest.TestCase):
    def alerts(self, failure_seconds, success_seconds, sudo_seconds, user="alice"):
        return [create_alert("FAIL", "medium", "failure", "failure", [event(failure_seconds, "authentication_failure", user)]),
                create_alert("SUCCESS", "medium", "success", "success", [event(success_seconds, "authentication_success", user)]),
                create_alert("SUDO", "low", "sudo", "sudo", [event(sudo_seconds, "sudo_activity", user)])]

    def test_chronology_boundaries_and_identity_semantics(self):
        at_300 = correlate_alerts(self.alerts(0, 300, 300))
        self.assertEqual({f.name for f in at_300}, {"AUTHENTICATION_ESCALATION", "AUTHENTICATION_TO_PRIVILEGED_ACTIVITY"})
        # Each 301-second edge is outside its relationship window.
        self.assertNotIn("AUTHENTICATION_ESCALATION", {f.name for f in correlate_alerts(self.alerts(0, 301, 301))})
        self.assertNotIn("AUTHENTICATION_TO_PRIVILEGED_ACTIVITY", {f.name for f in correlate_alerts(self.alerts(0, 30, 331))})
        for finding in at_300:
            self.assertLessEqual(finding.start_time, finding.end_time)
            self.assertEqual(list(finding.evidence_ids), list(dict.fromkeys(finding.evidence_ids)))

        missing = self.alerts(0, 30, 60, user=None)
        mismatch = self.alerts(0, 30, 60, user="bob")
        # Missing identities never match; mismatched identities across events never match.
        self.assertEqual(correlate_alerts(missing), [])
        mismatch[1] = create_alert("SUCCESS", "medium", "success", "success", [event(30, "authentication_success", "bob")])
        self.assertEqual(correlate_alerts([missing[0], mismatch[1], missing[2]]), [])

    def test_all_four_cross_source_correlation_relationships(self):
        success = event(0, "authentication_success")
        network = event(30, "network_connection")
        process = event(60, "process_execution")
        alerts = DetectionEngine().detect([success, network, process])
        findings = correlate_alerts(alerts)
        self.assertEqual({finding.name for finding in findings}, {
            "AUTHENTICATION_TO_NETWORK_ACTIVITY", "AUTHENTICATION_TO_PROCESS_ACTIVITY",
            "NETWORK_TO_PROCESS_ACTIVITY", "AUTH_NETWORK_PROCESS_CHAIN",
        })
        self.assertTrue(all(finding.related_alert_ids and finding.evidence_ids for finding in findings))
        self.assertNotIn("AUTHENTICATION_TO_NETWORK_ACTIVITY", {
            finding.name for finding in correlate_alerts([cross_alert("SUCCESS", event(0, "authentication_success", hostname="other")),
                                                         cross_alert("NETWORK", network)])
        })

    def test_independent_relationship_control_flow_and_no_duplicates(self):
        success = event(0, "authentication_success")
        network_one = event(30, "network_connection", raw="network-one")
        network_two = event(40, "network_connection", raw="network-two")
        process = event(60, "process_execution")

        auth_process = DetectionEngine().detect([success, process])
        self.assertEqual(
            [alert.rule_id for alert in auth_process].count("AUTHENTICATION_TO_PROCESS_ACTIVITY"), 1
        )

        network_process = DetectionEngine().detect([network_one, process])
        self.assertEqual(
            [alert.rule_id for alert in network_process].count("NETWORK_TO_PROCESS_ACTIVITY"), 1
        )

        all_events = DetectionEngine().detect([success, network_one, network_two, process])
        rules = [alert.rule_id for alert in all_events]
        self.assertEqual(rules.count("AUTHENTICATION_TO_PROCESS_ACTIVITY"), 1)
        self.assertEqual(rules.count("AUTH_NETWORK_PROCESS_CHAIN"), 2)
        single_chain = DetectionEngine().detect([success, network_one, process])
        self.assertEqual([alert.rule_id for alert in single_chain].count("AUTH_NETWORK_PROCESS_CHAIN"), 1)
        reversed_events = DetectionEngine().detect([process, network_two, success, network_one])
        self.assertEqual(
            [(alert.rule_id, alert.alert_id) for alert in all_events],
            [(alert.rule_id, alert.alert_id) for alert in reversed_events],
        )

    def test_production_network_parser_and_chain_overall_window(self):
        lines = [
            json.dumps({"timestamp": "2025-01-03T00:00:00Z", "source_ip": "192.0.2.1", "source_port": 40000, "destination_ip": "203.0.113.1", "destination_port": 443, "protocol": "tcp", "username": "alice", "hostname": "host"}),
            json.dumps({"timestamp": "2025-01-03T00:00:30Z", "source_ip": "192.0.2.1", "source_port": 40001, "destination_ip": "203.0.113.2", "destination_port": 443, "protocol": "tcp", "username": "alice", "hostname": "host"}),
        ]
        auth = event(0, "authentication_success")
        process = event(60, "process_execution")
        # Parsed records with an explicit hostname participate in cross-source matching.
        from sentinelforge.ingestion.pipeline import ingest_lines
        from sentinelforge.parsers.network import parse_lines as parse_network_lines
        result = ingest_lines(lines, parser=parse_network_lines)
        self.assertFalse(result.diagnostics)
        self.assertTrue(result.events[0].hostname == "host")
        alerts = DetectionEngine().detect([auth, result.events[0], process])
        self.assertIn("AUTHENTICATION_TO_NETWORK_ACTIVITY", {alert.rule_id for alert in alerts})
        self.assertIn("NETWORK_TO_PROCESS_ACTIVITY", {alert.rule_id for alert in alerts})
        late_process = event(600, "process_execution")
        self.assertNotIn("AUTH_NETWORK_PROCESS_CHAIN", {alert.rule_id for alert in DetectionEngine().detect([auth, result.events[0], late_process])})

    def test_multiple_chains_mixed_data_and_reversed_input_are_deterministic(self):
        alerts = self.alerts(0, 30, 60)
        alerts += [create_alert("FAIL2", "medium", "failure", "failure", [event(100, "authentication_failure", "bob", "b-fail")]),
                   create_alert("SUCCESS2", "medium", "success", "success", [event(130, "authentication_success", "bob", "b-success")])]
        first = correlate_alerts(alerts)
        second = correlate_alerts(list(reversed(alerts)))
        self.assertEqual([f.to_dict() for f in first], [f.to_dict() for f in second])
        self.assertEqual(len(first), 3)
        self.assertTrue(all(f.start_time <= f.end_time for f in first))


if __name__ == "__main__":
    unittest.main()

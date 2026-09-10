import unittest
from datetime import datetime, timedelta, timezone

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.registry import DEFAULT_RULE_REGISTRY
from sentinelforge.detection.rules import RuleConfig
from sentinelforge.parsers.linux_auth import parse_lines


class DetectionTests(unittest.TestCase):
    def events(self, count, spacing=10, ip="192.0.2.1", user="alice"):
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        lines = [f"{(start + timedelta(seconds=index * spacing)).strftime('%Y-%m-%dT%H:%M:%SZ')} host sshd[{index}]: Failed password for {user} from {ip} port 22 ssh2" for index in range(count)]
        return parse_lines(lines)[0]

    def test_threshold_and_exact_window(self):
        self.assertFalse(any(a.rule_id == "SSH_BRUTE_FORCE" for a in DetectionEngine().detect(self.events(4))))
        self.assertTrue(any(a.rule_id == "SSH_BRUTE_FORCE" for a in DetectionEngine().detect(self.events(5, spacing=30))))
        self.assertFalse(any(a.rule_id == "SSH_BRUTE_FORCE" for a in DetectionEngine().detect(self.events(5, spacing=31))))

    def test_ip_grouping_and_outside_window(self):
        events = self.events(4, ip="192.0.2.1") + self.events(1, ip="192.0.2.2")
        self.assertFalse(any(a.rule_id == "SSH_BRUTE_FORCE" for a in DetectionEngine().detect(events)))

    def test_repeated_failure_success_and_sudo(self):
        failure_events = self.events(3)
        success_line = "2025-01-01T00:01:00Z host sshd[9]: Accepted password for alice from 192.0.2.1 port 22 ssh2"
        sudo_line = "2025-01-01T00:01:01Z host sudo[10]: user=alice command=/usr/bin/id"
        success, _ = parse_lines([success_line, sudo_line])
        alerts = DetectionEngine(RuleConfig()).detect(failure_events + success)
        rule_ids = {alert.rule_id for alert in alerts}
        self.assertIn("REPEATED_AUTH_FAILURE", rule_ids)
        self.assertIn("SUCCESS_AFTER_FAILURES", rule_ids)
        self.assertIn("SUSPICIOUS_SUDO_ACTIVITY", rule_ids)

    def test_rule_can_be_disabled(self):
        events = self.events(3)
        alerts = DetectionEngine(RuleConfig(sudo_enabled=False)).detect(events)
        self.assertFalse(any(alert.rule_id == "SUSPICIOUS_SUDO_ACTIVITY" for alert in alerts))

    def test_source_targets_multiple_accounts_threshold_window_and_evidence(self):
        lines = [
            "2025-01-01T00:00:00Z host sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2",
            "2025-01-01T00:00:10Z host sshd[2]: Failed password for bob from 192.0.2.1 port 22 ssh2",
            "2025-01-01T00:00:20Z host sshd[3]: Failed password for carol from 192.0.2.1 port 22 ssh2",
        ]
        alerts = DetectionEngine().detect(parse_lines(lines)[0])
        match = [alert for alert in alerts if alert.rule_id == "SOURCE_TARGETS_MULTIPLE_ACCOUNTS"]
        self.assertEqual(len(match), 1)
        self.assertEqual(len(match[0].evidence), 3)
        self.assertEqual(match[0].severity, "medium")
        self.assertFalse(any(alert.rule_id == "SOURCE_TARGETS_MULTIPLE_ACCOUNTS" for alert in DetectionEngine().detect(parse_lines(lines[:2])[0])))
        late = [
            "2025-01-01T00:00:00Z host sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2",
            "2025-01-01T00:01:01Z host sshd[2]: Failed password for bob from 192.0.2.1 port 22 ssh2",
            "2025-01-01T00:02:02Z host sshd[3]: Failed password for carol from 192.0.2.1 port 22 ssh2",
        ]
        self.assertFalse(any(alert.rule_id == "SOURCE_TARGETS_MULTIPLE_ACCOUNTS" for alert in DetectionEngine().detect(parse_lines(late)[0])))

    def test_account_targeted_by_multiple_sources_and_unrelated_entities(self):
        lines = [
            "2025-01-01T00:00:00Z host sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2",
            "2025-01-01T00:00:10Z host sshd[2]: Failed password for alice from 192.0.2.2 port 22 ssh2",
            "2025-01-01T00:00:20Z host sshd[3]: Failed password for alice from 192.0.2.3 port 22 ssh2",
        ]
        alerts = DetectionEngine().detect(parse_lines(lines)[0])
        match = [alert for alert in alerts if alert.rule_id == "ACCOUNT_TARGETED_BY_MULTIPLE_SOURCES"]
        self.assertEqual(len(match), 1)
        self.assertEqual([event.username for event in match[0].evidence], ["alice"] * 3)
        unrelated = [
            "2025-01-01T00:00:00Z host sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2",
            "2025-01-01T00:00:10Z host sshd[2]: Failed password for bob from 192.0.2.2 port 22 ssh2",
            "2025-01-01T00:00:20Z host sshd[3]: Failed password for carol from 192.0.2.3 port 22 ssh2",
        ]
        self.assertFalse(any(alert.rule_id == "ACCOUNT_TARGETED_BY_MULTIPLE_SOURCES" for alert in DetectionEngine().detect(parse_lines(unrelated)[0])))

    def test_phase10_registry_presence_and_determinism(self):
        self.assertEqual(DEFAULT_RULE_REGISTRY.get("SOURCE_TARGETS_MULTIPLE_ACCOUNTS").detection_window_seconds, 120)
        self.assertEqual(DEFAULT_RULE_REGISTRY.get("ACCOUNT_TARGETED_BY_MULTIPLE_SOURCES").detection_window_seconds, 120)
        events = parse_lines([
            "2025-01-01T00:00:00Z host sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2",
            "2025-01-01T00:00:10Z host sshd[2]: Failed password for bob from 192.0.2.1 port 22 ssh2",
            "2025-01-01T00:00:20Z host sshd[3]: Failed password for carol from 192.0.2.1 port 22 ssh2",
        ])[0]
        first = DetectionEngine().detect(events)
        second = DetectionEngine().detect(list(reversed(events)))
        self.assertEqual([(a.alert_id, a.evidence) for a in first], [(a.alert_id, a.evidence) for a in second])

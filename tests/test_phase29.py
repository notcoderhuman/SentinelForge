"""Phase 29 deterministic detection regression corpus and replay quality checks."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.registry import DEFAULT_RULE_REGISTRY
from sentinelforge.detection.rules import RuleConfig
from sentinelforge.events import SecurityEvent
from sentinelforge.replay import evaluate, ExpectedAlert, replay_events
from sentinelforge.threat_context import ThreatContext

BASE = datetime(2025, 2, 1, tzinfo=timezone.utc)
BOUNDARY_RULES = (
    "REPEATED_AUTH_FAILURE",
    "REPEATED_CONNECTION_TO_SAME_DESTINATION",
    "REPEATED_DNS_QUERY",
    "REPEATED_FILE_ACTIVITY",
    "REPEATED_PROCESS_EXECUTION",
    "WINDOWS_SERVICE_START_AFTER_STOP",
)
NEGATIVE_RULES = (
    "AUTHENTICATION_TO_NETWORK_ACTIVITY",
    "DNS_QUERY_TO_SUSPICIOUS_DOMAIN",
    "HOST_MODIFIES_MANY_DISTINCT_FILES",
    "OUTBOUND_CONNECTION_TO_SUSPICIOUS_IP",
    "PRIVILEGED_PROCESS_EXECUTION",
    "REGISTRY_RUN_KEY_MODIFICATION",
    "SERVICE_CREATED_OR_UPDATED",
    "WINDOWS_SERVICE_STOPPED",
)


def coverage_metadata():
    """Build authoritative report metadata from the registry and test metadata."""
    registered = tuple(rule.rule_id for rule in DEFAULT_RULE_REGISTRY.all())
    positive = tuple(sorted(positive_corpus()))
    boundary = tuple(sorted(BOUNDARY_RULES))
    negative = tuple(sorted(NEGATIVE_RULES))
    registered_set = set(registered)
    return {
        "phase": "29",
        "description": "Deterministic detection regression corpus coverage summary.",
        "registered_rules": len(registered),
        "rules_with_positive_coverage": len(positive),
        "rules_with_boundary_coverage": len(boundary),
        "boundary_rules": list(boundary),
        "rules_with_negative_or_near_miss_coverage": len(negative),
        "rules_without_positive_regression_coverage": sorted(registered_set - set(positive)),
        "rules_without_boundary_coverage": sorted(registered_set - set(boundary)),
        "rules_without_negative_or_near_miss_coverage": sorted(registered_set - set(negative)),
        "negative_or_near_miss_rules": list(negative),
    }


def render_coverage_markdown(metadata):
    def bullets(items):
        return "\n".join(f"- {item}" for item in items) or "- None"

    return "\n".join((
        "# Phase 29 Detection Coverage",
        "",
        f"- Registered rules: {metadata['registered_rules']}",
        f"- Positive coverage: {metadata['rules_with_positive_coverage']}",
        f"- Boundary coverage: {metadata['rules_with_boundary_coverage']}",
        f"- Negative/near-miss coverage: {metadata['rules_with_negative_or_near_miss_coverage']}",
        "",
        "Positive coverage means the corpus has a deterministic case that emits each registered rule.",
        "Boundary coverage means threshold and/or temporal boundary behavior is tested for the listed rules.",
        "Negative/near-miss coverage means a targeted false-positive boundary is tested for the listed rules.",
        "Full positive coverage does not imply exhaustive negative or boundary coverage.",
        "",
        "## Rules lacking positive coverage",
        bullets(metadata["rules_without_positive_regression_coverage"]),
        "",
        "## Rules lacking boundary coverage",
        bullets(metadata["rules_without_boundary_coverage"]),
        "",
        "## Rules lacking negative/near-miss coverage",
        bullets(metadata["rules_without_negative_or_near_miss_coverage"]),
        "",
    ))


def event(seconds: int, event_type: str, **values) -> SecurityEvent:
    values.setdefault("hostname", "host-a")
    values.setdefault("process", None)
    values.setdefault("username", None)
    values.setdefault("source_ip", None)
    values.setdefault("message", event_type)
    values.setdefault("source", event_type)
    values.setdefault("event_id", f"phase29-{seconds}-{event_type}-{len(values)}")
    values.setdefault("raw", f"phase29|{seconds}|{event_type}|{json.dumps(values, sort_keys=True, default=str)}")
    return SecurityEvent(timestamp=BASE + timedelta(seconds=seconds), event_type=event_type, **values)


def threshold(count: int, event_type: str, **values):
    return [event(i * 10, event_type, **values) for i in range(count)]


def positive_corpus():
    """Return isolated deterministic positive cases: rule -> events/context."""
    cases = {}
    cases["OUTBOUND_CONNECTION_TO_SUSPICIOUS_IP"] = ([event(0, "network_connection", source_ip="10.0.0.1", destination_ip="203.0.113.10", direction="outbound")], [ThreatContext("ipv4", "203.0.113.10", "suspicious", "test", 80, "fixture", "phase29")])
    cases["REPEATED_CONNECTION_TO_SAME_DESTINATION"] = (threshold(5, "network_connection", source_ip="10.0.0.1", destination_ip="203.0.113.10", direction="inbound"), [])
    cases["SOURCE_CONTACTS_MANY_DESTINATIONS"] = ([event(i * 10, "network_connection", source_ip="10.0.0.1", destination_ip=f"203.0.113.{i + 10}") for i in range(5)], [])
    cases["DESTINATION_CONTACTED_BY_MANY_SOURCES"] = ([event(i * 10, "network_connection", source_ip=f"10.0.0.{i + 1}", destination_ip="203.0.113.10") for i in range(5)], [])
    cases["REPEATED_DNS_QUERY"] = (threshold(5, "dns_query", hostname="host-a", query="same.example"), [])
    cases["SOURCE_QUERIES_MANY_DOMAINS"] = ([event(i * 10, "dns_query", hostname="host-a", query=f"{i}.example") for i in range(5)], [])
    cases["DNS_QUERY_TO_SUSPICIOUS_DOMAIN"] = ([event(0, "dns_query", hostname="host-a", query="bad.example")], [ThreatContext("domain", "bad.example", "known_malicious", "test", 90, "fixture", "phase29")])
    cases["DOMAIN_QUERIED_BY_MANY_SOURCES"] = ([event(i * 10, "dns_query", hostname=f"host-{i}", query="same.example") for i in range(5)], [])
    cases["REPEATED_AUTH_FAILURE"] = (threshold(3, "authentication_failure", username="alice"), [])
    cases["SSH_BRUTE_FORCE"] = (threshold(5, "authentication_failure", username="alice", source_ip="10.0.0.1", process="sshd"), [])
    cases["SUCCESS_AFTER_FAILURES"] = ([event(0, "authentication_failure", username="alice"), event(10, "authentication_success", username="alice")], [])
    cases["SUSPICIOUS_SUDO_ACTIVITY"] = ([event(0, "sudo_activity", username="alice", command="sudo id")], [])
    cases["SOURCE_TARGETS_MULTIPLE_ACCOUNTS"] = ([event(i * 10, "authentication_failure", username=f"user{i}", source_ip="10.0.0.1") for i in range(3)], [])
    cases["ACCOUNT_TARGETED_BY_MULTIPLE_SOURCES"] = ([event(i * 10, "authentication_failure", username="alice", source_ip=f"10.0.0.{i + 1}") for i in range(3)], [])
    cases["WINDOWS_PRIVILEGED_LOGON"] = ([event(0, "privileged_logon", source="windows-security", event_id="4672", username="admin")], [])
    cases["PRIVILEGED_PROCESS_EXECUTION"] = ([event(0, "process_execution", process_name="admin.exe", privilege="admin")], [])
    cases["REPEATED_PROCESS_EXECUTION"] = (threshold(5, "process_execution", hostname="host-a", process_name="worker.exe"), [])
    cases["PARENT_PROCESS_SPAWNS_MANY_CHILDREN"] = ([event(i * 10, "process_execution", hostname="host-a", parent_process_id=10, process_id=i + 100) for i in range(5)], [])
    cases["USER_EXECUTES_MANY_DISTINCT_PROCESSES"] = ([event(i * 10, "process_execution", hostname="host-a", username="alice", process_name=f"tool{i}.exe") for i in range(5)], [])
    cases["REPEATED_FILE_ACTIVITY"] = (threshold(5, "file_activity", hostname="host-a", path="/tmp/a", action="modify"), [])
    cases["HOST_MODIFIES_MANY_DISTINCT_FILES"] = ([event(i * 10, "file_activity", hostname="host-a", username="alice", path=f"/tmp/{i}", action="modify") for i in range(5)], [])
    cases["EXECUTABLE_FILE_CREATED"] = ([event(0, "file_activity", path="/tmp/drop.exe", action="create")], [])
    cases["FILE_ACTIVITY_ON_SENSITIVE_PATH"] = ([event(0, "file_activity", path="/etc/shadow", action="read")], [ThreatContext("file_path", "/etc/shadow", "suspicious", "test", 80, "fixture", "phase29")])
    cases["REGISTRY_VALUE_MODIFIED"] = ([event(0, "registry_change", hive="HKCU", key_path="Software\\App", registry_action="set_value", value_name="Run", value_data="x")], [])
    cases["REGISTRY_KEY_DELETED"] = ([event(0, "registry_change", hive="HKCU", key_path="Software\\App", registry_action="delete_key")], [])
    cases["REGISTRY_RUN_KEY_MODIFICATION"] = ([event(0, "registry_change", hive="HKCU", key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Run", registry_action="set_value", value_name="Updater")], [])
    cases["REGISTRY_ACTIVITY_BY_MANY_PROCESSES"] = ([event(i * 10, "registry_change", hostname="host-a", hive="HKLM", key_path="Software\\App", process_name=f"reg{i}.exe", registry_action="set_value", value_name="v") for i in range(5)], [])
    cases["WINDOWS_SERVICE_STATE_CHANGE"] = ([event(0, "windows_system_event", source="windows_system_event", provider="Service Control Manager", system_event_id=7036, service_name="svc", service_state="running")], [])
    cases["WINDOWS_SERVICE_STOPPED"] = ([event(0, "windows_system_event", source="windows_system_event", provider="Service Control Manager", system_event_id=7036, service_name="svc", service_state="stopped")], [])
    cases["WINDOWS_SYSTEM_EVENT_WITH_COMMAND"] = ([event(0, "windows_system_event", source="windows_system_event", provider="Other Provider", system_event_id=100, system_action="configuration_change", command="configure svc")], [])
    cases["WINDOWS_SERVICE_START_AFTER_STOP"] = ([event(0, "windows_system_event", source="windows_system_event", provider="Service Control Manager", system_event_id=7036, service_name="svc", service_state="stopped"), event(300, "windows_system_event", source="windows_system_event", provider="Service Control Manager", system_event_id=7036, service_name="svc", service_state="running")], [])
    cases["SERVICE_CREATED_OR_UPDATED"] = ([event(0, "system_persistence", persistence_type="service", persistence_action="create", persistence_name="svc")], [])
    cases["SCHEDULED_TASK_CREATED_OR_UPDATED"] = ([event(0, "system_persistence", persistence_type="scheduled_task", persistence_action="create", persistence_name="task")], [])
    cases["SCHEDULED_TASK_CREATED_WITH_COMMAND"] = ([event(0, "system_persistence", persistence_type="scheduled_task", persistence_action="create", persistence_name="task", command="powershell.exe")], [])
    cases["SERVICE_STARTED_AFTER_CREATION"] = ([event(0, "system_persistence", persistence_type="service", persistence_action="create", persistence_name="svc", username="alice"), event(300, "system_persistence", persistence_type="service", persistence_action="start", persistence_name="svc", username="alice")], [])
    cases["AUTHENTICATION_TO_NETWORK_ACTIVITY"] = ([event(0, "authentication_success", username="alice", hostname="host-a"), event(10, "network_connection", username="alice", hostname="host-a", destination_ip="203.0.113.10")], [])
    cases["AUTHENTICATION_TO_PROCESS_ACTIVITY"] = ([event(0, "authentication_success", username="alice", hostname="host-a"), event(10, "process_execution", username="alice", hostname="host-a", process_name="x")], [])
    cases["NETWORK_TO_PROCESS_ACTIVITY"] = ([event(0, "network_connection", hostname="host-a", destination_ip="203.0.113.10"), event(10, "process_execution", hostname="host-a", process_name="x")], [])
    cases["AUTH_NETWORK_PROCESS_CHAIN"] = ([event(0, "authentication_success", username="alice", hostname="host-a"), event(10, "network_connection", username="alice", hostname="host-a", destination_ip="203.0.113.10"), event(20, "process_execution", username="alice", hostname="host-a", process_name="x")], [])
    return cases


class Phase29RegressionCorpusTests(unittest.TestCase):
    def test_every_registered_rule_has_exact_positive_expectation(self):
        cases = positive_corpus()
        registered = {rule.rule_id for rule in DEFAULT_RULE_REGISTRY.all()}
        self.assertEqual(set(cases), registered)
        for rule_id in sorted(cases):
            events, context = cases[rule_id]
            alerts = DetectionEngine().detect(events, context)
            matching = [alert for alert in alerts if alert.rule_id == rule_id]
            definition = DEFAULT_RULE_REGISTRY.get(rule_id)
            self.assertEqual(len(matching), 1, rule_id)
            self.assertEqual(matching[0].severity, definition.severity, rule_id)
            self.assertEqual(evaluate(matching, (ExpectedAlert(rule_id, definition.severity),)).false_positives, 0)

    def test_threshold_boundaries_use_rule_config(self):
        config = RuleConfig()
        before = threshold(config.repeated_connection_threshold - 1, "network_connection", source_ip="10.0.0.1", destination_ip="203.0.113.10")
        exact = threshold(config.repeated_connection_threshold, "network_connection", source_ip="10.0.0.1", destination_ip="203.0.113.10")
        self.assertNotIn("REPEATED_CONNECTION_TO_SAME_DESTINATION", {a.rule_id for a in DetectionEngine(config).detect(before)})
        self.assertIn("REPEATED_CONNECTION_TO_SAME_DESTINATION", {a.rule_id for a in DetectionEngine(config).detect(exact)})
        inside = threshold(config.repeated_connection_threshold, "network_connection", source_ip="10.0.0.1", destination_ip="203.0.113.10")
        outside = [event(0 if i == 0 else config.repeated_connection_window_seconds + 1, "network_connection", source_ip="10.0.0.1", destination_ip="203.0.113.10") for i in range(config.repeated_connection_threshold)]
        self.assertIn("REPEATED_CONNECTION_TO_SAME_DESTINATION", {a.rule_id for a in DetectionEngine(config).detect(inside)})
        self.assertNotIn("REPEATED_CONNECTION_TO_SAME_DESTINATION", {a.rule_id for a in DetectionEngine(config).detect(outside)})

    def test_temporal_threshold_boundaries_across_families(self):
        config = RuleConfig()
        families = [
            ("REPEATED_AUTH_FAILURE", config.repeated_failure_threshold, config.repeated_failure_window_seconds, "authentication_failure", {"username": "alice"}),
            ("REPEATED_DNS_QUERY", config.repeated_dns_query_threshold, config.repeated_dns_query_window_seconds, "dns_query", {"hostname": "host-a", "query": "same.example"}),
            ("REPEATED_PROCESS_EXECUTION", config.repeated_process_threshold, config.repeated_process_window_seconds, "process_execution", {"hostname": "host-a", "process_name": "worker.exe"}),
            ("REPEATED_FILE_ACTIVITY", config.repeated_file_activity_threshold, config.repeated_file_activity_window_seconds, "file_activity", {"hostname": "host-a", "path": "/tmp/a", "action": "modify"}),
        ]
        for rule_id, count, window_seconds, event_type, values in families:
            below = [event(i * 10, event_type, **values) for i in range(count - 1)]
            exact = [event(i * 10, event_type, **values) for i in range(count)]
            outside = [event(0 if i == 0 else window_seconds + 1, event_type, **values) for i in range(count)]
            self.assertNotIn(rule_id, {a.rule_id for a in DetectionEngine(config).detect(below)}, rule_id)
            self.assertIn(rule_id, {a.rule_id for a in DetectionEngine(config).detect(exact)}, rule_id)
            self.assertNotIn(rule_id, {a.rule_id for a in DetectionEngine(config).detect(outside)}, rule_id)

        stopped = event(0, "windows_system_event", source="windows_system_event", provider="Service Control Manager", system_event_id=7036, service_name="svc", service_state="stopped")
        exact = event(config.windows_service_correlation_window_seconds, "windows_system_event", source="windows_system_event", provider="Service Control Manager", system_event_id=7036, service_name="svc", service_state="running")
        late = event(config.windows_service_correlation_window_seconds + 1, "windows_system_event", source="windows_system_event", provider="Service Control Manager", system_event_id=7036, service_name="svc", service_state="running")
        self.assertIn("WINDOWS_SERVICE_START_AFTER_STOP", {a.rule_id for a in DetectionEngine(config).detect([stopped, exact])})
        self.assertNotIn("WINDOWS_SERVICE_START_AFTER_STOP", {a.rule_id for a in DetectionEngine(config).detect([stopped, late])})

    def test_false_positive_cases_remain_silent(self):
        cases = [
            ([event(0, "network_connection", source_ip="10.0.0.1", destination_ip="203.0.113.10", direction="inbound")], [ThreatContext("ipv4", "203.0.113.10", "suspicious", "test", 80, "fixture", "phase29")], "OUTBOUND_CONNECTION_TO_SUSPICIOUS_IP"),
            ([event(i * 10, "file_activity", hostname="host-a", username="alice", path=f"/tmp/{i}", action="read") for i in range(5)], [], "HOST_MODIFIES_MANY_DISTINCT_FILES"),
            ([event(0, "registry_change", hive="HKCU", key_path="Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceExtra", registry_action="set_value", value_name="x")], [], "REGISTRY_RUN_KEY_MODIFICATION"),
            ([event(0, "process_execution", process_name="x", privilege="unknown")], [], "PRIVILEGED_PROCESS_EXECUTION"),
            ([event(0, "authentication_success", username=None, hostname="host-a"), event(1, "network_connection", username=None, hostname="host-a")], [], "AUTHENTICATION_TO_NETWORK_ACTIVITY"),
            ([event(0, "windows_system_event", source="windows_system_event", provider="ServiceMonitorX", system_event_id=7036, service_name="svc", service_state="stopped")], [], "WINDOWS_SERVICE_STOPPED"),
            ([event(0, "system_persistence", persistence_type="service", persistence_action="delete", persistence_name="svc")], [], "SERVICE_CREATED_OR_UPDATED"),
            ([event(0, "dns_query", hostname="host-a", query="good.example")], [ThreatContext("domain", "bad.example", "suspicious", "test", 80, "fixture", "phase29")], "DNS_QUERY_TO_SUSPICIOUS_DOMAIN"),
        ]
        for events, context, rule_id in cases:
            self.assertNotIn(rule_id, {a.rule_id for a in DetectionEngine().detect(events, context)}, rule_id)

    def test_coverage_summary_matches_registry_and_corpus(self):
        coverage = json.loads(Path("fixtures/phase29-coverage.json").read_text(encoding="utf-8"))
        metadata = coverage_metadata()
        self.assertEqual(coverage, metadata)
        self.assertEqual(tuple(coverage["boundary_rules"]), tuple(sorted(coverage["boundary_rules"])))
        self.assertEqual(tuple(coverage["negative_or_near_miss_rules"]), tuple(sorted(coverage["negative_or_near_miss_rules"])))
        self.assertEqual(coverage["rules_without_positive_regression_coverage"], [])
        markdown = Path("fixtures/phase29-coverage.md").read_text(encoding="utf-8")
        self.assertEqual(markdown, render_coverage_markdown(metadata))

    def test_replay_is_repeatable_in_ids_order_and_evaluation(self):
        cases = positive_corpus()
        snapshots = []
        for _ in range(3):
            current = []
            for rule_id in sorted(cases):
                events, context = cases[rule_id]
                alerts = DetectionEngine().detect(events, context)
                current.extend((a.rule_id, a.severity, a.alert_id, tuple(e.event_id for e in a.evidence)) for a in alerts)
            snapshots.append(tuple(current))
        self.assertEqual(snapshots[0], snapshots[1])
        self.assertEqual(snapshots[1], snapshots[2])

    def test_fixture_replay_and_expected_rule_shapes(self):
        from sentinelforge.replay import replay_file
        expected = {
            "auth.log": {"REPEATED_AUTH_FAILURE", "SSH_BRUTE_FORCE", "SUCCESS_AFTER_FAILURES", "SUSPICIOUS_SUDO_ACTIVITY"},
            "network-phase17.ndjson": {"SOURCE_CONTACTS_MANY_DESTINATIONS", "DESTINATION_CONTACTED_BY_MANY_SOURCES"},
            "dns-phase20.ndjson": {"SOURCE_QUERIES_MANY_DOMAINS", "DOMAIN_QUERIED_BY_MANY_SOURCES"},
            "phase21-file-activity.ndjson": {"REPEATED_FILE_ACTIVITY", "EXECUTABLE_FILE_CREATED", "HOST_MODIFIES_MANY_DISTINCT_FILES"},
            "phase22-system-persistence.ndjson": {"SERVICE_CREATED_OR_UPDATED", "SCHEDULED_TASK_CREATED_OR_UPDATED", "SCHEDULED_TASK_CREATED_WITH_COMMAND", "SERVICE_STARTED_AFTER_CREATION"},
            "phase23-registry.ndjson": {"REGISTRY_RUN_KEY_MODIFICATION", "REGISTRY_VALUE_MODIFIED", "REGISTRY_KEY_DELETED", "REGISTRY_ACTIVITY_BY_MANY_PROCESSES"},
            "phase24-windows-system.ndjson": {"WINDOWS_SERVICE_STATE_CHANGE", "WINDOWS_SERVICE_STOPPED", "WINDOWS_SERVICE_START_AFTER_STOP", "WINDOWS_SYSTEM_EVENT_WITH_COMMAND"},
        }
        sources = {"auth.log": "linux_auth", "network-phase17.ndjson": "network_connection", "dns-phase20.ndjson": "dns_query", "phase21-file-activity.ndjson": "file_activity", "phase22-system-persistence.ndjson": "system_persistence", "phase23-registry.ndjson": "registry_change", "phase24-windows-system.ndjson": "windows_system_event"}
        for filename, rules in expected.items():
            result = replay_file(Path("fixtures") / filename, sources[filename])
            self.assertTrue(rules.issubset({alert.rule_id for alert in result.alerts}), filename)


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from datetime import datetime, timezone

from sentinelforge.alerts import create_alert
from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.provenance import (
    canonical_rule_definition, canonical_rule_configuration,
    configured_rule_fingerprint,
    engine_configuration_fingerprint, rule_fingerprint,
)
from sentinelforge.detection.registry import DEFAULT_RULE_REGISTRY, RuleRegistry
from sentinelforge.detection.rules import RuleConfig
from sentinelforge.events import SecurityEvent
from sentinelforge.investigation_package import build_package
from sentinelforge.replay import replay_events, replay_file
from sentinelforge.storage import AnalysisRepository, Database


class ProvenanceTests(unittest.TestCase):
    def test_fingerprints_are_deterministic_and_metadata_independent(self):
        definition = DEFAULT_RULE_REGISTRY.get("REPEATED_AUTH_FAILURE")
        config = RuleConfig()
        self.assertEqual(rule_fingerprint(definition, config), rule_fingerprint(definition, config))
        renamed = replace(definition, name="Documentation-only name", description="Documentation-only description")
        self.assertEqual(rule_fingerprint(definition, config), rule_fingerprint(renamed, config))
        self.assertEqual(canonical_rule_definition(definition)["rule_id"], definition.rule_id)
        self.assertFalse(hasattr(__import__("sentinelforge.detection.provenance", fromlist=["configuration_fingerprint"]), "configuration_fingerprint"))

    def test_aliases_are_normalized_to_selected_effective_values(self):
        cases = (
            ("SOURCE_QUERIES_MANY_DOMAINS", RuleConfig(dns_many_domains_threshold=7, dns_many_queries_threshold=99),
             RuleConfig(dns_many_domains_threshold=7, dns_many_queries_threshold=100),
             RuleConfig(dns_many_domains_threshold=8, dns_many_queries_threshold=99)),
            ("PARENT_PROCESS_SPAWNS_MANY_CHILDREN", RuleConfig(process_parent_child_threshold=7, parent_process_children_threshold=99),
             RuleConfig(process_parent_child_threshold=7, parent_process_children_threshold=100),
             RuleConfig(process_parent_child_threshold=8, parent_process_children_threshold=99)),
            ("USER_EXECUTES_MANY_DISTINCT_PROCESSES", RuleConfig(user_process_threshold=7, user_process_names_threshold=99),
             RuleConfig(user_process_threshold=7, user_process_names_threshold=100),
             RuleConfig(user_process_threshold=8, user_process_names_threshold=99)),
        )
        for rule_id, base, inactive_change, active_change in cases:
            definition = DEFAULT_RULE_REGISTRY.get(rule_id)
            self.assertEqual(canonical_rule_configuration(definition, base), canonical_rule_configuration(definition, inactive_change))
            self.assertEqual(rule_fingerprint(definition, base), rule_fingerprint(definition, inactive_change))
            self.assertNotEqual(rule_fingerprint(definition, base), rule_fingerprint(definition, active_change))

    def test_enabled_is_configured_identity_only(self):
        definition = DEFAULT_RULE_REGISTRY.get("REPEATED_AUTH_FAILURE")
        disabled = replace(definition, enabled=False)
        self.assertEqual(rule_fingerprint(definition, RuleConfig()), rule_fingerprint(disabled, RuleConfig()))
        self.assertNotEqual(configured_rule_fingerprint(definition, RuleConfig()), configured_rule_fingerprint(disabled, RuleConfig()))
        self.assertNotIn("enabled", canonical_rule_definition(definition))

    def test_relevant_definition_and_configuration_changes_change_identity(self):
        definition = DEFAULT_RULE_REGISTRY.get("REPEATED_AUTH_FAILURE")
        self.assertNotEqual(rule_fingerprint(definition, RuleConfig()), rule_fingerprint(definition, RuleConfig(repeated_failure_threshold=4)))
        self.assertNotEqual(rule_fingerprint(definition, RuleConfig()), rule_fingerprint(definition, RuleConfig(repeated_failure_window_seconds=121)))
        self.assertNotEqual(rule_fingerprint(definition, RuleConfig()), rule_fingerprint(replace(definition, severity="high"), RuleConfig()))

    def test_registry_presentation_metadata_is_irrelevant_but_authoritative_state_changes(self):
        base = DEFAULT_RULE_REGISTRY
        renamed = RuleRegistry(replace(item, name=item.name + " docs", description=item.description + " docs") for item in base.all())
        self.assertEqual(engine_configuration_fingerprint(RuleConfig(), base), engine_configuration_fingerprint(RuleConfig(), renamed))
        changed = RuleRegistry(replace(item, severity="high") if item.rule_id == "REPEATED_AUTH_FAILURE" else item for item in base.all())
        self.assertNotEqual(engine_configuration_fingerprint(RuleConfig(), base), engine_configuration_fingerprint(RuleConfig(), changed))
        disabled = RuleRegistry(replace(item, enabled=False) if item.rule_id == "REPEATED_AUTH_FAILURE" else item for item in base.all())
        self.assertNotEqual(engine_configuration_fingerprint(RuleConfig(), base), engine_configuration_fingerprint(RuleConfig(), disabled))

    def test_replay_exposes_rule_and_configuration_fingerprints(self):
        payload = replay_file("fixtures/auth.log", "linux_auth").to_dict()
        self.assertTrue(payload["detection_configuration_fingerprint"])
        self.assertTrue(all(alert["rule_fingerprint"] for alert in payload["alerts"]))
        self.assertEqual(sorted({alert["rule_fingerprint"] for alert in payload["alerts"]}), payload["rule_fingerprints"])
        first = replay_events([], DetectionEngine())
        second = replay_events([], DetectionEngine())
        self.assertEqual(first.detection_configuration_fingerprint, second.detection_configuration_fingerprint)

    def test_storage_round_trip_and_legacy_payload(self):
        event = SecurityEvent(datetime(2025, 1, 1, tzinfo=timezone.utc), "linux-auth", "authentication_failure", None, None, "alice", None, "failed", "raw")
        alert = create_alert("RULE", "low", "t", "d", [event])
        alert = replace(alert, rule_fingerprint=rule_fingerprint(DEFAULT_RULE_REGISTRY.get("REPEATED_AUTH_FAILURE"), RuleConfig()))
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as handle:
            path = handle.name
        try:
            with Database(path) as db:
                repo = AnalysisRepository(db)
                repo.save_run("run", {"run_id": "run", "started_at": "2025-01-01T00:00:00Z"})
                repo.save_alert(alert, "run")
                self.assertEqual(repo.get_alert(alert.alert_id).rule_fingerprint, alert.rule_fingerprint)
                legacy = {"alert_id": "legacy", "rule_id": "OLD", "severity": "low", "timestamp": "2025-01-01T00:00:00Z", "title": "t", "description": "d", "evidence": [{"timestamp": "2025-01-01T00:00:00Z", "source": "x", "event_type": "x", "message": "x", "raw": "x"}]}
                db.connection.execute("INSERT INTO alerts(alert_id, timestamp, payload) VALUES (?, ?, ?)", ("legacy", legacy["timestamp"], json.dumps(legacy)))
                self.assertIsNone(repo.get_alert("legacy").rule_fingerprint)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_alert_and_package_ids_do_not_use_fingerprint(self):
        event = SecurityEvent(datetime(2025, 1, 1, tzinfo=timezone.utc), "x", "x", None, None, None, None, "m", "raw")
        first = create_alert("RULE", "low", "t", "d", [event])
        second = replace(first, rule_fingerprint="different")
        self.assertEqual(first.alert_id, second.alert_id)
        self.assertEqual(build_package([first]).package_id, build_package([second]).package_id)


if __name__ == "__main__":
    unittest.main()

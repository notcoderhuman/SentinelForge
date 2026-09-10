import unittest
from datetime import datetime, timezone

from sentinelforge.alerts import create_alert
from sentinelforge.attack import TechniqueMapping, mappings_for_rule, mappings_for_rules
from sentinelforge.events import SecurityEvent
from sentinelforge.incident_engine import derive_incidents
from sentinelforge.investigation_engine import create_investigation


class AttackMappingTests(unittest.TestCase):
    def setUp(self):
        event = SecurityEvent(
            datetime(2025, 1, 1, tzinfo=timezone.utc), "linux-auth",
            "authentication_failure", "host", "sshd", "alice", "192.0.2.1",
            "Failed", "raw",
        )
        self.alert = create_alert("SSH_BRUTE_FORCE", "high", "Title", "Description", [event])

    def test_mapping_validation_and_determinism(self):
        mapping = mappings_for_rule("SSH_BRUTE_FORCE")[0]
        self.assertEqual(mapping.technique_id, "T1110")
        self.assertEqual(mapping, mappings_for_rules(("SSH_BRUTE_FORCE",))[0])
        with self.assertRaises(ValueError):
            TechniqueMapping("not-a-technique", "Name", "Tactic", "Reason", "RULE")
        with self.assertRaises(ValueError):
            TechniqueMapping("T1110", "", "Tactic", "Reason", "RULE")

    def test_unknown_rules_are_unmapped(self):
        self.assertEqual(mappings_for_rule("UNKNOWN_RULE"), ())
        unknown_alert = create_alert("UNKNOWN_RULE", "low", "Title", "Description", self.alert.evidence)
        self.assertEqual(unknown_alert.attack_mappings, ())

    def test_alert_incident_and_investigation_expose_derived_mapping(self):
        self.assertEqual([mapping.technique_id for mapping in self.alert.attack_mappings], ["T1110"])
        incident = derive_incidents([self.alert])[0]
        investigation = create_investigation(incident)
        self.assertEqual([mapping.technique_id for mapping in incident.attack_mappings], ["T1110"])
        self.assertEqual([mapping.technique_id for mapping in investigation.attack_mappings], ["T1110"])
        self.assertEqual(incident.to_dict()["attack_mappings"][0]["source_rule_id"], "SSH_BRUTE_FORCE")

    def test_mapping_order_is_deterministic(self):
        mappings = mappings_for_rules(("UNKNOWN_RULE", "SSH_BRUTE_FORCE", "SSH_BRUTE_FORCE"))
        self.assertEqual([mapping.technique_id for mapping in mappings], ["T1110"])

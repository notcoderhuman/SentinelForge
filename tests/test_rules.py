import unittest

from sentinelforge.detection.registry import DEFAULT_RULE_REGISTRY, RuleRegistry
from sentinelforge.detection.rule import RuleDefinition


class RuleTests(unittest.TestCase):
    def test_rule_validation(self):
        rule = RuleDefinition("RULE", "Name", "Description", "low", 10, True, ("event",))
        self.assertEqual(rule.rule_id, "RULE")
        with self.assertRaises(ValueError):
            RuleDefinition("", "Name", "Description", "low", 10, True, ("event",))
        with self.assertRaises(ValueError):
            RuleDefinition("RULE", "Name", "Description", "low", 0, True, ("event",))
        with self.assertRaises(ValueError):
            RuleDefinition("RULE", "Name", "Description", "low", 10, True, ())

    def test_registry_duplicate_lookup_order_and_unknown(self):
        with self.assertRaises(ValueError):
            RuleRegistry((RuleDefinition("RULE", "A", "A", "low", 1, True, ("e",)),
                          RuleDefinition("RULE", "B", "B", "low", 1, True, ("e",))))
        self.assertEqual(DEFAULT_RULE_REGISTRY.get("SSH_BRUTE_FORCE").severity, "high")
        self.assertEqual([rule.rule_id for rule in DEFAULT_RULE_REGISTRY.all()], sorted(rule.rule_id for rule in DEFAULT_RULE_REGISTRY.all()))
        with self.assertRaises(KeyError):
            DEFAULT_RULE_REGISTRY.get("UNKNOWN")

    def test_existing_rule_metadata(self):
        brute_force = DEFAULT_RULE_REGISTRY.get("SSH_BRUTE_FORCE")
        self.assertEqual(brute_force.detection_window_seconds, 120)
        self.assertEqual(brute_force.evidence_requirements[0].split()[0], "five")
        self.assertEqual(brute_force.attack_mapping_reference, ("T1110",))

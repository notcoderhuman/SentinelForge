import unittest
from datetime import datetime, timedelta, timezone

from sentinelforge.alerts import create_alert
from sentinelforge.events import SecurityEvent
from sentinelforge.incident_engine import derive_incidents
from sentinelforge.incidents import Incident, create_incident


class IncidentTests(unittest.TestCase):
    def setUp(self):
        timestamp = datetime(2025, 1, 1, tzinfo=timezone.utc)
        self.alice_event = SecurityEvent(
            timestamp, "linux-auth", "authentication_failure", "host", "sshd",
            "alice", "192.0.2.1", "Failed", "raw-alice",
        )
        self.bob_event = SecurityEvent(
            timestamp + timedelta(seconds=1), "linux-auth", "sudo_activity", "host", "sudo",
            "bob", None, "sudo", "raw-bob",
        )

    def test_incident_validation_and_serialization(self):
        alert = create_alert("RULE", "medium", "Title", "Description", [self.alice_event])
        incident = create_incident([alert], frozenset({"username:alice", "source_ip:192.0.2.1"}))
        serialized = incident.to_dict()
        self.assertEqual(incident.status, "open")
        self.assertEqual(serialized["related_alert_ids"], [alert.alert_id])
        self.assertEqual(serialized["affected_users"], ["alice"])
        self.assertEqual(serialized["evidence"][0]["raw"], "raw-alice")
        with self.assertRaises(ValueError):
            Incident("id", "title", "description", "medium", "invalid", self.alice_event.timestamp,
                     self.alice_event.timestamp, (alert.alert_id,), ("alice",), (), (self.alice_event,))

    def test_deterministic_ids_and_grouping(self):
        first_alert = create_alert("RULE_A", "medium", "A", "A", [self.alice_event])
        related_alert = create_alert("RULE_B", "low", "B", "B", [self.alice_event])
        unrelated_alert = create_alert("RULE_C", "low", "C", "C", [self.bob_event])
        first = derive_incidents([unrelated_alert, related_alert, first_alert])
        second = derive_incidents([first_alert, unrelated_alert, related_alert])
        self.assertEqual([incident.incident_id for incident in first],
                         [incident.incident_id for incident in second])
        self.assertEqual(len(first), 2)
        grouped = next(incident for incident in first if first_alert.alert_id in incident.related_alert_ids)
        self.assertEqual(set(grouped.related_alert_ids), {first_alert.alert_id, related_alert.alert_id})
        self.assertEqual(grouped.affected_users, ("alice",))
        self.assertEqual(len(grouped.evidence), 1)

    def test_valid_lifecycle_transitions(self):
        alert = create_alert("RULE", "medium", "Title", "Description", [self.alice_event])
        incident = create_incident([alert], frozenset({"username:alice"}))
        investigating = incident.transition_to("investigating", incident.updated_at + timedelta(seconds=1))
        resolved = investigating.transition_to("resolved", investigating.updated_at + timedelta(seconds=1))
        closed = resolved.transition_to("closed", resolved.updated_at + timedelta(seconds=1))
        self.assertEqual(closed.status, "closed")

    def test_invalid_lifecycle_transitions_rejected(self):
        alert = create_alert("RULE", "medium", "Title", "Description", [self.alice_event])
        incident = create_incident([alert], frozenset({"username:alice"}))
        with self.assertRaises(ValueError):
            incident.transition_to("closed")
        resolved = incident.transition_to("resolved")
        with self.assertRaises(ValueError):
            resolved.transition_to("investigating")
        with self.assertRaises(ValueError):
            resolved.transition_to("open")

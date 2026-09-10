import unittest
from datetime import datetime, timedelta, timezone

from sentinelforge.alerts import create_alert
from sentinelforge.events import SecurityEvent
from sentinelforge.incident_engine import derive_incidents
from sentinelforge.investigation_engine import create_investigation, create_note
from sentinelforge.investigations import AnalystNote, Investigation


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        first_timestamp = datetime(2025, 1, 1, tzinfo=timezone.utc)
        self.first_event = SecurityEvent(
            first_timestamp, "linux-auth", "authentication_failure", "host", "sshd",
            "alice", "192.0.2.1", "Failed first", "raw-first",
        )
        self.second_event = SecurityEvent(
            first_timestamp + timedelta(seconds=10), "linux-auth", "authentication_failure", "host", "sshd",
            "alice", "192.0.2.1", "Failed second", "raw-second",
        )
        alert = create_alert("RULE", "medium", "Title", "Description",
                             [self.first_event, self.second_event])
        self.incident = derive_incidents([alert])[0]

    def test_evidence_is_traceable_and_ids_are_deterministic(self):
        first = create_investigation(self.incident)
        second = create_investigation(self.incident)
        self.assertEqual(first.investigation_id, second.investigation_id)
        self.assertEqual([item.evidence_id for item in first.evidence],
                         [item.evidence_id for item in second.evidence])
        self.assertTrue(all(item.provenance == f"incident:{self.incident.incident_id}"
                            for item in first.evidence))
        self.assertEqual([item.event.raw for item in first.evidence], ["raw-first", "raw-second"])

    def test_investigation_validation_rejects_invalid_data(self):
        investigation = create_investigation(self.incident)
        with self.assertRaises(ValueError):
            Investigation(investigation.investigation_id, "", "active",
                          investigation.created_at, investigation.updated_at,
                          investigation.evidence, investigation.timeline, ())
        with self.assertRaises(ValueError):
            Investigation(investigation.investigation_id, investigation.incident_id, "unknown",
                          investigation.created_at, investigation.updated_at,
                          investigation.evidence, investigation.timeline, ())
        with self.assertRaises(ValueError):
            AnalystNote("note", datetime(2025, 1, 1), "analyst", "content")

    def test_duplicate_events_are_removed_and_timeline_is_chronological(self):
        duplicate_alert = create_alert("RULE_DUP", "low", "Duplicate", "Duplicate",
                                       [self.first_event, self.first_event])
        incident = derive_incidents([duplicate_alert])[0]
        investigation = create_investigation(incident)
        self.assertEqual(len(investigation.evidence), 1)
        timestamps = [entry.timestamp for entry in investigation.timeline]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_analyst_notes_are_inert_and_deterministically_ordered(self):
        investigation = create_investigation(self.incident)
        first_note = create_note("note-1", investigation.created_at, "analyst", "Observed activity")
        second_note = create_note("note-2", investigation.updated_at, "analyst", "Needs review")
        updated = Investigation(
            investigation.investigation_id, investigation.incident_id, investigation.status,
            investigation.created_at, investigation.updated_at,
            investigation.evidence, investigation.timeline, (first_note, second_note),
        )
        self.assertEqual([note.note_id for note in updated.analyst_notes], ["note-1", "note-2"])
        self.assertEqual(updated.to_dict()["analyst_notes"][0]["content"], "Observed activity")

import unittest
from pathlib import Path

from sentinelforge.ingestion.pipeline import ingest_file
from sentinelforge.parsers.windows_security import parse_event, parse_file


FIXTURE = Path("fixtures/windows-security.xml")


class WindowsSecurityParserTests(unittest.TestCase):
    def test_supported_events_and_fields(self):
        events, diagnostics = parse_file(str(FIXTURE))
        self.assertFalse(diagnostics)
        self.assertEqual([event.event_id for event in events], ["4624", "4625", "4672"])
        self.assertEqual([event.event_type for event in events], ["authentication_success", "authentication_failure", "privileged_logon"])
        self.assertEqual(events[0].username, "demo-alice")
        self.assertEqual(events[0].source_ip, "192.0.2.40")
        self.assertEqual(events[0].hostname, "WIN-DEMO-01")
        self.assertEqual(events[0].timestamp.isoformat(), "2025-01-03T00:00:00+00:00")
        self.assertIn("<Event", events[0].raw)

    def test_malformed_unsupported_and_missing_fields(self):
        event, diagnostic = parse_event("<Event>")
        self.assertIsNone(event)
        self.assertIn("malformed", diagnostic.reason)
        unsupported = "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>9999</EventID></System></Event>"
        event, diagnostic = parse_event(unsupported)
        self.assertIsNone(event)
        self.assertIn("unsupported", diagnostic.reason)
        missing_user = "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>4624</EventID><TimeCreated SystemTime=\"2025-01-03T00:00:00Z\"/><Computer>WIN</Computer></System><EventData /></Event>"
        event, diagnostic = parse_event(missing_user)
        self.assertIsNone(event)
        self.assertIn("username", diagnostic.reason)

    def test_deterministic_ingestion(self):
        first = ingest_file(FIXTURE, source="windows_security")
        second = ingest_file(FIXTURE, source="windows_security")
        self.assertEqual([event.to_dict() for event in first.events], [event.to_dict() for event in second.events])
        self.assertEqual([diagnostic.to_dict() for diagnostic in first.diagnostics], [diagnostic.to_dict() for diagnostic in second.diagnostics])

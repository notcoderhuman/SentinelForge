import unittest

from sentinelforge.parsers.linux_auth import parse_lines


class LinuxAuthParserTests(unittest.TestCase):
    def test_supported_events(self):
        lines = [
            "2025-01-01T00:00:00Z host sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2",
            "2025-01-01T00:00:01Z host sshd[2]: Accepted password for alice from 192.0.2.1 port 22 ssh2",
            "2025-01-01T00:00:02Z host sshd[3]: Invalid user admin from 192.0.2.2 port 22",
            "2025-01-01T00:00:03Z host sudo[4]: user=alice command=/usr/bin/id",
        ]
        events, diagnostics = parse_lines(lines)
        self.assertEqual([event.event_type for event in events], ["authentication_failure", "authentication_success", "authentication_failure", "sudo_activity"])
        self.assertEqual(events[0].source_ip, "192.0.2.1")
        self.assertEqual(events[2].username, "admin")
        self.assertFalse(diagnostics)

    def test_malformed_and_unsupported_are_diagnostics(self):
        lines = ["not a log line", "2025-01-01T00:00:00Z host sshd[1]: Connection closed"]
        events, diagnostics = parse_lines(lines)
        self.assertFalse(events)
        self.assertEqual(len(diagnostics), 2)
        self.assertEqual(diagnostics[0].line_number, 1)

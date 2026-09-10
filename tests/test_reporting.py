import json
import unittest
from contextlib import redirect_stdout
from io import StringIO

from sentinelforge.__main__ import main
from sentinelforge.reporting import analyze_file, render_human_report


class ReportingTests(unittest.TestCase):
    def test_analyze_json_is_deterministic(self):
        first = analyze_file("fixtures/auth.log")
        second = analyze_file("fixtures/auth.log")
        self.assertEqual(first, second)
        self.assertIn("alerts", first)
        self.assertIn("incidents", first)
        self.assertIn("investigations", first)

    def test_human_report_contains_summary_fields(self):
        report = analyze_file("fixtures/auth.log")
        rendered = render_human_report(report)
        self.assertIn("SentinelForge analysis", rendered)
        self.assertIn("Events:", rendered)
        self.assertIn("Risk:", rendered)
        self.assertIn("Incidents:", rendered)

    def test_filters_and_empty_results(self):
        high = analyze_file("fixtures/auth.log", severity="high")
        self.assertTrue(all(alert["severity"] == "high" for alert in high["alerts"]))
        empty = analyze_file("fixtures/auth.log", severity="critical")
        self.assertEqual(empty["alerts"], [])
        self.assertEqual(empty["incidents"], [])
        self.assertEqual(empty["investigations"], [])
        incident_id = analyze_file("fixtures/auth.log")["incidents"][0]["incident_id"]
        selected = analyze_file("fixtures/auth.log", incident_id=incident_id)
        self.assertEqual([item["incident_id"] for item in selected["incidents"]], [incident_id])

    def test_cli_json_and_exit_codes(self):
        output = StringIO()
        with redirect_stdout(output):
            exit_code = main(["analyze", "fixtures/auth.log", "--json"])
        self.assertEqual(exit_code, 0)
        self.assertIn("incidents", json.loads(output.getvalue()))
        with self.assertRaises(SystemExit):
            main(["analyze", "fixtures/auth.log", "--severity", "invalid"])

    def test_existing_commands_remain_available(self):
        expected_keys = {
            "parse": "events",
            "detect": "alerts",
            "incident": "incidents",
            "investigate": "investigations",
            "observables": "observables",
        }
        for command, key in expected_keys.items():
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main([command, "fixtures/auth.log"])
            self.assertEqual(exit_code, 0)
            self.assertIn(key, json.loads(output.getvalue()))

    def test_missing_file_is_fatal(self):
        with self.assertRaises(FileNotFoundError):
            main(["analyze", "missing-fixture.log"])

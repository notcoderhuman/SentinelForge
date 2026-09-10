import unittest
from datetime import datetime, timedelta, timezone

from sentinelforge.alerts import create_alert
from sentinelforge.correlation_engine import correlate_alerts
from sentinelforge.events import SecurityEvent
from sentinelforge.incident_engine import derive_incidents
from sentinelforge.investigation_engine import create_investigation
from sentinelforge.risk import RiskAssessment
from sentinelforge.risk_engine import assess_risk


class CorrelationRiskTests(unittest.TestCase):
    def setUp(self):
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        self.failure = SecurityEvent(start, "linux-auth", "authentication_failure", "host", "sshd", "alice", "192.0.2.1", "Failed", "failure")
        self.success = SecurityEvent(start + timedelta(seconds=30), "linux-auth", "authentication_success", "host", "sshd", "alice", "192.0.2.1", "Accepted", "success")
        self.sudo = SecurityEvent(start + timedelta(seconds=60), "linux-auth", "sudo_activity", "host", "sudo", "alice", None, "sudo", "sudo")

    def test_supported_sequences_and_determinism(self):
        failure_alert = create_alert("REPEATED_AUTH_FAILURE", "medium", "Failure", "Failure", [self.failure])
        success_alert = create_alert("SUCCESS_AFTER_FAILURES", "medium", "Success", "Success", [self.success])
        sudo_alert = create_alert("SUSPICIOUS_SUDO_ACTIVITY", "low", "Sudo", "Sudo", [self.sudo])
        first = correlate_alerts([sudo_alert, success_alert, failure_alert])
        second = correlate_alerts([failure_alert, success_alert, sudo_alert])
        self.assertEqual([item.correlation_id for item in first], [item.correlation_id for item in second])
        self.assertEqual({item.name for item in first}, {"AUTHENTICATION_ESCALATION", "AUTHENTICATION_TO_PRIVILEGED_ACTIVITY"})

    def test_non_matching_user_and_window_do_not_correlate(self):
        other_user = SecurityEvent(self.success.timestamp, "linux-auth", "authentication_success", "host", "sshd", "bob", "192.0.2.2", "Accepted", "other")
        late_sudo = SecurityEvent(self.success.timestamp + timedelta(seconds=301), "linux-auth", "sudo_activity", "host", "sudo", "alice", None, "sudo", "late")
        alerts = [create_alert("RULE_A", "medium", "A", "A", [self.failure]), create_alert("RULE_B", "medium", "B", "B", [other_user]), create_alert("RULE_C", "low", "C", "C", [late_sudo])]
        self.assertEqual(correlate_alerts(alerts), [])

    def test_risk_factors_bounds_and_determinism(self):
        brute_force = create_alert("SSH_BRUTE_FORCE", "high", "Brute", "Brute", [self.failure])
        correlations = correlate_alerts([brute_force])
        first = assess_risk([brute_force], correlations)
        second = assess_risk([brute_force], correlations)
        self.assertEqual(first, second)
        self.assertGreaterEqual(first.score, 0)
        self.assertLessEqual(first.score, 100)
        self.assertIn("highest alert severity", first.factors[0])
        with self.assertRaises(ValueError):
            RiskAssessment(101, "critical", ("factor",), "explanation")

    def test_incident_and_investigation_propagate_derived_data(self):
        alerts = [
            create_alert("REPEATED_AUTH_FAILURE", "medium", "Failure", "Failure", [self.failure]),
            create_alert("SUCCESS_AFTER_FAILURES", "medium", "Success", "Success", [self.success]),
        ]
        incident = derive_incidents(alerts)[0]
        investigation = create_investigation(incident)
        self.assertTrue(incident.correlations)
        self.assertIsNotNone(incident.risk_assessment)
        self.assertEqual(investigation.correlations, incident.correlations)
        self.assertEqual(investigation.risk_assessment, incident.risk_assessment)

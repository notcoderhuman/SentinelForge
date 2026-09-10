"""Readable, deterministic detections over normalized events."""

from __future__ import annotations

from datetime import timedelta
from typing import Callable, Dict, List, Sequence

from ..alerts import Alert, create_alert
from ..events import SecurityEvent
from .registry import DEFAULT_RULE_REGISTRY, RuleRegistry
from .rules import RuleConfig


class DetectionEngine:
    """Evaluate configured rules without changing or enriching source events."""

    def __init__(self, config: RuleConfig | None = None,
                 registry: RuleRegistry | None = None) -> None:
        self.config = config or RuleConfig()
        self.registry = registry or DEFAULT_RULE_REGISTRY

    def detect(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        """Return stable alerts for the supplied events in deterministic order."""
        ordered_events = sorted(events, key=lambda event: (event.timestamp, event.raw))
        alerts: List[Alert] = []
        alerts.extend(self._ssh_brute_force(ordered_events))
        alerts.extend(self._repeated_failures(ordered_events))
        alerts.extend(self._success_after_failures(ordered_events))
        alerts.extend(self._sudo_activity(ordered_events))
        alerts.extend(self._source_targets_multiple_accounts(ordered_events))
        alerts.extend(self._account_targeted_by_multiple_sources(ordered_events))
        alerts.extend(self._windows_privileged_logons(ordered_events))
        return sorted(alerts, key=lambda alert: (alert.timestamp, alert.rule_id, alert.alert_id))

    @staticmethod
    def _failures(events: Sequence[SecurityEvent]) -> List[SecurityEvent]:
        return [event for event in events if event.event_type == "authentication_failure"]

    def _ssh_brute_force(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        failures_by_ip: Dict[str, List[SecurityEvent]] = {}
        for event in self._failures(events):
            if event.process == "sshd" and event.source_ip:
                failures_by_ip.setdefault(event.source_ip, []).append(event)
        alerts: List[Alert] = []
        window = timedelta(seconds=self.config.ssh_brute_force_window_seconds)
        for source_ip, failures in sorted(failures_by_ip.items()):
            for end_index in range(self.config.ssh_brute_force_threshold - 1, len(failures)):
                matching = failures[end_index - self.config.ssh_brute_force_threshold + 1:end_index + 1]
                if matching[-1].timestamp - matching[0].timestamp <= window:
                    alerts.append(create_alert(
                        "SSH_BRUTE_FORCE", self.registry.get("SSH_BRUTE_FORCE").severity, "Possible SSH brute-force activity detected.",
                        f"Observed {len(matching)} failed SSH authentications from {source_ip} within the configured window.", matching))
                    break
        return alerts

    def _repeated_failures(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        failures_by_user: Dict[str, List[SecurityEvent]] = {}
        for event in self._failures(events):
            if event.username:
                failures_by_user.setdefault(event.username, []).append(event)
        alerts: List[Alert] = []
        window = timedelta(seconds=self.config.repeated_failure_window_seconds)
        for username, failures in sorted(failures_by_user.items()):
            for end_index in range(self.config.repeated_failure_threshold - 1, len(failures)):
                matching = failures[end_index - self.config.repeated_failure_threshold + 1:end_index + 1]
                if matching[-1].timestamp - matching[0].timestamp <= window:
                    alerts.append(create_alert(
                        "REPEATED_AUTH_FAILURE", self.registry.get("REPEATED_AUTH_FAILURE").severity, "Repeated authentication failures observed.",
                        f"Observed repeated failures for account {username}; the evidence does not establish account compromise.", matching))
                    break
        return alerts

    def _success_after_failures(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        alerts: List[Alert] = []
        window = timedelta(seconds=self.config.success_after_failure_window_seconds)
        for success in events:
            if success.event_type != "authentication_success" or not success.username:
                continue
            failures = [event for event in events if event.event_type == "authentication_failure"
                        and event.username == success.username
                        and event.timestamp <= success.timestamp
                        and success.timestamp - event.timestamp <= window]
            if failures:
                evidence = failures + [success]
                alerts.append(create_alert(
                    "SUCCESS_AFTER_FAILURES", self.registry.get("SUCCESS_AFTER_FAILURES").severity, "Successful authentication followed repeated failures.",
                    "A successful login followed earlier authentication failures; this pattern alone does not establish compromise.", evidence))
        return alerts

    def _sudo_activity(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        if not self.config.sudo_enabled:
            return []
        return [create_alert("SUSPICIOUS_SUDO_ACTIVITY", self.registry.get("SUSPICIOUS_SUDO_ACTIVITY").severity,
                             "Sudo activity observed for privileged command execution.",
                             "A sudo command was recorded. The command is not automatically considered malicious.", [event])
                for event in events if event.event_type == "sudo_activity"]

    def _source_targets_multiple_accounts(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        failures_by_ip: Dict[str, List[SecurityEvent]] = {}
        for event in self._failures(events):
            if event.source_ip and event.username:
                failures_by_ip.setdefault(event.source_ip, []).append(event)
        return self._distinct_entity_alerts(
            failures_by_ip,
            self.config.source_targeting_accounts_threshold,
            self.config.source_targeting_accounts_window_seconds,
            "SOURCE_TARGETS_MULTIPLE_ACCOUNTS",
            "One source IP targeted multiple accounts.",
            "Observed authentication failures for multiple accounts from source IP {entity} within the configured window.",
            lambda event: event.username,
        )

    def _account_targeted_by_multiple_sources(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        failures_by_user: Dict[str, List[SecurityEvent]] = {}
        for event in self._failures(events):
            if event.username and event.source_ip:
                failures_by_user.setdefault(event.username, []).append(event)
        return self._distinct_entity_alerts(
            failures_by_user,
            self.config.account_targeted_by_sources_threshold,
            self.config.account_targeted_by_sources_window_seconds,
            "ACCOUNT_TARGETED_BY_MULTIPLE_SOURCES",
            "One account was targeted by multiple sources.",
            "Observed authentication failures for account {entity} from multiple source IPs within the configured window.",
            lambda event: event.source_ip,
        )

    def _windows_privileged_logons(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        definition = self.registry.get("WINDOWS_PRIVILEGED_LOGON")
        return [create_alert(
            "WINDOWS_PRIVILEGED_LOGON", definition.severity,
            "Windows privileged logon observed.",
            "A Windows 4672 event assigned special privileges to a new logon; this does not establish misuse.",
            [event],
        ) for event in events if event.source == "windows-security" and event.event_id == "4672"
              and event.event_type == "privileged_logon" and event.username]

    def _distinct_entity_alerts(self, grouped_events: Dict[str, List[SecurityEvent]], threshold: int,
                                window_seconds: int, rule_id: str, title: str, description: str,
                                entity_key: Callable[[SecurityEvent], str | None]) -> List[Alert]:
        alerts: List[Alert] = []
        window = timedelta(seconds=window_seconds)
        for entity, grouped in sorted(grouped_events.items()):
            for end_index in range(threshold - 1, len(grouped)):
                matching = grouped[end_index - threshold + 1:end_index + 1]
                if (matching[-1].timestamp - matching[0].timestamp <= window
                        and len({entity_key(event) for event in matching}) >= threshold):
                    alerts.append(create_alert(
                        rule_id, self.registry.get(rule_id).severity, title,
                        description.format(entity=entity), matching))
                    break
        return alerts

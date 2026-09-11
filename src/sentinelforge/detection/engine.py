"""Readable, deterministic detections over normalized events."""

from __future__ import annotations

from datetime import timedelta
import ipaddress
import re
from typing import Callable, Dict, List, Sequence

from ..alerts import Alert, create_alert
from ..events import SecurityEvent
from ..observable_engine import extract_observables
from ..threat_context import ThreatContext
from ..threat_context_engine import match_context
from .registry import DEFAULT_RULE_REGISTRY, RuleRegistry
from .rules import RuleConfig

_DESTINATION_PATTERN = re.compile(
    r"(?:destination(?:_ip)?|dest(?:ination)?|dst|remote(?:_ip)?|to)"
    r"\s*[=:]?\s*(?P<ip>[^\s,;]+)", re.IGNORECASE
)
_NETWORK_EVENT_TYPES = frozenset({"network_connection", "outbound_connection", "connection"})
_NETWORK_RULE_IDS = frozenset({
    "OUTBOUND_CONNECTION_TO_SUSPICIOUS_IP",
    "REPEATED_CONNECTION_TO_SAME_DESTINATION",
    "SOURCE_CONTACTS_MANY_DESTINATIONS",
    "DESTINATION_CONTACTED_BY_MANY_SOURCES",
})


class DetectionEngine:
    """Evaluate configured rules without changing or enriching source events."""

    def __init__(self, config: RuleConfig | None = None,
                 registry: RuleRegistry | None = None) -> None:
        self.config = config or RuleConfig()
        self.registry = registry or DEFAULT_RULE_REGISTRY

    def detect(self, events: Sequence[SecurityEvent],
               threat_context: Sequence[ThreatContext] = ()) -> List[Alert]:
        """Return stable alerts for the supplied events in deterministic order."""
        ordered_events = sorted(events, key=lambda event: (event.timestamp, event.raw))
        alerts: List[Alert] = []
        if self.registry.get("OUTBOUND_CONNECTION_TO_SUSPICIOUS_IP").enabled:
            alerts.extend(self._outbound_to_suspicious_ip(ordered_events, threat_context))
        if self.registry.get("REPEATED_CONNECTION_TO_SAME_DESTINATION").enabled:
            alerts.extend(self._repeated_connection(ordered_events))
        if self.registry.get("SOURCE_CONTACTS_MANY_DESTINATIONS").enabled:
            alerts.extend(self._source_contacts_many_destinations(ordered_events))
        if self.registry.get("DESTINATION_CONTACTED_BY_MANY_SOURCES").enabled:
            alerts.extend(self._destination_contacted_by_many_sources(ordered_events))
        alerts.extend(self._ssh_brute_force(ordered_events))
        alerts.extend(self._repeated_failures(ordered_events))
        alerts.extend(self._success_after_failures(ordered_events))
        alerts.extend(self._sudo_activity(ordered_events))
        alerts.extend(self._source_targets_multiple_accounts(ordered_events))
        alerts.extend(self._account_targeted_by_multiple_sources(ordered_events))
        alerts.extend(self._windows_privileged_logons(ordered_events))
        if self.registry.get("PRIVILEGED_PROCESS_EXECUTION").enabled and self.config.privileged_process_enabled:
            alerts.extend(self._privileged_process_execution(ordered_events))
        if self.registry.get("REPEATED_PROCESS_EXECUTION").enabled:
            alerts.extend(self._repeated_process_execution(ordered_events))
        if self.registry.get("PARENT_PROCESS_SPAWNS_MANY_CHILDREN").enabled:
            alerts.extend(self._parent_process_spawns_many_children(ordered_events))
        if self.registry.get("USER_EXECUTES_MANY_DISTINCT_PROCESSES").enabled:
            alerts.extend(self._user_runs_many_process_names(ordered_events))
        return sorted(alerts, key=lambda alert: (alert.timestamp, alert.rule_id, alert.alert_id))

    @staticmethod
    def _failures(events: Sequence[SecurityEvent]) -> List[SecurityEvent]:
        return [event for event in events if event.event_type == "authentication_failure"]

    @staticmethod
    def _destination(event: SecurityEvent) -> str | None:
        """Return the normalized destination, with legacy message fallback."""
        destination_ip = getattr(event, "destination_ip", None)
        if destination_ip:
            try:
                return str(ipaddress.ip_address(destination_ip))
            except ValueError:
                return destination_ip.lower()
        match = _DESTINATION_PATTERN.search(event.message)
        if not match:
            return None
        value = match.group("ip").rstrip(".,;)]}")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value.lower() if value else None

    @staticmethod
    def _network_events(events: Sequence[SecurityEvent]) -> List[SecurityEvent]:
        """Return observed connections regardless of direction.

        The relationship rules describe contacts, not outbound traffic, so they
        use every normalized network event. Missing or unknown direction is not
        inferred to mean outbound; only the dedicated outbound rule uses the
        explicit direction filter below.
        """
        return [event for event in events if event.event_type in _NETWORK_EVENT_TYPES]

    @classmethod
    def _outbound_network_events(cls, events: Sequence[SecurityEvent]) -> List[SecurityEvent]:
        """Return only explicitly outbound network events.

        Missing, blank, and unknown directions are intentionally excluded rather
        than treated as outbound by inference.
        """
        return [event for event in cls._network_events(events)
                if isinstance(event.direction, str)
                and event.direction.strip().lower() == "outbound"]

    def _outbound_to_suspicious_ip(self, events: Sequence[SecurityEvent],
                                   threat_context: Sequence[ThreatContext]) -> List[Alert]:
        context_by_key = {(context.observable_type, context.value): context for context in threat_context}
        alerts: List[Alert] = []
        definition = self.registry.get("OUTBOUND_CONNECTION_TO_SUSPICIOUS_IP")
        for event in self._outbound_network_events(events):
            destination = self._destination(event)
            if destination is None:
                continue
            try:
                address_type = "ipv4" if ipaddress.ip_address(destination).version == 4 else "ipv6"
            except ValueError:
                continue
            destination_context = match_context(extract_observables([event]), threat_context)
            if any(context.context_type in {"suspicious", "known_malicious"}
                   and context_by_key.get((address_type, destination)) == context
                   for context in destination_context):
                alerts.append(create_alert(
                    definition.rule_id, definition.severity,
                    definition.name + " observed.",
                    f"An outbound connection was observed to suspicious destination {destination}; local context is not proof of malicious activity.",
                    [event],
                ))
        return alerts

    def _repeated_connection(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        grouped: Dict[tuple[str, str], List[SecurityEvent]] = {}
        for event in self._network_events(events):
            destination = self._destination(event)
            if event.source_ip and destination:
                grouped.setdefault((event.source_ip, destination), []).append(event)
        return self._network_threshold_alerts(
            grouped, self.config.repeated_connection_threshold,
            self.config.repeated_connection_window_seconds,
            "REPEATED_CONNECTION_TO_SAME_DESTINATION",
            "Repeated connection to the same destination.",
            "Observed repeated network connections from source {source} to destination {destination} within the configured window.",
        )

    def _source_contacts_many_destinations(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        grouped: Dict[str, List[SecurityEvent]] = {}
        for event in self._network_events(events):
            destination = self._destination(event)
            if event.source_ip and destination:
                grouped.setdefault(event.source_ip, []).append(event)
        return self._network_distinct_alerts(
            grouped, self.config.source_many_destinations_threshold,
            self.config.source_many_destinations_window_seconds,
            "SOURCE_CONTACTS_MANY_DESTINATIONS", "Source contacts many destinations.",
            "Observed one source {entity} contacting multiple destinations within the configured window.",
            self._destination,
        )

    def _destination_contacted_by_many_sources(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        grouped: Dict[str, List[SecurityEvent]] = {}
        for event in self._network_events(events):
            destination = self._destination(event)
            if destination and event.source_ip:
                grouped.setdefault(destination, []).append(event)
        return self._network_distinct_alerts(
            grouped, self.config.destination_many_sources_threshold,
            self.config.destination_many_sources_window_seconds,
            "DESTINATION_CONTACTED_BY_MANY_SOURCES", "Destination contacted by many sources.",
            "Observed destination {entity} contacted by multiple sources within the configured window.",
            lambda event: event.source_ip,
        )

    def _network_threshold_alerts(self, grouped_events: Dict[object, List[SecurityEvent]], threshold: int,
                                  window_seconds: int, rule_id: str, title: str, description: str) -> List[Alert]:
        alerts: List[Alert] = []
        window = timedelta(seconds=window_seconds)
        for entity, grouped in sorted(grouped_events.items(), key=lambda item: str(item[0])):
            for end_index in range(threshold - 1, len(grouped)):
                matching = grouped[end_index - threshold + 1:end_index + 1]
                if matching[-1].timestamp - matching[0].timestamp <= window:
                    if isinstance(entity, tuple):
                        format_values = {"source": entity[0], "destination": entity[1]}
                    else:
                        format_values = {"entity": entity}
                    alerts.append(create_alert(
                        rule_id, self.registry.get(rule_id).severity, title,
                        description.format(**format_values), matching,
                    ))
                    break
        return alerts

    def _network_distinct_alerts(self, grouped_events: Dict[str, List[SecurityEvent]], threshold: int,
                                 window_seconds: int, rule_id: str, title: str, description: str,
                                 entity_key: Callable[[SecurityEvent], str | None]) -> List[Alert]:
        alerts: List[Alert] = []
        window = timedelta(seconds=window_seconds)
        for entity, grouped in sorted(grouped_events.items()):
            for end_index in range(threshold - 1, len(grouped)):
                matching = grouped[end_index - threshold + 1:end_index + 1]
                if matching[-1].timestamp - matching[0].timestamp <= window and len({entity_key(event) for event in matching}) >= threshold:
                    alerts.append(create_alert(rule_id, self.registry.get(rule_id).severity, title,
                                               description.format(entity=entity), matching))
                    break
        return alerts

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

    def _process_events(self, events: Sequence[SecurityEvent]) -> List[SecurityEvent]:
        return [event for event in events if event.event_type == "process_execution"]

    def _privileged_process_execution(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        definition = self.registry.get("PRIVILEGED_PROCESS_EXECUTION")
        return [create_alert(
            definition.rule_id, definition.severity,
            "Privileged process execution observed.",
            "A process execution record explicitly declared a privileged execution context.",
            [event],
        ) for event in self._process_events(events)
            if isinstance(event.privilege, str) and event.privilege.strip().lower() in {
                "root", "admin", "privileged"
            }]

    def _repeated_process_execution(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        grouped: Dict[tuple[str, str], List[SecurityEvent]] = {}
        for event in self._process_events(events):
            source_identity = event.hostname
            process_identity = event.process_name or event.process
            if source_identity and process_identity:
                grouped.setdefault((source_identity, process_identity), []).append(event)
        return self._process_threshold_alerts(
            grouped, self.config.repeated_process_threshold,
            self.config.repeated_process_window_seconds,
            "REPEATED_PROCESS_EXECUTION", "Repeated process execution observed.",
            "Observed repeated executions of process {process} from source identity {source} within the configured window.",
        )

    def _parent_process_spawns_many_children(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        grouped: Dict[tuple[str, int], List[SecurityEvent]] = {}
        for event in self._process_events(events):
            if event.hostname and event.parent_process_id is not None and event.process_id is not None:
                grouped.setdefault((event.hostname, event.parent_process_id), []).append(event)
        return self._process_distinct_alerts(
            grouped, (self.config.process_parent_child_threshold
                      if self.config.process_parent_child_threshold is not None
                      else self.config.parent_process_children_threshold),
            self.config.parent_process_children_window_seconds,
            "PARENT_PROCESS_SPAWNS_MANY_CHILDREN", "Parent process spawned many children.",
            "Observed parent PID {parent} on host {host} associated with distinct child process IDs within the configured window.",
            lambda event: event.process_id,
        )

    def _user_runs_many_process_names(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        grouped: Dict[tuple[str, str], List[SecurityEvent]] = {}
        for event in self._process_events(events):
            process_name = event.process_name or event.process
            if event.hostname and event.username and process_name:
                grouped.setdefault((event.hostname, event.username), []).append(event)
        return self._process_distinct_alerts(
            grouped, (self.config.user_process_threshold
                      if self.config.user_process_threshold is not None
                      else self.config.user_process_names_threshold),
            self.config.user_process_names_window_seconds,
            "USER_EXECUTES_MANY_DISTINCT_PROCESSES", "User ran many process names.",
            "Observed user {user} on host {host} running distinct process names within the configured window.",
            lambda event: event.process_name or event.process,
        )

    def _process_threshold_alerts(self, grouped_events: Dict[tuple[str, str], List[SecurityEvent]],
                                  threshold: int, window_seconds: int, rule_id: str,
                                  title: str, description: str) -> List[Alert]:
        alerts: List[Alert] = []
        window = timedelta(seconds=window_seconds)
        for entity, grouped in sorted(grouped_events.items(), key=lambda item: str(item[0])):
            for end_index in range(threshold - 1, len(grouped)):
                matching = grouped[end_index - threshold + 1:end_index + 1]
                if matching[-1].timestamp - matching[0].timestamp <= window:
                    alerts.append(create_alert(rule_id, self.registry.get(rule_id).severity, title,
                                               description.format(source=entity[0], process=entity[1]), matching))
                    break
        return alerts

    def _process_distinct_alerts(self, grouped_events: Dict[tuple[str, object], List[SecurityEvent]],
                                 threshold: int, window_seconds: int, rule_id: str,
                                 title: str, description: str,
                                 entity_key: Callable[[SecurityEvent], object]) -> List[Alert]:
        alerts: List[Alert] = []
        window = timedelta(seconds=window_seconds)
        for entity, grouped in sorted(grouped_events.items(), key=lambda item: str(item[0])):
            for end_index in range(threshold - 1, len(grouped)):
                matching = grouped[end_index - threshold + 1:end_index + 1]
                if (matching[-1].timestamp - matching[0].timestamp <= window
                        and len({entity_key(event) for event in matching}) >= threshold):
                    if rule_id == "PARENT_PROCESS_SPAWNS_MANY_CHILDREN":
                        values = {"host": entity[0], "parent": entity[1]}
                    else:
                        values = {"host": entity[0], "user": entity[1]}
                    alerts.append(create_alert(
                        rule_id, self.registry.get(rule_id).severity, title,
                        description.format(**values), matching,
                    ))
                    break
        return alerts

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

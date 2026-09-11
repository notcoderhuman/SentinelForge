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
        if self.registry.get("REPEATED_DNS_QUERY").enabled:
            alerts.extend(self._dns_repeated_hostname_query(ordered_events))
        if self.registry.get("SOURCE_QUERIES_MANY_DOMAINS").enabled:
            alerts.extend(self._dns_hostname_many_queries(ordered_events))
        if self.registry.get("DNS_QUERY_TO_SUSPICIOUS_DOMAIN").enabled:
            alerts.extend(self._dns_suspicious_domain(ordered_events, threat_context))
        if self.registry.get("DOMAIN_QUERIED_BY_MANY_SOURCES").enabled:
            alerts.extend(self._dns_query_many_hostnames(ordered_events))
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
        if self.registry.get("REPEATED_FILE_ACTIVITY").enabled:
            alerts.extend(self._repeated_file_activity(ordered_events))
        if self.registry.get("HOST_MODIFIES_MANY_DISTINCT_FILES").enabled:
            alerts.extend(self._host_modifies_many_files(ordered_events))
        if self.registry.get("EXECUTABLE_FILE_CREATED").enabled and self.config.executable_file_created_enabled:
            alerts.extend(self._executable_file_created(ordered_events))
        if self.registry.get("FILE_ACTIVITY_ON_SENSITIVE_PATH").enabled and self.config.sensitive_file_path_enabled:
            alerts.extend(self._sensitive_file_activity(ordered_events, threat_context))
        alerts.extend(self._event_correlations(ordered_events))
        alerts.extend(self._registry_detections(ordered_events))
        alerts.extend(self._persistence_detections(ordered_events))
        unique = {alert.alert_id: alert for alert in alerts}
        return sorted(unique.values(), key=lambda alert: (alert.timestamp, alert.rule_id, alert.alert_id))

    @staticmethod
    def _dns_events(events: Sequence[SecurityEvent]) -> List[SecurityEvent]:
        return [event for event in events if event.event_type == "dns_query"]

    @staticmethod
    def _dns_query(event: SecurityEvent) -> str | None:
        query = getattr(event, "query", None)
        return query.strip().lower().rstrip(".") if isinstance(query, str) and query.strip() else None

    def _dns_repeated_hostname_query(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        grouped: Dict[tuple[str, str], List[SecurityEvent]] = {}
        for event in self._dns_events(events):
            query = self._dns_query(event)
            if event.hostname and query:
                grouped.setdefault((event.hostname, query), []).append(event)
        return self._dns_threshold_alerts(grouped, self.config.repeated_dns_query_threshold,
                                          self.config.repeated_dns_query_window_seconds,
                                          "REPEATED_DNS_QUERY",
                                          "Repeated DNS query observed.",
                                          "Hostname {hostname} repeatedly queried {query} within the configured window.")

    def _dns_hostname_many_queries(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        grouped: Dict[str, List[SecurityEvent]] = {}
        for event in self._dns_events(events):
            query = self._dns_query(event)
            if event.hostname and query:
                grouped.setdefault(event.hostname, []).append(event)
        return self._dns_distinct_alerts(grouped, self.config.dns_many_domains_threshold or self.config.dns_many_queries_threshold,
                                         self.config.dns_many_domains_window_seconds or self.config.dns_many_queries_window_seconds,
                                         "SOURCE_QUERIES_MANY_DOMAINS",
                                         "Hostname queried many distinct DNS names.",
                                         "Hostname {entity} queried distinct DNS names within the configured window.",
                                         self._dns_query)

    def _dns_suspicious_domain(self, events: Sequence[SecurityEvent], threat_context: Sequence[ThreatContext]) -> List[Alert]:
        definition = self.registry.get("DNS_QUERY_TO_SUSPICIOUS_DOMAIN")
        alerts = []
        for event in self._dns_events(events):
            # Match only the normalized query observable.  Domains mentioned in
            # the free-form message are deliberately not eligible for this rule.
            query_observables = [observable for observable in extract_observables([event])
                                 if observable.observable_type == "domain"
                                 and observable.provenance == "event.query"]
            contexts = match_context(query_observables, threat_context)
            context = next((item for item in contexts
                            if item.context_type in {"suspicious", "known_malicious"}), None)
            query = self._dns_query(event)
            if context is not None and query:
                alerts.append(create_alert(definition.rule_id, definition.severity,
                    "DNS query matched suspicious local domain context.",
                    f"DNS query for {query} exactly matched suspicious local context; local context is not proof of malicious activity.", [event]))
        return alerts

    def _dns_query_many_hostnames(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        grouped: Dict[str, List[SecurityEvent]] = {}
        for event in self._dns_events(events):
            query = self._dns_query(event)
            if event.hostname and query:
                grouped.setdefault(query, []).append(event)
        return self._dns_distinct_alerts(grouped, self.config.dns_many_hostnames_threshold,
                                         self.config.dns_many_hostnames_window_seconds,
                                         "DOMAIN_QUERIED_BY_MANY_SOURCES",
                                         "DNS query observed from many hostnames.",
                                         "DNS query {entity} was observed from distinct hostnames within the configured window.",
                                         lambda event: event.hostname)

    def _dns_threshold_alerts(self, grouped, threshold, window_seconds, rule_id, title, description):
        alerts = []
        window = timedelta(seconds=window_seconds)
        for entity, items in sorted(grouped.items(), key=lambda item: str(item[0])):
            for end in range(threshold - 1, len(items)):
                matching = items[end - threshold + 1:end + 1]
                if matching[-1].timestamp - matching[0].timestamp <= window:
                    alerts.append(create_alert(rule_id, self.registry.get(rule_id).severity, title,
                        description.format(hostname=entity[0], query=entity[1]), matching))
                    break
        return alerts

    def _dns_distinct_alerts(self, grouped, threshold, window_seconds, rule_id, title, description, key):
        alerts = []
        window = timedelta(seconds=window_seconds)
        for entity, items in sorted(grouped.items(), key=lambda item: str(item[0])):
            for end in range(threshold - 1, len(items)):
                matching = items[end - threshold + 1:end + 1]
                if matching[-1].timestamp - matching[0].timestamp <= window and len({key(event) for event in matching}) >= threshold:
                    alerts.append(create_alert(rule_id, self.registry.get(rule_id).severity, title,
                        description.format(entity=entity), matching))
                    break
        return alerts

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

    @staticmethod
    def _file_events(events: Sequence[SecurityEvent]) -> List[SecurityEvent]:
        return [event for event in events if event.event_type == "file_activity"]

    def _repeated_file_activity(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        grouped: Dict[tuple[str, str, str], List[SecurityEvent]] = {}
        for event in self._file_events(events):
            if event.hostname and event.path and event.action:
                grouped.setdefault((event.hostname, event.path, event.action), []).append(event)
        return self._file_threshold_alerts(grouped, self.config.repeated_file_activity_threshold,
                                           self.config.repeated_file_activity_window_seconds,
                                           "REPEATED_FILE_ACTIVITY", "Repeated file activity observed.",
                                           "Host {host} repeatedly performed action {action} on file {path} within the configured window.")

    def _host_modifies_many_files(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        grouped: Dict[tuple[str, str], List[SecurityEvent]] = {}
        for event in self._file_events(events):
            if event.hostname and event.username and event.path and (event.action or "").lower() in {"create", "modify", "delete", "rename"}:
                grouped.setdefault((event.hostname, event.username), []).append(event)
        return self._file_distinct_alerts(grouped, self.config.host_many_distinct_files_threshold,
                                           self.config.host_many_distinct_files_window_seconds,
                                           "HOST_MODIFIES_MANY_DISTINCT_FILES",
                                           "Host modified many distinct files.",
                                           "Host {entity} modified distinct file paths within the configured window.")

    def _executable_file_created(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        definition = self.registry.get("EXECUTABLE_FILE_CREATED")
        extensions = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".sh", ".so", ".dylib"}
        directories = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/windows/system32/", "/windows/syswow64/")
        alerts = []
        for event in self._file_events(events):
            path = event.path or ""
            normalized = path.replace("\\", "/").lower()
            name = normalized.rsplit("/", 1)[-1]
            action = (event.action or "").strip().lower()
            directory_match = any(normalized.startswith(directory) or ("/" + directory.strip("/") + "/") in normalized for directory in directories)
            if action in {"create", "created"} and (any(name.endswith(ext) for ext in extensions) or directory_match):
                alerts.append(create_alert(definition.rule_id, definition.severity, "Executable file created.", "A file activity event targeted a path commonly associated with executable content; this does not claim execution or malware.", [event]))
        return alerts

    def _sensitive_file_activity(self, events: Sequence[SecurityEvent], threat_context: Sequence[ThreatContext]) -> List[Alert]:
        definition = self.registry.get("FILE_ACTIVITY_ON_SENSITIVE_PATH")
        alerts = []
        for event in self._file_events(events):
            observables = [item for item in extract_observables([event]) if item.observable_type == "file_path" and item.provenance == "event.path"]
            if any(context.context_type in {"suspicious", "known_malicious"} for context in match_context(observables, threat_context)):
                alerts.append(create_alert(definition.rule_id, definition.severity, "File activity matched sensitive local context.", "File activity exactly matched a suspicious local file-path context; local context is not proof of malicious activity.", [event]))
        return alerts

    def _file_threshold_alerts(self, grouped, threshold, window_seconds, rule_id, title, description):
        alerts = []
        window = timedelta(seconds=window_seconds)
        for entity, items in sorted(grouped.items(), key=lambda item: str(item[0])):
            for end in range(threshold - 1, len(items)):
                matching = items[end - threshold + 1:end + 1]
                if matching[-1].timestamp - matching[0].timestamp <= window:
                    alerts.append(create_alert(rule_id, self.registry.get(rule_id).severity, title, description.format(host=entity[0], path=entity[1], action=entity[2]), matching))
                    break
        return alerts

    def _file_distinct_alerts(self, grouped, threshold, window_seconds, rule_id, title, description):
        alerts = []
        window = timedelta(seconds=window_seconds)
        for entity, items in sorted(grouped.items()):
            for end in range(threshold - 1, len(items)):
                matching = items[end - threshold + 1:end + 1]
                if matching[-1].timestamp - matching[0].timestamp <= window and len({event.path for event in matching}) >= threshold:
                    label = entity if isinstance(entity, str) else f"{entity[0]} / {entity[1]}"
                    alerts.append(create_alert(rule_id, self.registry.get(rule_id).severity, title, description.format(entity=label), matching))
                    break
        return alerts

    def _event_correlations(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        """Emit deterministic, evidence-linked cross-source relationships."""
        window = timedelta(seconds=300)
        auth = [event for event in events
                if event.event_type == "authentication_success"]
        network = [event for event in events
                   if event.event_type == "network_connection"]
        processes = [event for event in events
                     if event.event_type == "process_execution"]
        alerts: List[Alert] = []

        def emit(rule_id: str, evidence: Sequence[SecurityEvent], description: str) -> None:
            try:
                definition = self.registry.get(rule_id)
            except KeyError:
                return
            if not definition.enabled:
                return
            ordered = sorted(evidence, key=lambda event: (event.timestamp, event.raw))
            alerts.append(create_alert(
                rule_id, definition.severity, definition.name + " observed.",
                description, ordered,
            ))

        def auth_identity_matches(left: SecurityEvent, right: SecurityEvent) -> bool:
            return (bool(left.username and right.username and left.hostname and right.hostname)
                    and left.username == right.username
                    and left.hostname == right.hostname)

        def host_matches(left: SecurityEvent, right: SecurityEvent) -> bool:
            return bool(left.hostname and right.hostname and left.hostname == right.hostname)

        def within(start: SecurityEvent, end: SecurityEvent) -> bool:
            delta = end.timestamp - start.timestamp
            return timedelta(0) <= delta <= window

        for success in auth:
            for network_event in network:
                if within(success, network_event) and auth_identity_matches(success, network_event):
                    emit(
                        "AUTHENTICATION_TO_NETWORK_ACTIVITY", (success, network_event),
                        "A successful authentication was followed by network activity for the same explicit user and host.",
                    )

        for success in auth:
            for process_event in processes:
                if within(success, process_event) and auth_identity_matches(success, process_event):
                    emit(
                        "AUTHENTICATION_TO_PROCESS_ACTIVITY", (success, process_event),
                        "A successful authentication was followed by process execution for the same explicit user and host.",
                    )

        for network_event in network:
            for process_event in processes:
                if within(network_event, process_event) and host_matches(network_event, process_event):
                    emit(
                        "NETWORK_TO_PROCESS_ACTIVITY", (network_event, process_event),
                        "Network activity was followed by process execution on the same explicit host; no ownership is inferred.",
                    )

        for success in auth:
            for network_event in network:
                for process_event in processes:
                    if (within(success, network_event)
                            and within(network_event, process_event)
                            and process_event.timestamp - success.timestamp <= window
                            and auth_identity_matches(success, process_event)
                            and auth_identity_matches(success, network_event)
                            and host_matches(network_event, process_event)):
                        emit(
                            "AUTH_NETWORK_PROCESS_CHAIN", (success, network_event, process_event),
                            "Authentication, network activity, and process execution formed an explicit identity chain.",
                        )

        unique = {alert.alert_id: alert for alert in alerts}
        return sorted(unique.values(), key=lambda alert: (alert.timestamp, alert.rule_id, alert.alert_id))

    def _registry_detections(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        """Detect the four Phase 23 registry behaviors from explicit telemetry."""
        alerts: List[Alert] = []
        registry = [event for event in events if event.event_type in {"registry", "registry_activity", "registry_change"}]

        def emit(rule_id: str, evidence: Sequence[SecurityEvent], text: str) -> None:
            definition = self.registry.get(rule_id)
            if definition.enabled:
                ordered = sorted(evidence, key=lambda event: (event.timestamp, event.raw))
                alerts.append(create_alert(rule_id, definition.severity,
                                           definition.name + " observed.", text, ordered))

        for event in registry:
            action = (event.registry_action or "").strip().lower()
            key_path = (event.key_path or "").strip()
            if action == "set_value" and key_path and (event.value_name or "").strip():
                emit("REGISTRY_VALUE_MODIFIED", [event],
                     "A registry value was set or modified at an explicit key and value name.")
            if action == "delete_key" and key_path:
                emit("REGISTRY_KEY_DELETED", [event],
                     "A registry key was deleted at an explicit key path.")
            canonical = self._canonical_run_key(key_path, event.hive)
            if canonical and action == "set_value":
                emit("REGISTRY_RUN_KEY_MODIFICATION", [event],
                     "A canonical Windows Run or RunOnce registry key was modified.")

        grouped: Dict[tuple[str, str, str], List[SecurityEvent]] = {}
        for event in registry:
            if event.hostname and event.key_path and event.process_name:
                grouped.setdefault((event.hostname, event.hive, event.key_path), []).append(event)
        threshold = self.config.registry_activity_threshold
        window = timedelta(seconds=self.config.registry_activity_window_seconds)
        for entity, items in sorted(grouped.items(), key=lambda item: item[0]):
            for end in range(threshold - 1, len(items)):
                matching = items[end - threshold + 1:end + 1]
                names = {item.process_name for item in matching if item.process_name}
                if len(names) >= threshold and matching[-1].timestamp - matching[0].timestamp <= window:
                    emit("REGISTRY_ACTIVITY_BY_MANY_PROCESSES", matching,
                         "Registry activity for one explicit host and key path came from many distinct processes within the configured window.")
                    break
        unique = {alert.alert_id: alert for alert in alerts}
        return sorted(unique.values(), key=lambda alert: (alert.timestamp, alert.rule_id, alert.alert_id))

    @staticmethod
    def _canonical_run_key(key_path: str, hive: str | None = None) -> bool:
        normalized = key_path.replace("/", "\\").strip().rstrip("\\").lower()
        if hive:
            hive_name = hive.strip().lower()
            hive_name = {"hkey_current_user": "hkcu", "hkey_local_machine": "hklm"}.get(hive_name, hive_name)
            if "\\" not in normalized or not normalized.startswith(("hkcu\\", "hklm\\")):
                normalized = hive_name + "\\" + normalized
        return normalized in {
            "hkcu\\software\\microsoft\\windows\\currentversion\\run",
            "hkcu\\software\\microsoft\\windows\\currentversion\\runonce",
            "hklm\\software\\microsoft\\windows\\currentversion\\run",
            "hklm\\software\\microsoft\\windows\\currentversion\\runonce",
        }

    def _persistence_detections(self, events: Sequence[SecurityEvent]) -> List[Alert]:
        """Detect only explicit system-persistence records and relationships."""
        alerts: List[Alert] = []
        actions = {"create", "created", "update", "updated"}
        starts = {"start", "started", "running"}
        persistence = [event for event in events if event.event_type in {"persistence", "system_persistence"}]
        def emit(rule_id: str, evidence: Sequence[SecurityEvent], text: str) -> None:
            definition = self.registry.get(rule_id)
            if definition.enabled:
                ordered = sorted(evidence, key=lambda event: (event.timestamp, event.raw))
                alerts.append(create_alert(rule_id, definition.severity, definition.name + " observed.", text, ordered))
        for event in persistence:
            action = (event.persistence_action or "").strip().lower()
            kind = (event.persistence_type or "").strip().lower()
            if kind == "service" and action in actions:
                emit("SERVICE_CREATED_OR_UPDATED", [event], "A service create or update was observed.")
            if kind in {"scheduled_task", "cron"} and action in actions:
                emit("SCHEDULED_TASK_CREATED_OR_UPDATED", [event], "A scheduled-task or cron create or update was observed.")
                if event.command and event.command.strip():
                    emit("SCHEDULED_TASK_CREATED_WITH_COMMAND", [event], "A scheduled-task or cron create or update included an explicit command.")
        window = timedelta(seconds=self.config.persistence_correlation_window_seconds)
        for created in persistence:
            if (created.persistence_type or "").lower() != "service" or (created.persistence_action or "").lower() not in actions:
                continue
            if not created.hostname or not created.username or not created.persistence_name:
                continue
            for started in persistence:
                if ((started.persistence_type or "").lower() == "service"
                    and (started.persistence_action or "").lower() in starts
                    and started.hostname == created.hostname
                    and started.username == created.username
                    and started.persistence_name == created.persistence_name
                    and timedelta(0) <= started.timestamp - created.timestamp <= window):
                    emit("SERVICE_STARTED_AFTER_CREATION", [created, started], f"A service was started within {self.config.persistence_correlation_window_seconds} seconds of creation or update for the same explicit host, service, and user.")
        unique = {alert.alert_id: alert for alert in alerts}
        return sorted(unique.values(), key=lambda alert: (alert.timestamp, alert.rule_id, alert.alert_id))

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

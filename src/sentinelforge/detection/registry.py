"""Explicit registry for SentinelForge detection-rule metadata."""

from __future__ import annotations

from typing import Dict, Iterable, Tuple

from .rule import RuleDefinition


class RuleRegistry:
    """Immutable-by-convention collection of explicitly registered rules."""

    def __init__(self, definitions: Iterable[RuleDefinition]) -> None:
        definitions_by_id: Dict[str, RuleDefinition] = {}
        for definition in definitions:
            if definition.rule_id in definitions_by_id:
                raise ValueError(f"duplicate rule ID: {definition.rule_id}")
            definitions_by_id[definition.rule_id] = definition
        self._definitions = definitions_by_id

    def get(self, rule_id: str) -> RuleDefinition:
        """Return a definition or raise ``KeyError`` for an unknown rule."""
        return self._definitions[rule_id]

    def all(self) -> Tuple[RuleDefinition, ...]:
        """Return explicitly registered rules in stable rule-ID order."""
        return tuple(self._definitions[rule_id] for rule_id in sorted(self._definitions))


DEFAULT_RULE_REGISTRY = RuleRegistry((
    RuleDefinition("OUTBOUND_CONNECTION_TO_SUSPICIOUS_IP", "Outbound connection to suspicious IP",
                   "An outbound network connection reached an IP address explicitly marked suspicious by local threat context.", "medium", 1, True,
                   ("one outbound network event whose destination IP matches suspicious local threat context",)),
    RuleDefinition("REPEATED_CONNECTION_TO_SAME_DESTINATION", "Repeated connection to the same destination",
                   "Repeated outbound connections to one destination within a bounded window.", "low", 120, True,
                   ("five network connection events to one destination within 120 seconds",)),
    RuleDefinition("SOURCE_CONTACTS_MANY_DESTINATIONS", "Source contacts many destinations",
                   "One source contacts multiple destinations within a bounded window.", "medium", 120, True,
                   ("five network connection events from one source to distinct destinations within 120 seconds",)),
    RuleDefinition("DESTINATION_CONTACTED_BY_MANY_SOURCES", "Destination contacted by many sources",
                   "One destination is contacted by multiple sources within a bounded window.", "medium", 120, True,
                   ("five network connection events from distinct sources to one destination within 120 seconds",)),
    RuleDefinition("REPEATED_AUTH_FAILURE", "Repeated authentication failure",
                   "Repeated failures for one account within a bounded window.", "medium", 120, True,
                   ("three authentication_failure events for one username",)),
    RuleDefinition("SSH_BRUTE_FORCE", "Possible SSH brute-force activity",
                   "Failed SSH authentications from one source IP within a bounded window.", "high", 120, True,
                   ("five sshd authentication_failure events from one source IP",), ("T1110",)),
    RuleDefinition("SUCCESS_AFTER_FAILURES", "Successful authentication after failures",
                   "A success follows earlier failures for the same account.", "medium", 300, True,
                   ("authentication_failure events followed by authentication_success for one username",)),
    RuleDefinition("SUSPICIOUS_SUDO_ACTIVITY", "Observed sudo activity",
                   "A supported sudo command was recorded.", "low", 1, True,
                   ("sudo_activity event containing a command",)),
    RuleDefinition("SOURCE_TARGETS_MULTIPLE_ACCOUNTS", "One source targets multiple accounts",
                   "Authentication failures from one source IP target multiple usernames.", "medium", 120, True,
                   ("three authentication_failure events for distinct usernames from one source IP",)),
    RuleDefinition("ACCOUNT_TARGETED_BY_MULTIPLE_SOURCES", "One account targeted by multiple sources",
                   "Authentication failures for one username originate from multiple source IPs.", "medium", 120, True,
                   ("three authentication_failure events from distinct source IPs for one username",)),
    RuleDefinition("WINDOWS_PRIVILEGED_LOGON", "Windows privileged logon observed",
                   "A Windows Security Event 4672 assigned special privileges to a new logon.", "low", 300, True,
                   ("one Windows event_id 4672 with an explicit username",)),
))

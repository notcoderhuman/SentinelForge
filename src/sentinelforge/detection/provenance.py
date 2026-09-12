"""Deterministic provenance identities for detection configuration.

The engine has historically not enforced ``RuleDefinition.enabled`` uniformly.
Consequently this module keeps configured registry identity separate from the
behavioral identity attached to alerts: the latter never claims that enabled
is effective for every detection family.
"""

from __future__ import annotations

from dataclasses import fields
import hashlib
import json
from typing import Any, Mapping

from .registry import RuleRegistry
from .rule import RuleDefinition
from .rules import RuleConfig

CONFIGURATION_FIELDS = tuple(item.name for item in fields(RuleConfig))

# Values are deliberately expressed in the names used by the detection code,
# rather than including compatibility aliases that may be inactive.
RULE_CONFIGURATION_FIELDS = {
    "SSH_BRUTE_FORCE": ("ssh_brute_force_threshold", "ssh_brute_force_window_seconds"),
    "REPEATED_AUTH_FAILURE": ("repeated_failure_threshold", "repeated_failure_window_seconds"),
    "SUCCESS_AFTER_FAILURES": ("success_after_failure_window_seconds",),
    "SOURCE_TARGETS_MULTIPLE_ACCOUNTS": ("source_targeting_accounts_threshold", "source_targeting_accounts_window_seconds"),
    "ACCOUNT_TARGETED_BY_MULTIPLE_SOURCES": ("account_targeted_by_sources_threshold", "account_targeted_by_sources_window_seconds"),
    "REPEATED_CONNECTION_TO_SAME_DESTINATION": ("repeated_connection_threshold", "repeated_connection_window_seconds"),
    "SOURCE_CONTACTS_MANY_DESTINATIONS": ("source_many_destinations_threshold", "source_many_destinations_window_seconds"),
    "DESTINATION_CONTACTED_BY_MANY_SOURCES": ("destination_many_sources_threshold", "destination_many_sources_window_seconds"),
    "REPEATED_DNS_QUERY": ("repeated_dns_query_threshold", "repeated_dns_query_window_seconds"),
    "DOMAIN_QUERIED_BY_MANY_SOURCES": ("dns_many_hostnames_threshold", "dns_many_hostnames_window_seconds"),
    "PRIVILEGED_PROCESS_EXECUTION": ("privileged_process_enabled",),
    "REPEATED_PROCESS_EXECUTION": ("repeated_process_threshold", "repeated_process_window_seconds"),
    "SUSPICIOUS_SUDO_ACTIVITY": ("sudo_enabled",),
    "REPEATED_FILE_ACTIVITY": ("repeated_file_activity_threshold", "repeated_file_activity_window_seconds"),
    "HOST_MODIFIES_MANY_DISTINCT_FILES": ("host_many_distinct_files_threshold", "host_many_distinct_files_window_seconds"),
    "EXECUTABLE_FILE_CREATED": ("executable_file_created_enabled",),
    "FILE_ACTIVITY_ON_SENSITIVE_PATH": ("sensitive_file_path_enabled",),
    "SERVICE_STARTED_AFTER_CREATION": ("persistence_correlation_window_seconds",),
    "REGISTRY_ACTIVITY_BY_MANY_PROCESSES": ("registry_activity_threshold", "registry_activity_window_seconds"),
    "WINDOWS_SERVICE_START_AFTER_STOP": ("windows_service_correlation_window_seconds",),
}


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_rule_definition(definition: RuleDefinition, *, include_enabled: bool = False) -> dict[str, Any]:
    """Return identity fields; ``enabled`` is only for configured identity."""
    result = {
        "rule_id": definition.rule_id,
        "severity": definition.severity,
        "detection_window_seconds": definition.detection_window_seconds,
        "attack_mapping_reference": list(definition.attack_mapping_reference),
    }
    if include_enabled:
        result["enabled"] = definition.enabled
    return result


def canonical_rule_configuration(definition: RuleDefinition, config: RuleConfig) -> dict[str, Any]:
    """Return the values actually selected by this rule's detection path."""
    rule_id = definition.rule_id
    if rule_id == "SOURCE_QUERIES_MANY_DOMAINS":
        threshold = config.dns_many_domains_threshold or config.dns_many_queries_threshold
        window = config.dns_many_domains_window_seconds or config.dns_many_queries_window_seconds
        return {"threshold": threshold, "window_seconds": window}
    if rule_id == "PARENT_PROCESS_SPAWNS_MANY_CHILDREN":
        threshold = (config.process_parent_child_threshold
                     if config.process_parent_child_threshold is not None
                     else config.parent_process_children_threshold)
        return {"threshold": threshold, "window_seconds": config.parent_process_children_window_seconds}
    if rule_id == "USER_EXECUTES_MANY_DISTINCT_PROCESSES":
        threshold = (config.user_process_threshold
                     if config.user_process_threshold is not None
                     else config.user_process_names_threshold)
        return {"threshold": threshold, "window_seconds": config.user_process_names_window_seconds}
    return {name: getattr(config, name) for name in RULE_CONFIGURATION_FIELDS.get(rule_id, ())}


def _fingerprint(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()[:16]


def rule_fingerprint(definition: RuleDefinition, config: RuleConfig) -> str:
    """Per-rule provenance identity; excludes non-uniform registry ``enabled``.

    This is intentionally not named an effective behavioral fingerprint: the
    engine does not honor ``enabled`` on every direct detection path.
    """
    return _fingerprint({"rule_definition": canonical_rule_definition(definition),
                         "configuration": canonical_rule_configuration(definition, config)})


def configured_rule_fingerprint(definition: RuleDefinition, config: RuleConfig) -> str:
    """Declared registry identity, including enabled and effective rule config."""
    return _fingerprint({"rule_definition": canonical_rule_definition(definition, include_enabled=True),
                         "configuration": canonical_rule_configuration(definition, config)})


def engine_configuration_fingerprint(config: RuleConfig, registry: RuleRegistry) -> str:
    """Identity of the authoritative engine config, excluding presentation text."""
    rules = []
    for definition in registry.all():
        rules.append({"rule_definition": canonical_rule_definition(definition, include_enabled=True),
                      "configuration": canonical_rule_configuration(definition, config)})
    return _fingerprint({
        "rule_config": {name: getattr(config, name) for name in CONFIGURATION_FIELDS},
        "rule_registry": rules,
    })

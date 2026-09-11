"""Configuration for deterministic detection rules."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleConfig:
    """Thresholds and windows used by the deterministic engine."""

    ssh_brute_force_threshold: int = 5
    ssh_brute_force_window_seconds: int = 120
    repeated_failure_threshold: int = 3
    repeated_failure_window_seconds: int = 120
    success_after_failure_window_seconds: int = 300
    source_targeting_accounts_threshold: int = 3
    source_targeting_accounts_window_seconds: int = 120
    account_targeted_by_sources_threshold: int = 3
    account_targeted_by_sources_window_seconds: int = 120
    repeated_connection_threshold: int = 5
    repeated_connection_window_seconds: int = 120
    source_many_destinations_threshold: int = 5
    source_many_destinations_window_seconds: int = 120
    destination_many_sources_threshold: int = 5
    destination_many_sources_window_seconds: int = 120
    # Phase 18 process telemetry detections.
    privileged_process_enabled: bool = True
    repeated_process_threshold: int = 5
    repeated_process_window_seconds: int = 120
    parent_process_children_threshold: int = 5
    parent_process_children_window_seconds: int = 120
    user_process_names_threshold: int = 5
    user_process_names_window_seconds: int = 120
    # Phase 20 DNS telemetry detections.
    repeated_dns_query_threshold: int = 5
    repeated_dns_query_window_seconds: int = 120
    dns_many_queries_threshold: int = 5
    dns_many_queries_window_seconds: int = 120
    dns_many_hostnames_threshold: int = 5
    dns_many_hostnames_window_seconds: int = 120
    dns_many_domains_threshold: int = 5
    dns_many_domains_window_seconds: int = 120
    # Compatibility aliases used by early Phase 18 callers.
    process_parent_child_threshold: int | None = None
    user_process_threshold: int | None = None
    sudo_enabled: bool = True
    # Phase 21 file activity detections.
    repeated_file_activity_threshold: int = 5
    repeated_file_activity_window_seconds: int = 120
    host_many_distinct_files_threshold: int = 5
    host_many_distinct_files_window_seconds: int = 120
    executable_file_created_enabled: bool = True
    sensitive_file_path_enabled: bool = True
    # Phase 22 system-persistence detections.
    persistence_correlation_window_seconds: int = 300
    # Phase 23 registry telemetry detections.
    registry_activity_threshold: int = 5
    registry_activity_window_seconds: int = 120

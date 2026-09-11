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
    sudo_enabled: bool = True

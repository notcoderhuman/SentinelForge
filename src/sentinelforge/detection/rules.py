"""Configuration for Phase 1 detection rules."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleConfig:
    """Thresholds and windows used by the deterministic engine."""

    ssh_brute_force_threshold: int = 5
    ssh_brute_force_window_seconds: int = 120
    repeated_failure_threshold: int = 3
    repeated_failure_window_seconds: int = 120
    success_after_failure_window_seconds: int = 300
    sudo_enabled: bool = True

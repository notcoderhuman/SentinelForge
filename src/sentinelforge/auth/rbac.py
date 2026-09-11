"""Explicit role and permission policy."""

from __future__ import annotations

from enum import Enum


class Permission(str, Enum):
    READ_ANALYSIS = "read_analysis"
    RUN_ANALYSIS = "run_analysis"
    ADMIN_USERS = "admin_users"
    READ_AUDIT = "read_audit"

ROLE_PERMISSIONS = {
    "admin": frozenset(Permission),
    "analyst": frozenset({Permission.READ_ANALYSIS, Permission.RUN_ANALYSIS}),
    "viewer": frozenset({Permission.READ_ANALYSIS}),
}


def allowed(role: str, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())

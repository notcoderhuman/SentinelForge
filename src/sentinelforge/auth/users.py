"""Validated authenticated user model."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

ROLES = frozenset({"admin", "analyst", "viewer"})
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")


@dataclass(frozen=True)
class User:
    user_id: str
    username: str
    password_hash: str
    role: str
    created_at: datetime
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.user_id or not _USERNAME.fullmatch(self.username):
            raise ValueError("invalid user identity")
        if not self.password_hash or self.role not in ROLES:
            raise ValueError("invalid user credentials or role")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if not isinstance(self.enabled, bool):
            raise ValueError("enabled must be boolean")

    def public_dict(self) -> dict[str, object]:
        return {"user_id": self.user_id, "username": self.username, "role": self.role,
                "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
                "enabled": self.enabled}

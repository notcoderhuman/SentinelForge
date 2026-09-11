"""Server-side sessions with expiration and CSRF tokens."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

SESSION_TTL = timedelta(hours=8)


@dataclass(frozen=True)
class Session:
    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    last_seen_at: datetime
    csrf_token: str

    @property
    def expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at


def create_session(user_id: str, now: datetime | None = None) -> Session:
    current = now or datetime.now(timezone.utc)
    return Session(secrets.token_urlsafe(32), user_id, current, current + SESSION_TTL,
                   current, secrets.token_urlsafe(32))


def token_hash(token: str) -> str:
    """Return the non-reversible digest suitable for database storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

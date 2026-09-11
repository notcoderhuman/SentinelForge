"""Repositories for authentication records.

These helpers keep SQL and credential storage details out of API handlers.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from ..auth.users import User, ROLES
from .database import Database


def _user(row: Any) -> User:
    return User(row["user_id"], row["username"], row["password_hash"], row["role"],
                datetime.fromisoformat(row["created_at"]), bool(row["active"]))


class AuthRepository:
    """CRUD and lookup operations for users, sessions, and audit records."""
    def __init__(self, database: Database) -> None:
        self.db = database

    def create_user(self, user: User, password_hash: Optional[str] = None) -> User:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO users(user_id,username,password_hash,role,active,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
                (user.user_id, user.username, password_hash or user.password_hash, user.role,
                 int(user.enabled), user.created_at.isoformat(), user.created_at.isoformat()),
            )
        return user

    def get_user(self, user_id: str) -> Optional[User]:
        row = self.db.connection.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        return None if row is None else _user(row)

    def get_user_by_username(self, username: str, *, active_only: bool = False) -> Optional[User]:
        query = "SELECT * FROM users WHERE username=?" + (" AND active=1" if active_only else "")
        row = self.db.connection.execute(query, (username,)).fetchone()
        return None if row is None else _user(row)

    def list_users(self, *, active_only: bool = False) -> list[User]:
        query = "SELECT * FROM users" + (" WHERE active=1" if active_only else "") + " ORDER BY username"
        return [_user(row) for row in self.db.connection.execute(query)]

    def set_user_state(self, user_id: str, *, active: Optional[bool] = None, role: Optional[str] = None) -> Optional[User]:
        if role is not None and role not in ROLES:
            raise ValueError("invalid role")
        row = self.db.connection.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        if row is None:
            return None
        new_active = int(row["active"] if active is None else active)
        new_role = row["role"] if role is None else role
        with self.db.transaction() as conn:
            conn.execute("UPDATE users SET active=?, role=?, updated_at=? WHERE user_id=?",
                         (new_active, new_role, datetime.now(timezone.utc).isoformat(), user_id))
        return self.get_user(user_id)

    def delete_user(self, user_id: str) -> None:
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM users WHERE user_id=?", (user_id,))

    def session_for_token(self, token: str) -> Optional[Any]:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return self.db.connection.execute(
            "SELECT s.*, u.username, u.role, u.active FROM sessions s JOIN users u ON u.user_id=s.user_id "
            "WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.active=1",
            (token_hash, datetime.now(timezone.utc).isoformat()),
        ).fetchone()

    def revoke_session(self, session_id: str) -> bool:
        with self.db.transaction() as conn:
            result = conn.execute("UPDATE sessions SET revoked_at=? WHERE session_id=? AND revoked_at IS NULL",
                                  (datetime.now(timezone.utc).isoformat(), session_id))
        return result.rowcount == 1

    def add_audit(self, *, audit_id: str, user_id: Optional[str], action: str,
                  resource: Optional[str] = None, resource_id: Optional[str] = None,
                  details: Optional[dict[str, Any]] = None, ip_address: Optional[str] = None,
                  created_at: Optional[str] = None) -> None:
        with self.db.transaction() as conn:
            conn.execute("INSERT INTO audit_log VALUES (?,?,?,?,?,?,?,?)",
                         (audit_id, user_id, action, resource, resource_id,
                          json.dumps(details or {}, sort_keys=True), ip_address,
                          created_at or datetime.now(timezone.utc).isoformat()))

    def list_audit(self, *, user_id: Optional[str] = None, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if user_id is None:
            rows = self.db.connection.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = self.db.connection.execute("SELECT * FROM audit_log WHERE user_id=? ORDER BY created_at DESC LIMIT ?", (user_id, limit)).fetchall()
        return [dict(row) | {"details": json.loads(row["details"])} for row in rows]

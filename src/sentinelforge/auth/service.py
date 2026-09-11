"""Database-backed authentication, sessions, and account operations."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from .passwords import hash_password, verify_password
from .sessions import Session, create_session
from .users import User, ROLES
from ..storage.database import Database

class AuthenticationError(Exception): pass
class AuthorizationError(Exception): pass
class LastAdminError(Exception): pass

class AuthService:
    def __init__(self, db: Database): self.db = db

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def create_user(self, username: str, password: str, role: str = "viewer") -> User:
        if role not in ROLES: raise ValueError("invalid role")
        now = datetime.now(timezone.utc)
        user_id = secrets.token_urlsafe(16)
        password_hash = hash_password(password)
        with self.db.transaction() as c:
            c.execute("INSERT INTO users(user_id,username,password_hash,role,active,created_at,updated_at) VALUES (?,?,?,?,1,?,?)", (user_id, username, password_hash, role, now.isoformat(), now.isoformat()))
        return User(user_id, username, password_hash, role, now, True)

    def _user_from_row(self, row) -> User:
        return User(row["user_id"], row["username"], row["password_hash"], row["role"], datetime.fromisoformat(row["created_at"]), bool(row["active"]))

    def get_user(self, user_id: str) -> Optional[User]:
        row = self.db.connection.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        return None if row is None else self._user_from_row(row)

    def get_user_by_username(self, username: str) -> Optional[User]:
        row = self.db.connection.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return None if row is None else self._user_from_row(row)

    def list_users(self) -> list[User]:
        return [self._user_from_row(row) for row in self.db.connection.execute("SELECT * FROM users ORDER BY username")]

    def authenticate(self, username: str, password: str) -> tuple[User, Session, str]:
        user = self.get_user_by_username(username)
        if user is None or not user.enabled or not verify_password(password, user.password_hash):
            raise AuthenticationError("invalid credentials")
        session = create_session(user.user_id); token = secrets.token_urlsafe(32)
        with self.db.transaction() as c:
            c.execute("INSERT INTO sessions(session_id,user_id,token_hash,csrf_token_hash,created_at,expires_at) VALUES (?,?,?,?,?,?)", (session.session_id, user.user_id, self._hash(token), self._hash(session.csrf_token), session.created_at.isoformat(), session.expires_at.isoformat()))
        return user, session, token

    def resolve(self, token: Optional[str]) -> Optional[tuple[User, Session]]:
        if not token: return None
        row = self.db.connection.execute("SELECT s.session_id,s.user_id,s.created_at,s.expires_at,u.username,u.password_hash,u.role,u.active FROM sessions s JOIN users u ON u.user_id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL", (self._hash(token),)).fetchone()
        if row is None: return None
        expires = datetime.fromisoformat(row["expires_at"])
        if datetime.now(timezone.utc) >= expires or not bool(row["active"]): self.revoke(token); return None
        user = self._user_from_row(row); session = Session(row["session_id"], user.user_id, datetime.fromisoformat(row["created_at"]), expires, datetime.now(timezone.utc), "")
        return user, session

    def csrf_valid(self, session: Session, token: str) -> bool:
        row = self.db.connection.execute("SELECT csrf_token_hash FROM sessions WHERE session_id=? AND revoked_at IS NULL", (session.session_id,)).fetchone()
        return bool(row and token) and secrets.compare_digest(self._hash(token), row[0])

    def revoke(self, token: str) -> None:
        with self.db.transaction() as c: c.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=?", (datetime.now(timezone.utc).isoformat(), self._hash(token)))

    def revoke_user(self, user_id: str) -> None:
        with self.db.transaction() as c: c.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (datetime.now(timezone.utc).isoformat(), user_id))

    def set_user(self, user_id: str, active: Optional[bool] = None, role: Optional[str] = None, password: Optional[str] = None) -> User:
        user = self.get_user(user_id)
        if user is None: raise KeyError("user not found")
        if role is not None and role not in ROLES: raise ValueError("invalid role")
        if active is False and user.role == "admin" and user.enabled and sum(1 for item in self.list_users() if item.role == "admin" and item.enabled) <= 1: raise LastAdminError("cannot disable final active administrator")
        with self.db.transaction() as c:
            c.execute("UPDATE users SET active=COALESCE(?,active), role=COALESCE(?,role), password_hash=COALESCE(?,password_hash), updated_at=? WHERE user_id=?", (None if active is None else int(active), role, None if password is None else hash_password(password), datetime.now(timezone.utc).isoformat(), user_id))
        if active is False or password is not None: self.revoke_user(user_id)
        return self.get_user(user_id)  # type: ignore[return-value]

    def delete_user(self, user_id: str) -> None:
        user = self.get_user(user_id)
        if user and user.role == "admin" and user.enabled and sum(1 for item in self.list_users() if item.role == "admin" and item.enabled) <= 1: raise LastAdminError("cannot remove final active administrator")
        with self.db.transaction() as c: c.execute("DELETE FROM users WHERE user_id=?", (user_id,))

    def logout_all(self, user_id: str) -> None:
        self.revoke_user(user_id)

    def change_password(self, user_id: str, current: str, new: str) -> None:
        user = self.get_user(user_id)
        if user is None or not verify_password(current, user.password_hash): raise AuthenticationError("invalid credentials")
        self.set_user(user_id, password=new)

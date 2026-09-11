"""Password hashing using the standard-library scrypt KDF."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

PASSWORD_SCHEME = "scrypt"
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_HASH_BYTES = 32
_MIN_PASSWORD_LENGTH = 12


def validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < _MIN_PASSWORD_LENGTH or not password.strip():
        raise ValueError("password must contain at least 12 non-whitespace characters")


def hash_password(password: str) -> str:
    validate_password(password)
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N,
                            r=_SCRYPT_R, p=_SCRYPT_P, dklen=_HASH_BYTES)
    encode = lambda value: base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
    return f"{PASSWORD_SCHEME}${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${encode(salt)}${encode(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n_text, r_text, p_text, salt_text, digest_text = encoded.split("$", 5)
        if scheme != PASSWORD_SCHEME:
            return False
        n, r, p = int(n_text), int(r_text), int(p_text)
        if n != _SCRYPT_N or r != _SCRYPT_R or p != _SCRYPT_P:
            return False
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        expected = base64.urlsafe_b64decode(digest_text + "=" * (-len(digest_text) % 4))
        if len(salt) != _SALT_BYTES or len(expected) != _HASH_BYTES:
            return False
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeError, OverflowError, MemoryError):
        return False

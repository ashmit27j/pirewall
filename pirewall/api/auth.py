"""Authentication for pirewall-api: password hashing, sessions, Admin PC IP restriction (spec §29).

Single admin role only — no RBAC (spec §29 "only one administrator role is
required"). Password hashing uses stdlib `hashlib.scrypt` rather than
bcrypt/argon2; session tokens are opaque `secrets.token_urlsafe` values,
not JWTs — see `docs/ARCHITECTURE.md` for why both avoid adding a
dependency beyond `CLAUDE.md`'s allowed list.
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from pirewall.core.exceptions import AuthenticationError

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_KEY_LENGTH = 32
_SESSION_TOKEN_BYTES = 32


def hash_password(password: str) -> str:
    """Hash `password` with scrypt and a fresh random salt. Returns `"<salt_hex>$<hash_hex>"`."""
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_KEY_LENGTH
    )
    return f"{salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time-compare `password` against a hash produced by `hash_password`."""
    try:
        salt_hex, hash_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=len(expected)
    )
    return hmac.compare_digest(derived, expected)


@dataclass(frozen=True, slots=True)
class Session:
    """An issued session token and its validity window."""

    token: str
    username: str
    issued_at: datetime
    expires_at: datetime


class SessionStore:
    """In-memory session-token table. No cross-restart persistence needed for a single admin."""

    def __init__(self, token_expiry_seconds: int) -> None:
        self._token_expiry_seconds = token_expiry_seconds
        self._sessions: dict[str, Session] = {}

    def create(self, username: str, now: datetime) -> Session:
        token = secrets.token_urlsafe(_SESSION_TOKEN_BYTES)
        session = Session(
            token=token,
            username=username,
            issued_at=now,
            expires_at=now + timedelta(seconds=self._token_expiry_seconds),
        )
        self._sessions[token] = session
        return session

    def validate(self, token: str, now: datetime) -> Session | None:
        session = self._sessions.get(token)
        if session is None:
            return None
        if session.expires_at <= now:
            del self._sessions[token]
            return None
        return session

    def invalidate(self, token: str) -> None:
        self._sessions.pop(token, None)


class Authenticator:
    """Verifies the single admin's credentials and issues/validates sessions."""

    def __init__(self, admin_username: str, admin_password_hash: str, session_store: SessionStore) -> None:
        self._admin_username = admin_username
        self._admin_password_hash = admin_password_hash
        self._sessions = session_store

    def login(self, username: str, password: str, now: datetime) -> Session:
        """Raises `AuthenticationError` on any mismatch — never reveals which part was wrong."""
        username_ok = hmac.compare_digest(username, self._admin_username)
        password_ok = verify_password(password, self._admin_password_hash)
        if not (username_ok and password_ok):
            raise AuthenticationError("invalid username or password")
        return self._sessions.create(username, now)

    def authenticate(self, token: str, now: datetime) -> Session:
        session = self._sessions.validate(token, now)
        if session is None:
            raise AuthenticationError("invalid or expired session")
        return session

    def logout(self, token: str) -> None:
        self._sessions.invalidate(token)


def enforce_admin_pc_ip(client_host: str | None, admin_pc_ip: str, restrict: bool) -> None:
    """Raise `AuthenticationError` if `client_host` isn't the configured Admin PC (spec §29).

    `restrict` lets `config.security.restrict_to_admin_pc` disable this for
    local-network-only deployments; `client_host` being `None` (no
    connection info at all) is always treated as untrusted.
    """
    if not restrict:
        return
    if client_host is None or client_host != admin_pc_ip:
        raise AuthenticationError(
            f"administrative access is restricted to the configured Admin PC ({admin_pc_ip})"
        )

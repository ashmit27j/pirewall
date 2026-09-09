"""Authentication for pirewall-api: sessions and Admin PC IP restriction (spec §29).

Single admin role only — no RBAC (spec §29 "only one administrator role is
required"). Password hashing lives in `pirewall.core.passwords`, shared with
pirewall-core's portal user store (ADDENDUM_3.md C3) so there is exactly one
scrypt implementation in the tree; `hash_password`/`verify_password` are
re-exported here because this module was their original home and callers
(including `scripts/deployment/configure.py`) import them from here.
Session tokens are opaque `secrets.token_urlsafe` values, not JWTs — see
`docs/ARCHITECTURE.md` for why both avoid adding a dependency beyond
`CLAUDE.md`'s allowed list.
"""

import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address

from pirewall.core.exceptions import AuthenticationError
from pirewall.core.passwords import hash_password, verify_password

__all__ = [
    "Authenticator",
    "Session",
    "SessionStore",
    "enforce_admin_pc_ip",
    "hash_password",
    "verify_password",
]

_SESSION_TOKEN_BYTES = 32


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


def enforce_admin_pc_ip(
    client_host: str | None,
    admin_pc_ip: str,
    restrict: bool,
    allow_local_console: bool = False,
) -> None:
    """Raise `AuthenticationError` if `client_host` isn't the configured Admin PC (spec §29).

    `restrict` lets `config.security.restrict_to_admin_pc` disable this for
    local-network-only deployments; `client_host` being `None` (no
    connection info at all) is always treated as untrusted.

    `allow_local_console` (`config.admin.allow_local_console`, ADDENDUM_3.md
    C6) additionally permits loopback, so an operator sitting at the Pi's own
    desktop can open the control panel without widening access to a routable
    address. Loopback is deliberately the only addition: it cannot be reached
    from any network, so it grants nothing to a LAN or WAN attacker, whereas
    permitting the Pi's own LAN address would expose the panel to anything
    that can spoof or occupy that segment. Defaults to `False` — a deployment
    only gets this by asking for it in config.
    """
    if not restrict:
        return
    if client_host is None:
        raise AuthenticationError(
            f"administrative access is restricted to the configured Admin PC ({admin_pc_ip})"
        )
    if client_host == admin_pc_ip:
        return
    if allow_local_console and _is_loopback(client_host):
        return
    raise AuthenticationError(
        f"administrative access is restricted to the configured Admin PC ({admin_pc_ip})"
    )


def _is_loopback(client_host: str) -> bool:
    """True for `127.0.0.0/8` and `::1`, false for anything unparseable.

    Fails closed: a host string that is not a valid IP address (a hostname,
    a malformed header value) is never treated as loopback.
    """
    try:
        return ip_address(client_host).is_loopback
    except ValueError:
        return False

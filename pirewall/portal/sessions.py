"""Portal session bookkeeping and brute-force throttling (ADDENDUM_3.md C1, C3).

Held in memory by pirewall-core, like pirewall-api's `SessionStore`: a
restart logs LAN clients out, which is the safe direction to fail, and the
authoritative forwarding state is the kernel's `@authed` nft set anyway —
core re-derives that set at startup rather than trusting stale sessions.

Both classes here are bounded on purpose. Everything else in this codebase
that tracks per-source state carries a cap (`max_tracked_sources`,
`max_flows`, `max_active_rules`); an unauthenticated LAN client can drive
both of these structures, so they get the same discipline.
"""

from collections.abc import Hashable
from datetime import datetime, timedelta
from ipaddress import IPv4Address

from pirewall.core.models.portal import PortalSession
from pirewall.core.throttle import Lockout, LockoutScope, ScopedThrottle

_SESSION_TOKEN_BYTES = 32
# The longest username `PortalUserStore` accepts; a longer submitted name
# can match no account, and must not make a throttle key bigger than one.
_MAX_USERNAME_KEY_LENGTH = 64


class PortalSessionRegistry:
    """Active LAN sessions, keyed by token and indexed by client IP.

    One session per IP: a second successful login from the same address
    replaces the first rather than stacking, because the thing being
    authorized is the address, not the person. Without that, logging in
    twice would leave an orphaned token that could outlive the visible
    session and re-authorize the address.
    """

    def __init__(self, token_expiry_seconds: int, max_sessions: int = 512) -> None:
        self._token_expiry_seconds = token_expiry_seconds
        self._max_sessions = max_sessions
        self._by_token: dict[str, PortalSession] = {}
        self._token_by_ip: dict[IPv4Address, str] = {}

    def create(self, username: str, client_ip: IPv4Address, token: str, now: datetime) -> PortalSession:
        """Issue a session for `client_ip`, replacing any existing one for that address."""
        self.purge_expired(now)
        self.invalidate_ip(client_ip)
        if len(self._by_token) >= self._max_sessions:
            # Bounded state: drop the session closest to expiry rather than
            # refusing the login outright, so a full table degrades into
            # shorter sessions instead of a locked-out network.
            oldest = min(self._by_token.values(), key=lambda item: item.expires_at)
            self.invalidate(oldest.token)
        session = PortalSession(
            token=token,
            username=username,
            client_ip=client_ip,
            issued_at=now,
            expires_at=now + timedelta(seconds=self._token_expiry_seconds),
        )
        self._by_token[token] = session
        self._token_by_ip[client_ip] = token
        return session

    def validate(self, token: str, client_ip: IPv4Address, now: datetime) -> PortalSession | None:
        """Return the session only if the token is live *and* still bound to `client_ip`."""
        session = self._by_token.get(token)
        if session is None:
            return None
        if session.expires_at <= now:
            self.invalidate(token)
            return None
        if session.client_ip != client_ip:
            # A token replayed from another address authorizes nothing. Not
            # an error the holder gets to distinguish — it reads as expired.
            return None
        return session

    def get_by_ip(self, client_ip: IPv4Address, now: datetime) -> PortalSession | None:
        token = self._token_by_ip.get(client_ip)
        if token is None:
            return None
        return self.validate(token, client_ip, now)

    def invalidate(self, token: str) -> PortalSession | None:
        session = self._by_token.pop(token, None)
        if session is not None and self._token_by_ip.get(session.client_ip) == token:
            del self._token_by_ip[session.client_ip]
        return session

    def invalidate_ip(self, client_ip: IPv4Address) -> PortalSession | None:
        token = self._token_by_ip.get(client_ip)
        return self.invalidate(token) if token is not None else None

    def purge_expired(self, now: datetime) -> list[PortalSession]:
        """Drop every expired session. Returns them so the caller can retire nft set elements."""
        expired = [item for item in self._by_token.values() if item.expires_at <= now]
        for session in expired:
            self.invalidate(session.token)
        return expired

    def list_sessions(self, now: datetime) -> list[PortalSession]:
        """Live sessions, soonest-to-expire first, for the control panel."""
        self.purge_expired(now)
        return sorted(self._by_token.values(), key=lambda item: item.expires_at)


class LoginThrottle:
    """Failed-login limiter per source IP, per account and globally (ADDENDUM_3.md C3, PLAN_FINAL §4.9).

    The portal is deliberately reachable by anything that can associate
    with the AP, so an online password-guessing attack against it is a
    real, cheap attack that scrypt alone only slows down.

    * **Per source IP** (`max_failures`): one device guessing is stopped
      without affecting anyone else.
    * **Per account** (`max_failures_per_account`): guessing one account's
      password from many addresses (or spoofed ones) is stopped too.
    * **Global** (`max_failures_global`): caps the total guessing rate.

    The per-account and global limits are opt-in here (None disables them)
    so this class keeps its per-IP meaning when built with only the first
    two arguments; `PortalService` always sets all three from config. A
    locked account or a global lockout refuses the *right* password too,
    which is what makes it a throttle and also why its limits are looser
    than the per-IP one: whoever trips them locks out other people.

    Sliding windows over recorded failure timestamps, capped in both
    dimensions (`pirewall.core.throttle.FailureWindow`): at most
    `max_tracked_sources` keys per scope, and at most the scope's limit of
    timestamps per key.
    """

    def __init__(
        self,
        max_failures: int,
        window_seconds: int,
        max_tracked_sources: int = 4096,
        *,
        max_failures_per_account: int | None = None,
        max_failures_global: int | None = None,
    ) -> None:
        limits = {LockoutScope.SOURCE: max_failures}
        if max_failures_per_account is not None:
            limits[LockoutScope.ACCOUNT] = max_failures_per_account
        if max_failures_global is not None:
            limits[LockoutScope.GLOBAL] = max_failures_global
        self._throttle = ScopedThrottle(limits, window_seconds, max_tracked_sources)

    def lockout(self, client_ip: IPv4Address, username: str | None, now: datetime) -> Lockout | None:
        """The lockout refusing a login from `client_ip` as `username`, or None."""
        return self._throttle.lockout(_keys(client_ip, username), now)

    def is_locked_out(self, client_ip: IPv4Address, now: datetime) -> bool:
        """Per-IP (and global) lockout only, ignoring accounts."""
        return self.lockout(client_ip, None, now) is not None

    def seconds_until_unlocked(self, client_ip: IPv4Address, now: datetime) -> int:
        lockout = self.lockout(client_ip, None, now)
        return 0 if lockout is None else lockout.retry_after_seconds

    def record_failure(
        self, client_ip: IPv4Address, now: datetime, username: str | None = None
    ) -> tuple[LockoutScope, ...]:
        """Record one failed login. Returns the scopes this failure newly locked."""
        return self._throttle.record_failure(_keys(client_ip, username), now)

    def clear(self, client_ip: IPv4Address, username: str | None = None) -> None:
        """Forget an address's (and account's) failures — called on a successful login."""
        self._throttle.clear(LockoutScope.SOURCE, client_ip)
        if username is not None:
            self._throttle.clear(LockoutScope.ACCOUNT, _account_key(username))


def _account_key(username: str) -> str:
    """Case-folded, so `Alice` and `alice` share one count; capped like a stored username."""
    return username.casefold()[:_MAX_USERNAME_KEY_LENGTH]


def _keys(client_ip: IPv4Address, username: str | None) -> dict[LockoutScope, Hashable]:
    keys: dict[LockoutScope, Hashable] = {LockoutScope.SOURCE: client_ip}
    if username is not None:
        keys[LockoutScope.ACCOUNT] = _account_key(username)
    return keys

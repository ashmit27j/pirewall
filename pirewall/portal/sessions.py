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

from collections import deque
from datetime import datetime, timedelta
from ipaddress import IPv4Address

from pirewall.core.models.portal import PortalSession

_SESSION_TOKEN_BYTES = 32


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
    """Per-source-IP failed-login limiter (ADDENDUM_3.md C3).

    The admin panel never needed this — ADDENDUM.md A4 and spec §29 keep it
    reachable only from the Admin PC. The portal is deliberately reachable
    by anything that can associate with the AP, so an online password-
    guessing attack against it is a real, cheap attack that scrypt alone
    only slows down.

    Sliding window over recorded failure timestamps, capped in both
    dimensions: at most `max_tracked_sources` addresses, and at most
    `max_failures` timestamps per address.
    """

    def __init__(
        self,
        max_failures: int,
        window_seconds: int,
        max_tracked_sources: int = 4096,
    ) -> None:
        self._max_failures = max_failures
        self._window_seconds = window_seconds
        self._max_tracked_sources = max_tracked_sources
        self._failures: dict[IPv4Address, deque[datetime]] = {}

    def is_locked_out(self, client_ip: IPv4Address, now: datetime) -> bool:
        recent = self._recent(client_ip, now)
        return len(recent) >= self._max_failures

    def seconds_until_unlocked(self, client_ip: IPv4Address, now: datetime) -> int:
        recent = self._recent(client_ip, now)
        if len(recent) < self._max_failures:
            return 0
        unlock_at = recent[0] + timedelta(seconds=self._window_seconds)
        return max(0, int((unlock_at - now).total_seconds()))

    def record_failure(self, client_ip: IPv4Address, now: datetime) -> None:
        if client_ip not in self._failures and len(self._failures) >= self._max_tracked_sources:
            # Bounded: evict the address whose most recent failure is oldest.
            stalest = min(self._failures, key=lambda key: self._failures[key][-1])
            del self._failures[stalest]
        recent = self._failures.setdefault(client_ip, deque(maxlen=self._max_failures))
        recent.append(now)

    def clear(self, client_ip: IPv4Address) -> None:
        """Forget an address's failures — called on a successful login."""
        self._failures.pop(client_ip, None)

    def _recent(self, client_ip: IPv4Address, now: datetime) -> deque[datetime]:
        recent = self._failures.get(client_ip)
        if recent is None:
            return deque()
        cutoff = now - timedelta(seconds=self._window_seconds)
        while recent and recent[0] <= cutoff:
            recent.popleft()
        if not recent:
            del self._failures[client_ip]
        return recent

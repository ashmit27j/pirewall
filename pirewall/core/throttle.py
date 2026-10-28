"""`FailureWindow`: a bounded sliding-window failure counter, keyed by anything hashable.

Shared by the admin login throttle (`pirewall.api.throttle`) and the portal
login throttle (`pirewall.portal.sessions.LoginThrottle`), so both count
failures the same way. Each key holds at most `max_failures` timestamps,
and at most `max_tracked_keys` keys are held at once. A guessing attack
that cycles through source addresses or usernames therefore cannot grow
memory without bound: the key whose newest failure is oldest is evicted.

Not thread-safe; callers that share one across threads hold their own lock.
"""

import math
from collections import deque
from collections.abc import Hashable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

# The one key every failure shares in the GLOBAL scope.
_GLOBAL_KEY = "*"


class LockoutScope(StrEnum):
    """What a lockout is counted over."""

    SOURCE = "source"
    ACCOUNT = "account"
    GLOBAL = "global"


@dataclass(frozen=True, slots=True)
class Lockout:
    """A refusal: which scope is locked, and for how long (the longest, if several are)."""

    scope: LockoutScope
    retry_after_seconds: int


class FailureWindow[K: Hashable]:
    """Counts failures per key over the last `window_seconds`, and locks a key at `max_failures`."""

    def __init__(self, max_failures: int, window_seconds: int, max_tracked_keys: int = 4096) -> None:
        self._max_failures = max_failures
        self._window_seconds = window_seconds
        self._max_tracked_keys = max_tracked_keys
        self._failures: dict[K, deque[datetime]] = {}

    def is_locked_out(self, key: K, now: datetime) -> bool:
        """True while `key` has `max_failures` failures inside the window."""
        return len(self._recent(key, now)) >= self._max_failures

    def seconds_until_unlocked(self, key: K, now: datetime) -> int:
        """Whole seconds, rounded up, until `key` drops below the limit; 0 when not locked.

        Rounded up so a client that waits exactly this long is never refused
        again by a fraction of a second (it is what `Retry-After` carries).
        """
        recent = self._recent(key, now)
        if len(recent) < self._max_failures:
            return 0
        unlock_at = recent[0] + timedelta(seconds=self._window_seconds)
        return max(1, math.ceil((unlock_at - now).total_seconds()))

    def record_failure(self, key: K, now: datetime) -> bool:
        """Record one failure. Returns True when this failure is the one that locks `key`."""
        was_locked = self.is_locked_out(key, now)
        if key not in self._failures and len(self._failures) >= self._max_tracked_keys:
            stalest = min(self._failures, key=lambda tracked: self._failures[tracked][-1])
            del self._failures[stalest]
        self._failures.setdefault(key, deque(maxlen=self._max_failures)).append(now)
        return not was_locked and self.is_locked_out(key, now)

    def clear(self, key: K) -> None:
        """Forget a key's failures (a successful login)."""
        self._failures.pop(key, None)

    def _recent(self, key: K, now: datetime) -> deque[datetime]:
        recent = self._failures.get(key)
        if recent is None:
            return deque()
        cutoff = now - timedelta(seconds=self._window_seconds)
        while recent and recent[0] <= cutoff:
            recent.popleft()
        if not recent:
            del self._failures[key]
        return recent


class ScopedThrottle:
    """Several `FailureWindow`s over one window length, one per `LockoutScope`.

    `limits` names the scopes in use and each one's failure limit. Callers
    pass the per-attempt keys (`SOURCE` → client address, `ACCOUNT` → the
    username); `GLOBAL`, when limited, is counted internally over one shared
    key. A scope missing from `keys` is skipped for that attempt.
    """

    def __init__(
        self,
        limits: Mapping[LockoutScope, int],
        window_seconds: int,
        max_tracked_keys: int = 4096,
    ) -> None:
        self._windows: dict[LockoutScope, FailureWindow[Hashable]] = {
            scope: FailureWindow(limit, window_seconds, max_tracked_keys) for scope, limit in limits.items()
        }

    def lockout(self, keys: Mapping[LockoutScope, Hashable], now: datetime) -> Lockout | None:
        """The lockout refusing this attempt, or None. With several, the longest wait wins."""
        worst: Lockout | None = None
        for scope, key in self._keys(keys):
            wait = self._windows[scope].seconds_until_unlocked(key, now)
            if wait and (worst is None or wait > worst.retry_after_seconds):
                worst = Lockout(scope, wait)
        return worst

    def record_failure(
        self, keys: Mapping[LockoutScope, Hashable], now: datetime
    ) -> tuple[LockoutScope, ...]:
        """Record one failure in every scope. Returns the scopes this failure newly locked."""
        return tuple(
            scope for scope, key in self._keys(keys) if self._windows[scope].record_failure(key, now)
        )

    def clear(self, scope: LockoutScope, key: Hashable) -> None:
        """Forget one key's failures in one scope. The global count is never cleared by a success."""
        window = self._windows.get(scope)
        if window is not None and scope is not LockoutScope.GLOBAL:
            window.clear(key)

    def _keys(self, keys: Mapping[LockoutScope, Hashable]) -> list[tuple[LockoutScope, Hashable]]:
        pairs: list[tuple[LockoutScope, Hashable]] = [
            (scope, key)
            for scope, key in keys.items()
            if scope in self._windows and scope is not LockoutScope.GLOBAL
        ]
        if LockoutScope.GLOBAL in self._windows:
            pairs.append((LockoutScope.GLOBAL, _GLOBAL_KEY))
        return pairs

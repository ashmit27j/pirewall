"""`AdminLoginThrottle`: failed admin logins, limited per client IP and globally (PLAN_FINAL §4.9).

The control panel is reachable only from the Admin PC (spec §29), so a
per-IP limit alone would mostly protect that one address. The global limit
covers what per-IP cannot: a spoofed or rotated source, or a deployment
with `security.restrict_to_admin_pc = false`. The cost is stated once: a
global lockout also refuses the real admin's correct password until the
window lapses. The local console (ADDENDUM_3.md C6) is no way around it,
because it shares the same counter.

Failed password re-confirmations (`POST /api/v1/allowlist`) count as failed
logins, so a stolen session cookie cannot be used to guess the password.

FastAPI runs sync routes in a thread pool, so every method takes a lock.
"""

import logging
import threading
from datetime import datetime

from fastapi import HTTPException

from pirewall.config.models import AuthenticationConfig
from pirewall.core.enums import EventSeverity, SecurityEventType
from pirewall.core.models.event import SecurityEvent
from pirewall.core.throttle import Lockout, LockoutScope, ScopedThrottle
from pirewall.ipc.client import BaseRpcClient

_logger = logging.getLogger(__name__)
_SUBSYSTEM = "api.auth"

# A connection with no peer address (it never happens over TCP) still has
# to be counted, and never as the Admin PC.
_UNKNOWN_CLIENT = "unknown"


class AdminLoginThrottle:
    """Per-IP + global sliding-window limiter over failed admin authentications."""

    def __init__(self, config: AuthenticationConfig) -> None:
        self._lock = threading.Lock()
        self._throttle = ScopedThrottle(
            {
                LockoutScope.SOURCE: config.max_failed_logins_per_ip,
                LockoutScope.GLOBAL: config.max_failed_logins_global,
            },
            config.failed_login_window_seconds,
        )

    def lockout(self, client_host: str | None, now: datetime) -> Lockout | None:
        """The lockout refusing an attempt from `client_host`, or None."""
        with self._lock:
            return self._throttle.lockout({LockoutScope.SOURCE: _key(client_host)}, now)

    def record_failure(self, client_host: str | None, now: datetime) -> tuple[LockoutScope, ...]:
        """Record one failure. Returns the scopes this failure newly locked."""
        with self._lock:
            return self._throttle.record_failure({LockoutScope.SOURCE: _key(client_host)}, now)

    def clear(self, client_host: str | None) -> None:
        """Forget this client's failures after a success. The global count stays."""
        with self._lock:
            self._throttle.clear(LockoutScope.SOURCE, _key(client_host))


def _key(client_host: str | None) -> str:
    return client_host if client_host else _UNKNOWN_CLIENT


def refuse_if_locked_out(throttle: AdminLoginThrottle, client_host: str | None, now: datetime) -> None:
    """Raise 429 with `Retry-After` while `client_host` (or everyone) is locked out.

    Checked before any password is looked at, so a locked attempt costs no
    scrypt and tells the client nothing about the password. Refused attempts
    are logged here, not sent to core as events: the event is emitted once,
    when the lockout starts (`record_failed_authentication`), so a client
    hammering a locked endpoint cannot flood the bounded audit history.
    """
    lockout = throttle.lockout(client_host, now)
    if lockout is None:
        return
    _logger.warning(
        "admin authentication from %s refused: %s lockout, %ds remaining",
        client_host,
        lockout.scope.value,
        lockout.retry_after_seconds,
    )
    raise HTTPException(
        status_code=429,
        detail=f"too many failed attempts; try again in {lockout.retry_after_seconds} seconds",
        headers={"Retry-After": str(lockout.retry_after_seconds)},
    )


def record_failed_authentication(
    throttle: AdminLoginThrottle,
    rpc_client: BaseRpcClient,
    client_host: str | None,
    now: datetime,
    reason: str,
) -> None:
    """Count one failed admin authentication and report it to core's audit trail.

    Emits `AUTHENTICATION_FAILURE` for the failure itself and, when this
    failure starts a lockout, one more for each scope it locked.
    """
    newly_locked = throttle.record_failure(client_host, now)
    rpc_client.record_event(_failure_event(now, reason))
    for scope in newly_locked:
        lockout_reason = f"admin login lockout started ({scope.value}) after a failure from {client_host}"
        rpc_client.record_event(_failure_event(now, lockout_reason))


def _failure_event(now: datetime, reason: str) -> SecurityEvent:
    return SecurityEvent(
        timestamp=now,
        severity=EventSeverity.WARNING,
        event_type=SecurityEventType.AUTHENTICATION_FAILURE,
        subsystem=_SUBSYSTEM,
        reason=reason,
    )

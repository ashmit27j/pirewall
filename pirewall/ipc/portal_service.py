"""`PortalService`: the pirewall-core half of the captive portal (ADDENDUM_3.md C1-C4).

Lives under `pirewall.ipc` rather than `pirewall.portal` on purpose. This
module imports `pirewall.firewall.manager`, which the LAN-facing
pirewall-portal process must never load; keeping it here leaves
`pirewall/portal/` importing nothing but `pirewall.core` and
`pirewall.ipc.client`, which is what
`tests/security/test_api_process_isolation.py` asserts.

Everything that decides anything about a portal client happens here, in the
privileged process:

* credential verification, against the core-owned `PortalUserStore`
* session issue/expiry, in `PortalSessionRegistry`
* the nft `@authed` grant, via `FirewallManager` — the one authorized path
  to the backend (CLAUDE.md)
* the blocked-client answer (C4)

The portal process holds no state of its own and makes no decisions; it
renders what this returns. That is the same relationship pirewall-api has
with pirewall-core under ADDENDUM.md A4.
"""

import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import IPv4Address

from pirewall.config.models import PirewallConfig
from pirewall.core.enums import EventSeverity, SecurityEventType
from pirewall.core.exceptions import FirewallError
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.portal import (
    PortalClientState,
    PortalClientStatus,
    PortalSession,
    PortalUser,
)
from pirewall.core.passwords import generate_password
from pirewall.firewall.manager import FirewallManager
from pirewall.portal.sessions import LoginThrottle, PortalSessionRegistry
from pirewall.portal.store import PortalUserStore

_SESSION_TOKEN_BYTES = 32

_BLOCKED_MESSAGE = (
    "Malicious activity has been detected from this device and its network "
    "access has been suspended."
)


class PortalLoginError(Exception):
    """A login that failed for a reason the client is allowed to be told."""


class PortalService:
    """Portal logic, owned by pirewall-core. Not thread-safe on its own.

    `pirewall.runtime.core._SynchronizedDispatcher` already serializes every
    RPC call behind the daemon's shared lock, which is what makes that safe
    — the same arrangement `CoreRpcDispatcher` relies on.
    """

    def __init__(
        self,
        config: PirewallConfig,
        manager: FirewallManager,
        store: PortalUserStore,
        on_event: Callable[[SecurityEvent], None],
        now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._config = config
        self._manager = manager
        self._store = store
        self._on_event = on_event
        self._now_fn = now_fn
        self._sessions = PortalSessionRegistry(
            config.portal.session_timeout_seconds, max_sessions=config.portal.max_sessions
        )
        self._throttle = LoginThrottle(
            config.portal.max_failed_logins_per_ip, config.portal.failed_login_window_seconds
        )

    # ---------------------------------------------------------------- client

    def status(self) -> dict[str, object]:
        """What the login page needs before anyone has authenticated."""
        return {
            "enabled": self._config.portal.enabled,
            "demo_accounts_present": self._store.has_demo_accounts(),
            "contact_message": self._config.portal.contact_message,
            "session_timeout_seconds": self._config.portal.session_timeout_seconds,
            "keepalive_interval_seconds": self._config.portal.keepalive_interval_seconds,
        }

    def login(self, username: str, password: str, client_ip: IPv4Address) -> PortalSession:
        """Authenticate a LAN client and authorize its address for forwarding.

        Raises `PortalLoginError` for every user-visible failure, with a
        message that never distinguishes "no such user" from "wrong
        password" — the same discipline as `Authenticator.login`.
        """
        now = self._now_fn()

        if self._throttle.is_locked_out(client_ip, now):
            wait = self._throttle.seconds_until_unlocked(client_ip, now)
            self._emit(
                EventSeverity.WARNING,
                SecurityEventType.AUTHENTICATION_FAILURE,
                f"portal login throttled for {client_ip} ({wait}s remaining)",
            )
            raise PortalLoginError(f"Too many failed attempts. Try again in {wait} seconds.")

        # A device already blocked by the adaptive pipeline must not be able
        # to log its way back onto the network (ADDENDUM_3.md C4).
        if self._manager.restrictive_rules_matching(client_ip):
            raise PortalLoginError(_BLOCKED_MESSAGE + " " + self._config.portal.contact_message)

        if not self._store.verify(username, password):
            self._throttle.record_failure(client_ip, now)
            self._emit(
                EventSeverity.WARNING,
                SecurityEventType.AUTHENTICATION_FAILURE,
                f"portal login failed for username {username!r} from {client_ip}",
            )
            raise PortalLoginError("Invalid username or password.")

        token = secrets.token_urlsafe(_SESSION_TOKEN_BYTES)
        session = self._sessions.create(username, client_ip, token, now)
        try:
            self._manager.authorize_portal_client(
                client_ip, self._config.portal.session_timeout_seconds
            )
        except FirewallError as exc:
            # Never report a login as successful when the client is not
            # actually authorized to forward — that would leave them staring
            # at a countdown on a dead network (spec §46, labelling honesty).
            self._sessions.invalidate(token)
            self._emit(
                EventSeverity.ERROR,
                SecurityEventType.FIREWALL_ERROR,
                f"portal authorization failed for {client_ip}: {exc}",
            )
            raise PortalLoginError("Could not grant network access. Please try again.") from exc

        self._throttle.clear(client_ip)
        self._emit(
            EventSeverity.INFO,
            SecurityEventType.FIREWALL_ALLOW,
            f"portal login: {username!r} authorized {client_ip} "
            f"for {self._config.portal.session_timeout_seconds}s",
        )
        return session

    def keepalive(self, token: str | None, client_ip: IPv4Address) -> PortalClientState:
        """Answer one keepalive poll: authenticated, expired, blocked, or unknown.

        The blocked check runs first and unconditionally, including for a
        client with no valid token, because a blocked device needs the
        explanation more than an unauthenticated one needs the login page.
        """
        now = self._now_fn()

        if self._manager.restrictive_rules_matching(client_ip):
            # Revoke immediately rather than waiting for the session to
            # lapse: the adaptive rule and the portal grant disagree, and
            # the restrictive one wins. The client can still reach this
            # endpoint because adaptive rules sit on the `forward` hook
            # while the portal sits on `input` — which is the whole reason
            # a blocked device can be told anything at all (C4).
            self._revoke(client_ip, reason="blocked by an active firewall rule")
            return PortalClientState(
                status=PortalClientStatus.BLOCKED,
                client_ip=client_ip,
                message=f"{_BLOCKED_MESSAGE} {self._config.portal.contact_message}",
            )

        session = self._sessions.validate(token, client_ip, now) if token else None
        if session is None:
            # A token that no longer validates means the session ran out (or
            # was ended for them); no token at all means they never logged
            # in. The page says something different for each.
            if token:
                self._revoke(client_ip, reason="portal session expired")
                return PortalClientState(status=PortalClientStatus.EXPIRED, client_ip=client_ip)
            return PortalClientState(status=PortalClientStatus.UNAUTHENTICATED, client_ip=client_ip)

        remaining = int((session.expires_at - now).total_seconds())
        return PortalClientState(
            status=PortalClientStatus.AUTHENTICATED,
            username=session.username,
            client_ip=client_ip,
            seconds_remaining=max(0, remaining),
            expires_at=session.expires_at,
        )

    def logout(self, token: str, client_ip: IPv4Address) -> bool:
        """End a client's own session. Returns False if the token wasn't theirs."""
        now = self._now_fn()
        session = self._sessions.validate(token, client_ip, now)
        if session is None:
            return False
        self._sessions.invalidate(token)
        self._deauthorize(client_ip)
        self._emit(
            EventSeverity.INFO,
            SecurityEventType.FIREWALL_ALLOW,
            f"portal logout: {session.username!r} released {client_ip}",
        )
        return True

    # ----------------------------------------------------------------- admin

    def list_users(self) -> list[PortalUser]:
        return self._store.list_users()

    def add_user(
        self, username: str, password: str | None, created_by: str, note: str = ""
    ) -> tuple[PortalUser, str | None]:
        """Provision an account. Returns the user and, when generated, the plaintext password.

        The plaintext is returned exactly once, for the control panel to
        show the admin, and is never persisted — only its hash is.
        """
        generated = None if password else generate_password()
        user = self._store.add(
            username=username,
            password=password or generated or "",
            created_at=self._now_fn(),
            created_by=created_by,
            note=note,
        )
        self._emit(
            EventSeverity.INFO,
            SecurityEventType.SYSTEM_WARNING if user.is_demo else SecurityEventType.FIREWALL_ALLOW,
            f"portal user {username!r} created by {created_by!r}",
        )
        return user, generated

    def set_password(self, username: str, password: str | None) -> tuple[PortalUser, str | None]:
        """Rotate a password, generating one if not supplied. Ends that user's live sessions."""
        generated = None if password else generate_password()
        user = self._store.set_password(username, password or generated or "")
        self._end_sessions_for(username, reason="password changed")
        return user, generated

    def remove_user(self, username: str) -> bool:
        """Delete an account and immediately end any session it holds."""
        removed = self._store.remove(username)
        if removed:
            self._end_sessions_for(username, reason="account removed")
            self._emit(
                EventSeverity.INFO,
                SecurityEventType.SYSTEM_WARNING,
                f"portal user {username!r} removed",
            )
        return removed

    def list_sessions(self) -> list[PortalSession]:
        return self._sessions.list_sessions(self._now_fn())

    def force_logout(self, client_ip: IPv4Address) -> bool:
        """Admin-initiated disconnect of one client."""
        session = self._sessions.invalidate_ip(client_ip)
        self._deauthorize(client_ip)
        if session is not None:
            self._emit(
                EventSeverity.WARNING,
                SecurityEventType.SYSTEM_WARNING,
                f"portal session for {session.username!r} at {client_ip} ended by administrator",
            )
        return session is not None

    # -------------------------------------------------------------- internals

    def sweep(self) -> int:
        """Retire sessions the clock has passed. Returns how many were retired.

        The kernel drops the nft element on its own, so this exists to keep
        pirewall's *view* honest — the control panel should not list a
        session that stopped forwarding minutes ago. Called from the core
        daemon's existing sweep loop, not a thread of its own.
        """
        expired = self._sessions.purge_expired(self._now_fn())
        for session in expired:
            self._deauthorize(session.client_ip)
        return len(expired)

    def warn_about_demo_accounts(self) -> None:
        """Emit a startup warning while the documented demo credentials still exist."""
        if not self._store.has_demo_accounts():
            return
        demo = sorted(user.username for user in self._store.list_users() if user.is_demo)
        self._emit(
            EventSeverity.WARNING,
            SecurityEventType.SYSTEM_WARNING,
            f"portal demo accounts are still present ({', '.join(demo)}) — their passwords are "
            "published in docs/SETUP.md and must be removed before production use",
        )

    def _revoke(self, client_ip: IPv4Address, reason: str) -> None:
        session = self._sessions.invalidate_ip(client_ip)
        self._deauthorize(client_ip)
        if session is not None:
            self._emit(
                EventSeverity.WARNING,
                SecurityEventType.SYSTEM_WARNING,
                f"portal session for {session.username!r} at {client_ip} revoked: {reason}",
            )

    def _end_sessions_for(self, username: str, reason: str) -> None:
        for session in list(self._sessions.list_sessions(self._now_fn())):
            if session.username == username:
                self._sessions.invalidate(session.token)
                self._deauthorize(session.client_ip)
                self._emit(
                    EventSeverity.INFO,
                    SecurityEventType.SYSTEM_WARNING,
                    f"portal session for {username!r} at {session.client_ip} ended: {reason}",
                )

    def _deauthorize(self, client_ip: IPv4Address) -> None:
        """Drop a client's nft grant, tolerating a backend that is down (ADDENDUM.md A6)."""
        try:
            self._manager.deauthorize_portal_client(client_ip)
        except FirewallError as exc:
            self._emit(
                EventSeverity.ERROR,
                SecurityEventType.FIREWALL_ERROR,
                f"could not deauthorize portal client {client_ip}: {exc}",
            )

    def _emit(self, severity: EventSeverity, event_type: SecurityEventType, reason: str) -> None:
        self._on_event(
            SecurityEvent(
                timestamp=self._now_fn(),
                severity=severity,
                event_type=event_type,
                subsystem="portal",
                reason=reason,
            )
        )

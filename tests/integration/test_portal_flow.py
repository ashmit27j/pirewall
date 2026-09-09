"""End-to-end captive portal: sign in, keepalive, countdown, block, auto-logout.

Exercises the real `pirewall-portal` app against the real
`PortalRpcDispatcher` and `PortalService`, with only the firewall backend
and the clock faked — so the RPC envelope, the route handlers, the session
registry, and the nft-set grant are all the production code paths.
"""

import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from pirewall.config.models import PirewallConfig
from pirewall.core.enums import EnforcementMode, FirewallAction, RuleStatus, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.event import SecurityEvent
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.client import BaseRpcClient
from pirewall.ipc.portal_dispatcher import PortalRpcDispatcher
from pirewall.ipc.portal_service import PortalService
from pirewall.ipc.protocol import RpcOperation, RpcRequest, RpcResponse
from pirewall.portal.app import create_app
from pirewall.portal.store import PortalUserStore
from tests.helpers.api import Response
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate

SESSION_SECONDS = 60
PASSWORD = "correct-horse-battery"
# A plausible remote peer, outside the protected network.
REMOTE_HOST = "203.0.113.9/32"


class _DirectRpcClient(BaseRpcClient):
    """Speaks the real RPC envelope straight to the dispatcher, skipping only the socket."""

    def __init__(self, dispatcher: PortalRpcDispatcher) -> None:
        self._dispatcher = dispatcher

    def _call(
        self, operation: RpcOperation, params: dict[str, Any] | None = None
    ) -> RpcResponse:
        return self._dispatcher.handle(RpcRequest(operation=operation, params=params or {}))


class Harness:
    """Everything a portal test needs, with a clock it can move."""

    def __init__(
        self,
        backend: FakeFirewallBackend | None = None,
        store: PortalUserStore | None = None,
        now: datetime | None = None,
        client_ip: IPv4Address | None = None,
    ) -> None:
        self.now = now or datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
        self.config = _portal_config()
        self.client_ip = client_ip or list(self.config.network.protected_network.hosts())[9]
        # Injectable so `restart_core` can carry the kernel set and the user
        # store across a simulated restart while everything in memory is lost.
        self.backend = backend or FakeFirewallBackend()
        self.backend.set_clock(self.now)
        self.manager = FirewallManager(self.config, self.backend)
        self.store = store or PortalUserStore(Path(tempfile.mkdtemp()) / "users.json")
        if self.store.get("alice") is None:
            self.store.add("alice", PASSWORD, self.now, "admin")
        self.events: list[SecurityEvent] = []
        self.service = PortalService(
            self.config,
            self.manager,
            self.store,
            on_event=self.events.append,
            now_fn=lambda: self.now,
        )
        self._client = TestClient(
            create_app(self.config, _DirectRpcClient(PortalRpcDispatcher(self.service))),
            client=(str(self.client_ip), 51234),
        )

    # `Response` and these two wrappers exist for the reason
    # `tests/helpers/api.py` documents: `TestClient` overrides `httpx.Client`
    # in a way pyright cannot fully resolve under strict mode, so raw member
    # access on it comes back partially Unknown. Isolate it in one place.
    def get(self, url: str, **kwargs: Any) -> Response:
        return Response(self._client.get(url, **kwargs))  # pyright: ignore[reportUnknownMemberType]

    def post(self, url: str, **kwargs: Any) -> Response:
        return Response(self._client.post(url, **kwargs))  # pyright: ignore[reportUnknownMemberType]

    def headers_of(self, response: Response) -> dict[str, str]:
        return response.headers

    def restart_core(self) -> "Harness":
        """Rebuild the core-side service exactly as a pirewall-core restart would.

        Sessions are in-memory so they are lost; the backend (standing in for
        the kernel) keeps its set, because nftables outlives the process.
        That asymmetry is the whole point of the test.
        """
        restarted = Harness(
            backend=self.backend, store=self.store, now=self.now, client_ip=self.client_ip
        )
        restarted.service.reconcile()  # what CoreDaemon.start() does
        return restarted

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)
        self.backend.set_clock(self.now)

    def sign_in(self, username: str = "alice", password: str = PASSWORD) -> Response:
        return self.post(
            "/portal/login",
            data={"username": username, "password": password},
            follow_redirects=False,
        )

    def authorized(self) -> frozenset[IPv4Address]:
        return self.backend.list_portal_clients()

    def block(self, reason: str = "port scan detected") -> None:
        """Block this client through the real validated pipeline, as detection would.

        Deploying through `register_decision` + `submit_candidate` rather
        than writing to the manager's rule table means these tests only ever
        see rule shapes the §24 validation chain actually permits.
        """
        candidate = make_candidate(
            action=FirewallAction.BLOCK,
            source=f"{self.client_ip}/32",
            destination=REMOTE_HOST,
            reason=reason,
            threat_score=95.0,
            created_at=self.now,
            expires_at=self.now + timedelta(hours=1),
        )
        self.manager.register_decision(
            FirewallDecision(
                id=candidate.decision_id,
                threat_assessment_id="assessment-1",
                flow_id="flow-1",
                action=candidate.action,
                threat_score=95.0,
                threat_level=ThreatLevel.CRITICAL,
                reason=reason,
                decided_at=self.now,
            )
        )
        result = self.manager.submit_candidate(candidate, self.now)
        assert result.rule is not None and result.rule.status is RuleStatus.ACTIVE


def _portal_config() -> PirewallConfig:
    config = make_config()
    return config.model_copy(
        update={
            "portal": config.portal.model_copy(
                update={
                    "enabled": True,
                    "session_timeout_seconds": SESSION_SECONDS,
                    "keepalive_interval_seconds": 5,
                    "network_name": "pirewall-lan",
                    "max_failed_logins_per_ip": 3,
                }
            ),
            # ACTIVE so a submitted candidate really deploys — the portal's
            # block notice is about rules that actually took effect.
            "firewall": config.firewall.model_copy(
                update={"enforcement_mode": EnforcementMode.ACTIVE}
            ),
        }
    )


@pytest.fixture
def harness() -> Iterator[Harness]:
    yield Harness()


# ------------------------------------------------------------ the happy path


def test_an_unauthenticated_client_is_shown_the_sign_in_page(harness: Harness) -> None:
    response = harness.get("/portal")
    assert response.status_code == 200
    assert "Sign in to pirewall-lan" in response.text
    assert harness.authorized() == frozenset(), "nothing is authorized before signing in"


def test_signing_in_authorizes_the_client_in_the_nft_set(harness: Harness) -> None:
    """The set element *is* the authorization — a session that did not grant one is a lie."""
    response = harness.sign_in()
    assert response.status_code == 303
    assert response.headers["location"] == "/portal/connected"
    assert harness.authorized() == frozenset({harness.client_ip})


def test_the_keepalive_page_shows_the_user_and_a_countdown(harness: Harness) -> None:
    harness.sign_in()
    page = harness.get("/portal/connected")
    assert page.status_code == 200
    assert "Authentication keepalive active" in page.text
    assert "alice" in page.text
    assert "until automatic sign-out" in page.text


def test_the_countdown_is_computed_server_side_on_every_poll(harness: Harness) -> None:
    """A client cannot extend its own session by holding a stopped clock."""
    harness.sign_in()
    assert harness.get("/portal/api/keepalive").json()["seconds_remaining"] == SESSION_SECONDS
    harness.advance(25)
    assert harness.get("/portal/api/keepalive").json()["seconds_remaining"] == SESSION_SECONDS - 25


def test_signing_out_releases_the_authorization(harness: Harness) -> None:
    harness.sign_in()
    assert harness.authorized() == frozenset({harness.client_ip})
    response = harness.post("/portal/logout", follow_redirects=False)
    assert response.status_code == 303
    assert harness.authorized() == frozenset()


# ----------------------------------------------------------------- expiry


def test_an_expired_session_reports_expired_and_loses_its_authorization(harness: Harness) -> None:
    harness.sign_in()
    harness.advance(SESSION_SECONDS + 1)
    assert harness.get("/portal/api/keepalive").json()["status"] == "expired"
    assert harness.authorized() == frozenset()


def test_the_kernel_expires_the_element_without_being_told(harness: Harness) -> None:
    """ADDENDUM_3.md C2: auto-logout costs nothing because nft does it.

    The fake models the real set's behaviour — the element lapses on its own
    timeout, with no call from pirewall to remove it.
    """
    harness.sign_in()
    assert harness.backend.portal_deauthorize_calls == 0
    harness.advance(SESSION_SECONDS + 1)
    assert harness.authorized() == frozenset(), "the element should have expired in the kernel"


def test_the_connected_page_sends_an_expired_client_back_to_sign_in(harness: Harness) -> None:
    harness.sign_in()
    harness.advance(SESSION_SECONDS + 1)
    response = harness.get("/portal/connected", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/portal"


# ---------------------------------------------------------------- blocked


def test_a_blocked_client_is_told_why_on_its_next_poll(harness: Harness) -> None:
    """ADDENDUM_3.md C4 — the whole point of the portal's presence on the input hook."""
    harness.sign_in()
    harness.block()
    state = harness.get("/portal/api/keepalive").json()
    assert state["status"] == "blocked"
    assert "Malicious activity has been detected" in state["message"]
    assert "contact your network administrator" in state["message"].lower()


def test_being_blocked_revokes_the_authorization_immediately(harness: Harness) -> None:
    """The adaptive rule and the portal grant disagree; the restrictive one wins."""
    harness.sign_in()
    assert harness.authorized() == frozenset({harness.client_ip})
    harness.block()
    harness.get("/portal/api/keepalive")
    assert harness.authorized() == frozenset()


def test_a_blocked_client_can_still_reach_the_portal_to_be_told(harness: Harness) -> None:
    harness.sign_in()
    harness.block()
    page = harness.get("/portal/connected")
    assert page.status_code == 403
    assert "Network access suspended" in page.text


def test_a_blocked_client_cannot_sign_back_in(harness: Harness) -> None:
    """Otherwise a device could log its way out of an adaptive block."""
    harness.block()
    response = harness.sign_in()
    assert response.status_code == 401
    assert "Malicious activity" in response.text
    assert harness.authorized() == frozenset()


def test_a_blocked_client_with_no_session_is_still_told(harness: Harness) -> None:
    """The explanation matters more than the login page for a device in this state."""
    harness.block()
    assert harness.get("/portal/api/keepalive").json()["status"] == "blocked"


# ------------------------------------------------------------ credentials


def test_a_wrong_password_authorizes_nothing(harness: Harness) -> None:
    response = harness.sign_in(password="wrong")
    assert response.status_code == 401
    assert "Invalid username or password" in response.text
    assert harness.authorized() == frozenset()


def test_the_error_does_not_reveal_whether_the_username_exists(harness: Harness) -> None:
    wrong_password = harness.sign_in(username="alice", password="wrong")
    unknown_user = harness.sign_in(username="mallory", password="wrong")
    assert "Invalid username or password" in wrong_password.text
    assert "Invalid username or password" in unknown_user.text


def test_repeated_failures_are_throttled(harness: Harness) -> None:
    """Online guessing against a LAN-reachable login is cheap; scrypt alone only slows it."""
    for _ in range(3):
        harness.sign_in(password="wrong")
    response = harness.sign_in(password=PASSWORD)
    assert response.status_code == 401
    assert "Too many failed attempts" in response.text
    assert harness.authorized() == frozenset(), "throttling must hold even for the right password"


def test_throttling_lapses_and_the_right_password_then_works(harness: Harness) -> None:
    for _ in range(3):
        harness.sign_in(password="wrong")
    harness.advance(harness.config.portal.failed_login_window_seconds + 1)
    assert harness.sign_in().status_code == 303
    assert harness.authorized() == frozenset({harness.client_ip})


# ------------------------------------------------------- captive detection


@pytest.mark.parametrize(
    "path",
    ["/generate_204", "/hotspot-detect.html", "/connecttest.txt", "/ncsi.txt", "/canonical.html", "/"],
)
def test_os_captive_probes_redirect_to_the_portal(harness: Harness, path: str) -> None:
    """This is what makes the sign-in sheet appear by itself."""
    response = harness.get(path, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/portal"


def test_an_arbitrary_url_also_lands_on_the_portal(harness: Harness) -> None:
    """The nat chain redirects every port-80 request here, whatever was asked for."""
    response = harness.get("/some/deep/path?q=1", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/portal"


# ------------------------------------------------------------------ misc


def test_a_demo_account_raises_a_banner_on_the_sign_in_page(harness: Harness) -> None:
    harness.store.add("demo-alice", "pirewall-demo-1", harness.now, "seed", is_demo=True)
    assert "Demo accounts are active" in harness.get("/portal").text


def test_no_banner_once_the_demo_accounts_are_gone(harness: Harness) -> None:
    assert "Demo accounts are active" not in harness.get("/portal").text


def test_a_failed_login_is_recorded_in_the_audit_trail(harness: Harness) -> None:
    harness.sign_in(password="wrong")
    reasons = [event.reason for event in harness.events]
    assert any("portal login failed" in (reason or "") for reason in reasons)


def test_a_failed_grant_does_not_report_a_successful_login(harness: Harness) -> None:
    """Reporting success while the client cannot forward would be a countdown on a dead network."""
    harness.backend.fail_on_portal = True
    response = harness.sign_in()
    assert response.status_code == 401
    assert "Could not grant network access" in response.text
    assert harness.get("/portal/api/keepalive").json()["status"] == "unauthenticated"


# ------------------------------------------- kernel set / session reconciliation
#
# Regression tests for two divergences observed on real hardware. Both leave
# an address forwarding that nothing in pirewall believes is signed in, which
# is the one direction of drift that matters: the client keeps network access
# while being shown a login page.


def test_a_restart_does_not_leave_a_client_authorized(harness: Harness) -> None:
    """pirewall-core restarting must revoke every grant, not orphan it.

    Sessions live in memory and grants live in the kernel. After a restart
    the registry is empty and the set is not, so every surviving element
    would forward for up to a full session length with nothing behind it —
    observed on this Pi, triggered by the bring-up script's own core restart.
    """
    harness.sign_in()
    assert harness.authorized() == frozenset({harness.client_ip})

    restarted = harness.restart_core()

    assert restarted.authorized() == frozenset(), (
        "a grant survived a restart with no session behind it"
    )
    assert restarted.get("/portal/api/keepalive").json()["status"] == "unauthenticated"


def test_reconcile_revokes_a_grant_with_no_session(harness: Harness) -> None:
    """The invariant, asserted directly: an address in `@authed` has a live session.

    Reproduces the other observed divergence — a login round-trip that timed
    out *after* core authorized the client, so core and the kernel agreed
    while the user was told their password was wrong and held no session.
    """
    harness.manager.authorize_portal_client(harness.client_ip, 1800)
    assert harness.authorized() == frozenset({harness.client_ip})

    assert harness.service.reconcile() == 1
    assert harness.authorized() == frozenset()


def test_reconcile_leaves_a_legitimate_session_alone(harness: Harness) -> None:
    """It must not log out the people who are actually signed in."""
    harness.sign_in()
    assert harness.service.reconcile() == 0
    assert harness.authorized() == frozenset({harness.client_ip})
    assert harness.get("/portal/api/keepalive").json()["status"] == "authenticated"


def test_reconcile_reports_the_revocation(harness: Harness) -> None:
    """Silently revoking would make a confusing failure impossible to diagnose."""
    harness.manager.authorize_portal_client(harness.client_ip, 1800)
    harness.events.clear()
    harness.service.reconcile()
    reasons = [event.reason or "" for event in harness.events]
    assert any("orphaned portal authorization" in reason for reason in reasons)


def test_the_sweep_reconciles_too(harness: Harness) -> None:
    """So the orphan window is bounded by the sweep interval, not the session length."""
    harness.manager.authorize_portal_client(harness.client_ip, 1800)
    assert harness.service.sweep() >= 1
    assert harness.authorized() == frozenset()

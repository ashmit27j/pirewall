"""Admin-side portal routes, allowlist provisioning, and the local-console exemption.

Covers the pirewall-api half of ADDENDUM_3.md: C3 (provisioning an account
alongside an allowlist entry) and C6 (letting an operator at the Pi's own
desktop reach the control panel without widening access to a routable
address).
"""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from pirewall.api.auth import enforce_admin_pc_ip
from pirewall.core.exceptions import AuthenticationError
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.portal_service import PortalService
from pirewall.ipc.protocol import RpcOperation, RpcRequest, RpcResponse
from pirewall.ipc.state import CoreStateStore
from pirewall.portal.store import PortalUserStore
from tests.helpers.config import make_config

ADMIN_PC = "192.168.1.100"
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


# ------------------------------------------------- C6: local console access


def test_the_admin_pc_is_always_permitted() -> None:
    enforce_admin_pc_ip(ADMIN_PC, ADMIN_PC, restrict=True)


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.53", "::1"])
def test_loopback_is_permitted_only_when_the_console_exemption_is_on(host: str) -> None:
    with pytest.raises(AuthenticationError):
        enforce_admin_pc_ip(host, ADMIN_PC, restrict=True)
    enforce_admin_pc_ip(host, ADMIN_PC, restrict=True, allow_local_console=True)


@pytest.mark.parametrize("host", ["192.168.1.101", "10.0.0.1", "0.0.0.0", "localhost", "127.0.0.1.evil"])
def test_the_exemption_never_admits_a_non_loopback_or_unparseable_host(host: str) -> None:
    """It must be loopback *addresses* only — never a hostname, never a routable address.

    `localhost` matters specifically: it resolves to loopback but is not an
    address, and treating it as one would let a Host/header-derived value
    through if this function were ever fed something other than a peer IP.
    """
    with pytest.raises(AuthenticationError):
        enforce_admin_pc_ip(host, ADMIN_PC, restrict=True, allow_local_console=True)


def test_a_missing_client_host_is_refused_even_with_the_exemption_on() -> None:
    """Fails closed: no connection info is untrusted, not "probably local"."""
    with pytest.raises(AuthenticationError):
        enforce_admin_pc_ip(None, ADMIN_PC, restrict=True, allow_local_console=True)


def test_the_exemption_defaults_to_off() -> None:
    """A deployment gets local-console access only by asking for it in config."""
    assert make_config().admin.allow_local_console is False


# ------------------------------------- C3: allowlist -> portal provisioning


class _Fixture:
    def __init__(self, portal_enabled: bool = True) -> None:
        config = make_config()
        self.config = config.model_copy(
            update={"portal": config.portal.model_copy(update={"enabled": portal_enabled})}
        )
        self.manager = FirewallManager(self.config, FakeFirewallBackend())
        self.store = PortalUserStore(Path(tempfile.mkdtemp()) / "users.json")
        self.service = (
            PortalService(
                self.config, self.manager, self.store, on_event=lambda _e: None, now_fn=lambda: NOW
            )
            if portal_enabled
            else None
        )
        state = CoreStateStore(started_at=NOW, max_history=50)
        self.dispatcher = CoreRpcDispatcher(state, self.manager, self.config, portal=self.service)

    def call(self, operation: RpcOperation, params: dict[str, Any] | None = None) -> RpcResponse:
        return self.dispatcher.handle(RpcRequest(operation=operation, params=params or {}))

    def entry_params(self, **overrides: Any) -> dict[str, Any]:
        params: dict[str, Any] = {
            "target": "192.168.1.77/32",
            "reason": "printer",
            "created_at": NOW.isoformat(),
            "created_by": "admin",
        }
        params.update(overrides)
        return params


def test_an_allowlist_entry_without_a_username_provisions_nothing() -> None:
    """CIDR-only entries must stay possible — a gateway or printer cannot sign in."""
    fixture = _Fixture()
    response = fixture.call(RpcOperation.ADD_ALLOWLIST_ENTRY, fixture.entry_params())
    assert response.ok is True
    assert "portal_password" not in response.data
    assert fixture.store.list_users() == []
    assert len(fixture.manager.allowlist) == 1


def test_supplying_a_username_provisions_an_account_and_returns_its_password_once() -> None:
    fixture = _Fixture()
    response = fixture.call(
        RpcOperation.ADD_ALLOWLIST_ENTRY, fixture.entry_params(portal_username="dana")
    )
    assert response.ok is True
    password = response.data["portal_password"]
    assert response.data["portal_username"] == "dana"
    assert password, "a generated password must be returned"
    assert fixture.store.verify("dana", password) is True
    assert len(fixture.manager.allowlist) == 1


def test_the_generated_password_is_never_written_to_the_store_in_the_clear() -> None:
    fixture = _Fixture()
    response = fixture.call(
        RpcOperation.ADD_ALLOWLIST_ENTRY, fixture.entry_params(portal_username="dana")
    )
    password = response.data["portal_password"]
    assert password not in fixture.store.path.read_text(encoding="utf-8")


def test_provisioning_is_refused_when_the_portal_is_disabled() -> None:
    """Silently dropping the username would leave an account the admin thinks exists."""
    fixture = _Fixture(portal_enabled=False)
    response = fixture.call(
        RpcOperation.ADD_ALLOWLIST_ENTRY, fixture.entry_params(portal_username="dana")
    )
    assert response.ok is False
    assert "captive portal is disabled" in (response.error or "")


def test_the_username_never_reaches_allowlist_entry_validation() -> None:
    """`AllowlistEntry` forbids extra fields, so a leaked key would reject the whole entry."""
    fixture = _Fixture()
    params = fixture.entry_params(portal_username="dana")
    response = fixture.call(RpcOperation.ADD_ALLOWLIST_ENTRY, params)
    assert response.ok is True
    # The caller's dict is not mutated out from under them.
    assert params["portal_username"] == "dana"


# ------------------------------------------------- admin portal operations


def test_admin_operations_manage_accounts_and_sessions() -> None:
    fixture = _Fixture()
    created = fixture.call(
        RpcOperation.PORTAL_ADD_USER, {"username": "erin", "created_by": "admin", "note": "phone"}
    )
    assert created.ok is True
    password = created.data["generated_password"]
    assert fixture.store.verify("erin", password) is True

    listed = fixture.call(RpcOperation.PORTAL_LIST_USERS)
    assert [user["username"] for user in listed.data] == ["erin"]

    rotated = fixture.call(RpcOperation.PORTAL_SET_PASSWORD, {"username": "erin"})
    assert rotated.ok is True
    assert fixture.store.verify("erin", rotated.data["generated_password"]) is True
    assert fixture.store.verify("erin", password) is False, "the old password must stop working"

    removed = fixture.call(RpcOperation.PORTAL_REMOVE_USER, {"username": "erin"})
    assert removed.data is True
    assert fixture.store.list_users() == []


def test_removing_an_absent_user_is_reported_not_faked() -> None:
    fixture = _Fixture()
    assert fixture.call(RpcOperation.PORTAL_REMOVE_USER, {"username": "ghost"}).data is False


def test_force_logout_rejects_a_malformed_address() -> None:
    fixture = _Fixture()
    response = fixture.call(RpcOperation.PORTAL_FORCE_LOGOUT, {"client_ip": "not-an-ip"})
    assert response.ok is False
    assert "invalid client_ip" in (response.error or "")


def test_removing_a_user_ends_their_live_session() -> None:
    """An account that no longer exists must not keep forwarding."""
    fixture = _Fixture()
    client_ip = list(fixture.config.network.protected_network.hosts())[9]
    fixture.call(RpcOperation.PORTAL_ADD_USER, {"username": "erin", "created_by": "admin", "password": "pw"})
    service = fixture.service
    assert service is not None
    service.login("erin", "pw", client_ip)
    assert fixture.manager.authorized_portal_clients() == frozenset({client_ip})
    fixture.call(RpcOperation.PORTAL_REMOVE_USER, {"username": "erin"})
    assert service.list_sessions() == []
    assert fixture.manager.authorized_portal_clients() == frozenset()

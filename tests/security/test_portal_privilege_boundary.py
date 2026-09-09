"""The portal RPC surface cannot reach a privileged operation (ADDENDUM_3.md C1).

pirewall-portal is the process untrusted LAN clients talk to. If it could
call pirewall-core's ordinary RPC surface it would hold the kill switch, the
allowlist, and every rule mutation — a privilege escalation, and a
regression against the reasoning ADDENDUM.md A4 spent a process boundary on.

The restriction is structural: `PortalRpcDispatcher` has its own handler
table, so there is no privileged handler present to reach. These tests
assert that directly rather than probing behaviour, because a filtered view
over `CoreRpcDispatcher` would be one missing branch away from full access
and would still pass a behavioural test written the obvious way.
"""

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pirewall.config.models import PirewallConfig
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.portal_dispatcher import PortalRpcDispatcher
from pirewall.ipc.portal_service import PortalService
from pirewall.ipc.protocol import RpcOperation, RpcRequest
from pirewall.ipc.state import CoreStateStore
from pirewall.portal.store import PortalUserStore
from tests.helpers.config import make_config

# Everything a compromised portal process must not be able to do.
_PRIVILEGED_OPERATIONS = frozenset(
    {
        RpcOperation.KILL_SWITCH,
        RpcOperation.ADD_ALLOWLIST_ENTRY,
        RpcOperation.REMOVE_ALLOWLIST_ENTRY,
        RpcOperation.LIST_ALLOWLIST,
        RpcOperation.DISABLE_RULE,
        RpcOperation.REMOVE_RULE,
        RpcOperation.APPROVE_RULE,
        RpcOperation.REJECT_RULE,
        RpcOperation.RECORD_EVENT,
        RpcOperation.LIST_RULES,
        RpcOperation.LIST_FLOWS,
        RpcOperation.GET_STATUS,
        RpcOperation.PORTAL_LIST_USERS,
        RpcOperation.PORTAL_ADD_USER,
        RpcOperation.PORTAL_REMOVE_USER,
        RpcOperation.PORTAL_SET_PASSWORD,
        RpcOperation.PORTAL_LIST_SESSIONS,
        RpcOperation.PORTAL_FORCE_LOGOUT,
    }
)

_ALLOWED_PORTAL_OPERATIONS = frozenset(
    {
        RpcOperation.PORTAL_STATUS,
        RpcOperation.PORTAL_LOGIN,
        RpcOperation.PORTAL_KEEPALIVE,
        RpcOperation.PORTAL_LOGOUT,
    }
)


@pytest.fixture
def portal_dispatcher() -> PortalRpcDispatcher:
    config = _portal_config()
    backend = FakeFirewallBackend()
    manager = FirewallManager(config, backend)
    store = PortalUserStore(Path(tempfile.mkdtemp()) / "users.json")
    service = PortalService(config, manager, store, on_event=lambda _event: None)
    return PortalRpcDispatcher(service)


def _portal_config() -> PirewallConfig:
    config = make_config()
    return config.model_copy(update={"portal": config.portal.model_copy(update={"enabled": True})})


def _handler_keys(
    dispatcher_class: type[PortalRpcDispatcher] | type[CoreRpcDispatcher],
) -> set[RpcOperation]:
    """The dispatcher's handler table.

    Reaching for a private attribute is the point here: the handler table
    *is* the privilege boundary (ADDENDUM_3.md C1), so asserting on it
    directly is stronger than probing behaviour — a filtered view over
    the core dispatcher would pass a behavioural test while being one
    missing branch away from full access.
    """
    return set(dispatcher_class._HANDLERS)  # pyright: ignore[reportPrivateUsage]


def test_portal_dispatcher_exposes_exactly_the_four_client_operations() -> None:
    """The handler table is the security boundary, so pin it exactly."""
    assert _handler_keys(PortalRpcDispatcher) == _ALLOWED_PORTAL_OPERATIONS


def test_portal_dispatcher_has_no_privileged_handler_at_all() -> None:
    """Not "rejects them" — has no handler to reach in the first place."""
    present = _handler_keys(PortalRpcDispatcher) & _PRIVILEGED_OPERATIONS
    assert present == frozenset(), f"portal dispatcher implements privileged operations: {present}"


@pytest.mark.parametrize("operation", sorted(_PRIVILEGED_OPERATIONS))
def test_every_privileged_operation_is_refused_over_the_portal_socket(
    portal_dispatcher: PortalRpcDispatcher, operation: RpcOperation
) -> None:
    """Behavioural counterpart: each privileged call is refused, and nothing happens."""
    response = portal_dispatcher.handle(RpcRequest(operation=operation, params={}))
    assert response.ok is False
    assert response.data is None
    assert "unknown operation" in (response.error or "")


def test_portal_dispatcher_is_not_a_core_dispatcher() -> None:
    """A shared base class would let a future handler be inherited into the portal surface."""
    assert not issubclass(PortalRpcDispatcher, CoreRpcDispatcher)


def test_refusal_does_not_disclose_which_privileged_operations_exist(
    portal_dispatcher: PortalRpcDispatcher,
) -> None:
    """A portal-side error must read the same for "privileged" as for "nonsense".

    Otherwise the error text is an enumeration oracle for the privileged
    surface, which is exactly what an attacker who has just taken the portal
    process wants next.
    """
    privileged = portal_dispatcher.handle(RpcRequest(operation=RpcOperation.KILL_SWITCH, params={}))
    unrelated = portal_dispatcher.handle(RpcRequest(operation=RpcOperation.LIST_FLOWS, params={}))
    assert privileged.error == "unknown operation: kill_switch"
    assert unrelated.error == "unknown operation: list_flows"


def test_core_dispatcher_still_serves_the_admin_portal_operations() -> None:
    """The admin side keeps them — the split is about *which socket*, not about removing them."""
    handlers = _handler_keys(CoreRpcDispatcher)
    assert RpcOperation.PORTAL_LIST_USERS in handlers
    assert RpcOperation.PORTAL_FORCE_LOGOUT in handlers
    # ...and the core dispatcher deliberately does *not* serve the
    # client-facing four: those exist only behind the portal socket.
    assert not (handlers & _ALLOWED_PORTAL_OPERATIONS)


def test_admin_portal_operations_report_cleanly_when_the_portal_is_disabled() -> None:
    """A disabled portal is a configuration state, not an internal error."""
    config = make_config()
    assert config.portal.enabled is False
    state = CoreStateStore(started_at=datetime.now(UTC), max_history=10)
    manager = FirewallManager(config, FakeFirewallBackend())
    dispatcher = CoreRpcDispatcher(state, manager, config)
    response = dispatcher.handle(RpcRequest(operation=RpcOperation.PORTAL_LIST_USERS, params={}))
    assert response.ok is False
    assert "captive portal is disabled" in (response.error or "")

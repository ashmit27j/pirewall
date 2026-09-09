"""The portal's own `AF_UNIX` socket, separate from pirewall-core's (ADDENDUM_3.md C1).

The security property being tested is not "the portal can sign people in" —
it is that the socket the LAN-facing process reaches serves a dispatcher
with no privileged operation on it, over the real transport, with the real
JSON envelope. A test that only exercised `PortalRpcDispatcher` in-process
would not catch a wiring mistake that pointed pirewall-portal at
`core.sock`.
"""

import socket
import stat
import tempfile
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.client import UnixSocketRpcClient
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.portal_dispatcher import PortalRpcDispatcher
from pirewall.ipc.portal_service import PortalService
from pirewall.ipc.protocol import RpcOperation, RpcResponse
from pirewall.ipc.server import UnixSocketRpcServer
from pirewall.ipc.state import CoreStateStore
from pirewall.portal.store import PortalUserStore
from tests.helpers.config import make_config

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="platform has no AF_UNIX support"
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
PASSWORD = "correct-horse-battery"
_JOIN_TIMEOUT_SECONDS = 5.0


def _portal_config(tmp: Path):  # type: ignore[no-untyped-def]
    config = make_config()
    return config.model_copy(
        update={
            "portal": config.portal.model_copy(
                update={
                    "enabled": True,
                    "user_store_path": str(tmp / "users.json"),
                    "rpc_socket_path": str(tmp / "portal.sock"),
                }
            ),
            "api": config.api.model_copy(update={"rpc_socket_path": str(tmp / "core.sock")}),
        }
    )


class _Servers:
    """Both sockets, served the way `CoreDaemon` serves them."""

    def __init__(self, tmp: Path) -> None:
        self.config = _portal_config(tmp)
        self.client_ip = list(self.config.network.protected_network.hosts())[9]
        self.manager = FirewallManager(self.config, FakeFirewallBackend())
        self.store = PortalUserStore(self.config.portal.user_store_path)
        self.store.add("alice", PASSWORD, NOW, "admin")
        self.service = PortalService(
            self.config, self.manager, self.store, on_event=lambda _e: None, now_fn=lambda: NOW
        )
        state = CoreStateStore(started_at=NOW, max_history=50)
        self.core_server = UnixSocketRpcServer(
            self.config.api.rpc_socket_path,
            CoreRpcDispatcher(state, self.manager, self.config, portal=self.service),
        )
        self.portal_server = UnixSocketRpcServer(
            self.config.portal.rpc_socket_path, PortalRpcDispatcher(self.service)
        )

    def start(self) -> None:
        self.core_server.start()
        self.portal_server.start()

    def stop(self) -> None:
        self.core_server.stop()
        self.portal_server.stop()

    def serve_one_on(self, server: UnixSocketRpcServer) -> threading.Thread:
        thread = threading.Thread(target=server.serve_one, daemon=True)
        thread.start()
        return thread


@pytest.fixture
def servers() -> Iterator[_Servers]:
    tmp = Path(tempfile.mkdtemp())
    instance = _Servers(tmp)
    instance.start()
    try:
        yield instance
    finally:
        instance.stop()


def _round_trip(
    servers: _Servers,
    server: UnixSocketRpcServer,
    path: str,
    operation: RpcOperation,
    params: dict[str, object],
) -> RpcResponse:
    thread = servers.serve_one_on(server)
    try:
        # `_call` is the single funnel every typed method on
        # `BaseRpcClient` goes through, and these tests are about the
        # transport and the dispatcher surface rather than any one typed
        # method — several of the operations under test have no typed
        # method on the portal client at all, by design.
        client = UnixSocketRpcClient(path)
        return client._call(operation, params)  # pyright: ignore[reportPrivateUsage]
    finally:
        thread.join(timeout=_JOIN_TIMEOUT_SECONDS)


def test_the_two_sockets_are_distinct_files(servers: _Servers) -> None:
    assert servers.config.portal.rpc_socket_path != servers.config.api.rpc_socket_path
    assert Path(servers.config.portal.rpc_socket_path).exists()
    assert Path(servers.config.api.rpc_socket_path).exists()


def test_the_portal_socket_is_not_world_connectable(servers: _Servers) -> None:
    """Same reasoning as core.sock: the umask must not decide who can reach this."""
    mode = stat.S_IMODE(Path(servers.config.portal.rpc_socket_path).stat().st_mode)
    assert mode & stat.S_IRWXO == 0, f"portal socket is reachable by other users: {oct(mode)}"


def test_a_login_works_over_the_real_portal_socket(servers: _Servers) -> None:
    response = _round_trip(
        servers,
        servers.portal_server,
        servers.config.portal.rpc_socket_path,
        RpcOperation.PORTAL_LOGIN,
        {"username": "alice", "password": PASSWORD, "client_ip": str(servers.client_ip)},
    )
    assert response.ok is True
    assert response.data["username"] == "alice"
    assert servers.manager.authorized_portal_clients() == frozenset({servers.client_ip})


def test_the_kill_switch_is_unreachable_over_the_portal_socket(servers: _Servers) -> None:
    """The point of the second socket, asserted over the wire rather than in-process."""
    response = _round_trip(
        servers,
        servers.portal_server,
        servers.config.portal.rpc_socket_path,
        RpcOperation.KILL_SWITCH,
        {},
    )
    assert response.ok is False
    assert "unknown operation" in (response.error or "")
    # And nothing happened: enforcement mode is untouched.
    assert servers.manager.enforcement_mode is servers.config.firewall.enforcement_mode


def test_allowlist_mutation_is_unreachable_over_the_portal_socket(servers: _Servers) -> None:
    response = _round_trip(
        servers,
        servers.portal_server,
        servers.config.portal.rpc_socket_path,
        RpcOperation.ADD_ALLOWLIST_ENTRY,
        {"target": "0.0.0.0/0", "reason": "pwn", "created_at": NOW.isoformat(), "created_by": "mallory"},
    )
    assert response.ok is False
    assert len(servers.manager.allowlist) == len(servers.config.firewall.allowlist)


def test_the_client_facing_operations_are_unreachable_over_the_core_socket(servers: _Servers) -> None:
    """The split cuts both ways: core.sock is not a second way into the portal surface."""
    response = _round_trip(
        servers,
        servers.core_server,
        servers.config.api.rpc_socket_path,
        RpcOperation.PORTAL_LOGIN,
        {"username": "alice", "password": PASSWORD, "client_ip": str(servers.client_ip)},
    )
    assert response.ok is False
    assert "unknown operation" in (response.error or "")


def test_the_admin_operations_work_over_the_core_socket(servers: _Servers) -> None:
    response = _round_trip(
        servers,
        servers.core_server,
        servers.config.api.rpc_socket_path,
        RpcOperation.PORTAL_LIST_USERS,
        {},
    )
    assert response.ok is True
    assert [user["username"] for user in response.data] == ["alice"]


def test_a_bad_client_address_is_refused_over_the_wire(servers: _Servers) -> None:
    """`client_ip` decides who gets forwarded, so it is parsed defensively."""
    response = _round_trip(
        servers,
        servers.portal_server,
        servers.config.portal.rpc_socket_path,
        RpcOperation.PORTAL_LOGIN,
        {"username": "alice", "password": PASSWORD, "client_ip": "not-an-address"},
    )
    assert response.ok is False
    assert "not a valid IPv4 address" in (response.error or "")


def test_an_unknown_socket_group_is_fatal_rather_than_silently_ignored() -> None:
    """Leaving the socket in the wrong group would silently widen or break access.

    The server *verifies* rather than sets the group (pirewall-core cannot
    `chown` under its own `SystemCallFilter=~@privileged`), so this is what
    turns a missing `tmpfiles` entry into a startup failure instead of a
    socket the portal can never reach.
    """
    from pirewall.core.exceptions import RpcError

    tmp = Path(tempfile.mkdtemp())
    server = UnixSocketRpcServer(
        str(tmp / "portal.sock"),
        PortalRpcDispatcher(
            PortalService(
                _portal_config(tmp),
                FirewallManager(make_config(), FakeFirewallBackend()),
                PortalUserStore(tmp / "users.json"),
                on_event=lambda _e: None,
            )
        ),
        socket_group="pirewall-no-such-group-exists",
    )
    with pytest.raises(RpcError, match="does not exist"):
        server.start()
    assert not (tmp / "portal.sock").exists(), "a socket we cannot secure must not be left behind"


def test_a_socket_in_the_wrong_group_is_refused() -> None:
    """A real group that is simply not the expected one must also stop startup."""
    from pirewall.core.exceptions import RpcError

    tmp = Path(tempfile.mkdtemp())
    config = _portal_config(tmp)
    # `root` exists everywhere and is never the portal group, so binding lands
    # the socket in the wrong group without needing to create one.
    server = UnixSocketRpcServer(
        str(tmp / "portal.sock"),
        PortalRpcDispatcher(
            PortalService(
                config,
                FirewallManager(make_config(), FakeFirewallBackend()),
                PortalUserStore(tmp / "users.json"),
                on_event=lambda _e: None,
            )
        ),
        socket_group="root",
    )
    with pytest.raises(RpcError, match="must be in 'root'"):
        server.start()
    assert not (tmp / "portal.sock").exists()

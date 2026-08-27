"""The real `AF_UNIX` RPC transport, end to end (ADDENDUM.md A4).

Every other test of the RPC layer uses `LoopbackRpcClient`, which calls
`CoreRpcDispatcher` in-process and never opens a socket. These exercise
`UnixSocketRpcServer`/`UnixSocketRpcClient` for real: bind, connect,
accept, full JSON request/response round-trip over the wire, and the
resulting socket's permission bits.

Previous sessions labeled this transport Environment-dependent because
they ran on Windows, where `socket.AF_UNIX` does not exist. It does exist
on macOS and Linux, so the transport itself is testable here; what stays
Environment-dependent is the *deployment* around it — real service users,
real `pirewall-ipc` group membership, systemd's `RuntimeDirectory=`.

The server is single-connection-at-a-time by design (`serve_one`), so each
test runs it on a background thread and joins with a timeout — a hang here
means a genuine protocol deadlock, not a slow machine.
"""

import os
import socket
import stat
import tempfile
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pirewall.core.enums import EnforcementMode
from pirewall.core.exceptions import RpcError
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.client import UnixSocketRpcClient
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.server import UnixSocketRpcServer
from pirewall.ipc.state import CoreStateStore
from tests.helpers.config import make_config

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="platform has no AF_UNIX support"
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
_JOIN_TIMEOUT_SECONDS = 10.0


def _dispatcher() -> CoreRpcDispatcher:
    config = make_config(firewall={"enforcement_mode": "active"})
    manager = FirewallManager(config, FakeFirewallBackend())
    state = CoreStateStore(max_history=50, started_at=NOW)
    return CoreRpcDispatcher(config=config, manager=manager, state=state)


@pytest.fixture
def socket_dir() -> Iterator[Path]:
    """A deliberately short temp dir.

    `AF_UNIX` paths are capped at ~104 bytes on macOS / ~108 on Linux, and
    pytest's `tmp_path` (which embeds the test name) blows past that — a
    plain `tmp_path` fixture here fails with a bare EACCES/ENAMETOOLONG
    that looks nothing like a path-length problem.

    Prefers `/tmp` (short on both Linux and macOS, unlike macOS's default
    `$TMPDIR` under `/var/folders/...`) but falls back to the platform
    default if it is absent, rather than hardcoding a path that may not
    exist.
    """
    base = "/tmp" if Path("/tmp").is_dir() else None
    with tempfile.TemporaryDirectory(dir=base, prefix="pw") as directory:
        yield Path(directory)


@pytest.fixture
def server(socket_dir: Path) -> Iterator[UnixSocketRpcServer]:
    rpc_server = UnixSocketRpcServer(str(socket_dir / "c.sock"), _dispatcher())
    rpc_server.start()
    try:
        yield rpc_server
    finally:
        rpc_server.stop()


def _serve_once_in_background(rpc_server: UnixSocketRpcServer) -> threading.Thread:
    thread = threading.Thread(target=rpc_server.serve_one, daemon=True)
    thread.start()
    return thread


def test_round_trip_over_a_real_socket(server: UnixSocketRpcServer, socket_dir: Path) -> None:
    thread = _serve_once_in_background(server)
    client = UnixSocketRpcClient(str(socket_dir / "c.sock"))

    status = client.get_status()

    thread.join(timeout=_JOIN_TIMEOUT_SECONDS)
    assert not thread.is_alive(), "server thread did not finish — protocol deadlock"
    assert status.enforcement_mode is EnforcementMode.ACTIVE
    assert status.active_rule_count == 0


def test_list_operation_round_trips_an_empty_collection(
    server: UnixSocketRpcServer, socket_dir: Path
) -> None:
    """A list response is a distinct wire shape from a single object — cover both."""
    thread = _serve_once_in_background(server)
    client = UnixSocketRpcClient(str(socket_dir / "c.sock"))

    rules = client.list_rules()

    thread.join(timeout=_JOIN_TIMEOUT_SECONDS)
    assert rules == []


def test_malformed_request_gets_an_error_response_instead_of_crashing_core(
    server: UnixSocketRpcServer, socket_dir: Path
) -> None:
    """Garbage on the wire must not take pirewall-core down.

    pirewall-api is the less-trusted process (ADDENDUM.md A4) and is what
    speaks to this socket, so malformed input arriving here is exactly the
    "compromised control panel" case A4 exists for. The server must answer
    `ok=false` and stay up, not raise out of `serve_one`.
    """
    thread = _serve_once_in_background(server)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
        raw.settimeout(_JOIN_TIMEOUT_SECONDS)
        raw.connect(str(socket_dir / "c.sock"))
        raw.sendall(b"this is not JSON at all")
        raw.shutdown(socket.SHUT_WR)
        response = raw.recv(65536)

    thread.join(timeout=_JOIN_TIMEOUT_SECONDS)
    assert not thread.is_alive(), "server thread died on malformed input"
    assert b'"ok":false' in response.replace(b" ", b"")


def test_client_raises_rpc_error_on_a_malformed_response(socket_dir: Path) -> None:
    """The mirror case: a client must not silently accept a non-conforming reply."""
    socket_path = socket_dir / "bad.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)

    def _reply_with_garbage() -> None:
        connection, _ = listener.accept()
        with connection:
            connection.recv(65536)
            connection.sendall(b"<!doctype html>not an RpcResponse")

    thread = threading.Thread(target=_reply_with_garbage, daemon=True)
    thread.start()
    try:
        with pytest.raises(RpcError):
            UnixSocketRpcClient(str(socket_path)).get_status()
    finally:
        thread.join(timeout=_JOIN_TIMEOUT_SECONDS)
        listener.close()


def test_socket_is_not_world_accessible(server: UnixSocketRpcServer, socket_dir: Path) -> None:
    """ADDENDUM.md A4: the socket must be reachable only by the two service users.

    Regression test for an audit finding: the mode was left entirely to the
    process umask, so a pirewall-core started with a default 0o022 umask
    created a world-connectable 0o755 socket, exposing every privileged RPC
    operation to any local user.
    """
    mode = stat.S_IMODE(os.stat(socket_dir / "c.sock").st_mode)

    assert not mode & stat.S_IRWXO, f"socket is world-accessible: {oct(mode)}"
    assert mode == 0o660, f"expected owner+group rw only, got {oct(mode)}"


def test_socket_mode_does_not_depend_on_the_caller_umask(socket_dir: Path) -> None:
    """The same finding, stated as the property that actually matters."""
    previous_umask = os.umask(0o022)  # a permissive default, as a login shell would have
    try:
        rpc_server = UnixSocketRpcServer(str(socket_dir / "u.sock"), _dispatcher())
        rpc_server.start()
        try:
            mode = stat.S_IMODE(os.stat(socket_dir / "u.sock").st_mode)
        finally:
            rpc_server.stop()
    finally:
        os.umask(previous_umask)

    assert mode == 0o660, f"umask leaked into socket permissions: {oct(mode)}"


def test_socket_directory_is_traversable_when_created_by_start(socket_dir: Path) -> None:
    """Regression test: under the 0o117 umask the service sets, mkdir produced a 0o660 directory.

    That has no execute bits, so nothing — including pirewall-api — could
    traverse into it to reach the socket. Under systemd this was masked by
    `RuntimeDirectory=` having already created the directory.
    """
    previous_umask = os.umask(0o117)  # exactly what pirewall-core.service sets
    try:
        socket_path = socket_dir / "run" / "pirewall" / "c.sock"
        rpc_server = UnixSocketRpcServer(str(socket_path), _dispatcher())
        rpc_server.start()
        try:
            dir_mode = stat.S_IMODE(os.stat(socket_path.parent).st_mode)
            thread = _serve_once_in_background(rpc_server)
            reachable = UnixSocketRpcClient(str(socket_path)).get_status()
            thread.join(timeout=_JOIN_TIMEOUT_SECONDS)
        finally:
            rpc_server.stop()
    finally:
        os.umask(previous_umask)

    assert dir_mode & stat.S_IXUSR, f"socket directory not owner-traversable: {oct(dir_mode)}"
    assert dir_mode & stat.S_IXGRP, f"socket directory not group-traversable: {oct(dir_mode)}"
    assert not dir_mode & stat.S_IRWXO, f"socket directory is world-accessible: {oct(dir_mode)}"
    assert reachable.enforcement_mode is EnforcementMode.ACTIVE


def test_unreachable_socket_raises_rpc_error(socket_dir: Path) -> None:
    """A down pirewall-core must surface as a clean RpcError, not an unhandled OSError."""
    client = UnixSocketRpcClient(str(socket_dir / "nonexistent.sock"), timeout_seconds=1.0)
    with pytest.raises(RpcError):
        client.get_status()

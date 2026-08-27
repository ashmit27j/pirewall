"""The pirewall-core side of the RPC transport (ADDENDUM.md A4).

Requires `socket.AF_UNIX`, so this cannot run on Windows — but it is
exercised for real (bind, accept, full request/response round-trip,
resulting socket permissions) by
`tests/integration/test_rpc_unix_socket.py` on any POSIX host. What
remains Environment-dependent is the *deployment* around it: real
`pirewall-core`/`pirewall-api` service users, real group membership, and
systemd's `RuntimeDirectory=`. See `docs/PROGRESS.md`.
"""

import contextlib
import os
import socket
from collections.abc import Generator
from pathlib import Path

from pydantic import ValidationError

from pirewall.core.exceptions import RpcError
from pirewall.ipc._framing import read_all
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.protocol import RpcRequest, RpcResponse

_LISTEN_BACKLOG = 5

# owner rw + group rw, nothing for other. The group is the shared
# `pirewall-ipc` group both service users belong to (see
# deploy/systemd/README.md) — this is what actually restricts the socket to
# pirewall-core and pirewall-api.
_SOCKET_MODE = 0o660
# owner rwx + group rx: the group must be able to traverse into the
# directory to reach the socket, so this needs its execute bits (a mode
# derived from a 0o117 umask would be 0o660 — no traversal at all).
_SOCKET_DIR_MODE = 0o750


@contextlib.contextmanager
def _umask_for(mode: int) -> Generator[None]:
    """Temporarily set the umask so a file created inside gets exactly `mode`.

    `mkdir(mode=...)`/`bind()` both derive their result from the umask
    (`mode & ~umask`), so passing an explicit mode is not sufficient on its
    own — under pirewall-core.service's `UMask=0117`, even an explicit
    `mkdir(mode=0o750)` lands as `0o640`. Setting the umask rather than
    chmod-ing afterwards also means the file is never briefly more
    permissive than intended, so there is no window to race.

    Process-global and not thread-safe; only used during `start()`, which
    runs once in pirewall-core's startup sequence before any worker threads
    exist (spec §42).
    """
    previous = os.umask(0o777 & ~mode)
    try:
        yield
    finally:
        os.umask(previous)


class UnixSocketRpcServer:
    """Binds a Unix domain socket and serves `CoreRpcDispatcher` requests, one connection at a time.

    The socket is created mode `0o660` (owner+group read/write) by `start()`
    itself, so restricting it to the two service users does not depend on
    the systemd unit's `UMask=` being present and correct. Which *group*
    owns it still comes from the deployment (pirewall-core's primary group
    is the shared `pirewall-ipc` group — see `deploy/systemd/README.md`);
    this class guarantees only that nothing outside that group can reach it.
    """

    def __init__(self, socket_path: str, dispatcher: CoreRpcDispatcher) -> None:
        self._socket_path = socket_path
        self._dispatcher = dispatcher
        self._server_socket: socket.socket | None = None

    def start(self) -> None:
        """Bind and start listening, with the socket restricted to the pirewall-ipc group.

        Access control is applied here rather than being left to the
        process umask. `bind()` derives the socket's mode from the umask, so
        a pirewall-core started with a default 0o022 umask (a manual run, a
        unit missing `UMask=`, a non-systemd init) would otherwise create a
        world-connectable 0o755 socket — and every privileged RPC operation
        (disable/remove rules, approve pending BLOCKs, edit the allowlist,
        the kill-switch) would be reachable by any local user. The umask
        guard closes the window between bind and chmod; the explicit chmod
        then guarantees the final mode regardless of what the umask was.

        Setting the umask is process-global and not thread-safe, which is
        fine here: `start()` runs once during pirewall-core's startup
        sequence (spec §42), before any worker threads exist.
        """
        path = Path(self._socket_path)
        try:
            # Under systemd this is a no-op: RuntimeDirectory= already
            # created the directory, 0750, correctly owned. It matters for
            # every other way pirewall-core can be started.
            with _umask_for(_SOCKET_DIR_MODE):
                path.parent.mkdir(mode=_SOCKET_DIR_MODE, parents=True, exist_ok=True)
            path.unlink(missing_ok=True)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            with _umask_for(_SOCKET_MODE):
                sock.bind(str(path))
            sock.listen(_LISTEN_BACKLOG)
        except OSError as exc:
            raise RpcError(f"failed to bind RPC socket at {self._socket_path}: {exc}") from exc
        self._server_socket = sock

    def stop(self) -> None:
        """Close the listening socket and remove the socket file. Idempotent."""
        if self._server_socket is not None:
            self._server_socket.close()
            self._server_socket = None
        Path(self._socket_path).unlink(missing_ok=True)

    def serve_one(self) -> None:
        """Accept and handle exactly one connection. Callers loop this for `serve_forever`-style behavior."""
        if self._server_socket is None:
            raise RpcError("RPC server has not been started")
        connection, _address = self._server_socket.accept()
        try:
            self._handle(connection)
        finally:
            connection.close()

    def _handle(self, connection: socket.socket) -> None:
        raw = read_all(connection)
        try:
            request = RpcRequest.model_validate_json(raw)
        except ValidationError as exc:
            response = RpcResponse(ok=False, error=f"invalid request: {exc}")
        else:
            response = self._dispatcher.handle(request)
        connection.sendall(response.model_dump_json().encode("utf-8"))
        connection.shutdown(socket.SHUT_WR)

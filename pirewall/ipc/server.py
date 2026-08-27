"""The pirewall-core side of the RPC transport (ADDENDUM.md A4).

Linux-only (`socket.AF_UNIX`) — cannot be exercised on this dev machine.
See `docs/PROGRESS.md` Phase 7 for the Environment-dependent label; the
actual operation logic (`pirewall.ipc.dispatcher.CoreRpcDispatcher`) is
fully unit-tested independent of this transport.
"""

import socket
from pathlib import Path

from pydantic import ValidationError

from pirewall.core.exceptions import RpcError
from pirewall.ipc._framing import read_all
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.protocol import RpcRequest, RpcResponse

_LISTEN_BACKLOG = 5


class UnixSocketRpcServer:
    """Binds a Unix domain socket and serves `CoreRpcDispatcher` requests, one connection at a time.

    Socket file permissions restricting it to the `pirewall-core`/
    `pirewall-api` service users are applied by Phase 8's systemd units,
    not here.
    """

    def __init__(self, socket_path: str, dispatcher: CoreRpcDispatcher) -> None:
        self._socket_path = socket_path
        self._dispatcher = dispatcher
        self._server_socket: socket.socket | None = None

    def start(self) -> None:
        """Bind and start listening. Raises `RpcError` on failure."""
        path = Path(self._socket_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.unlink(missing_ok=True)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
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

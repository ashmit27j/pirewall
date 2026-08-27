"""`LoopbackRpcClient`: an in-process `RpcClient` test double (ADDENDUM.md A4).

Calls `CoreRpcDispatcher.handle()` directly — no socket at all.
**Test-only.** The real two-process deployment must never use this: doing
so would put `pirewall-api` back in the same process/memory space as
`pirewall-core`, defeating A4's entire point (a compromised `pirewall-api`
must never have a direct path to `firewall.manager`/`firewall.backend`).
`tests/security/test_api_process_isolation.py` only allows this module to
be imported from test files.
"""

from typing import Any

from pirewall.ipc.client import BaseRpcClient
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.protocol import RpcOperation, RpcRequest, RpcResponse


class LoopbackRpcClient(BaseRpcClient):
    """Wraps a `CoreRpcDispatcher` directly, implementing the same interface as `UnixSocketRpcClient`."""

    def __init__(self, dispatcher: CoreRpcDispatcher) -> None:
        self._dispatcher = dispatcher

    def _call(self, operation: RpcOperation, params: dict[str, Any] | None = None) -> RpcResponse:
        return self._dispatcher.handle(RpcRequest(operation=operation, params=params or {}))

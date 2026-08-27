"""pirewall-core <-> pirewall-api RPC protocol (ADDENDUM.md A4).

`pirewall.ipc.loopback.LoopbackRpcClient` is test-only — never used by the
real two-process deployment. See `docs/ARCHITECTURE.md` "Process split".
"""

from pirewall.ipc.client import BaseRpcClient, UnixSocketRpcClient
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.protocol import RpcOperation, RpcRequest, RpcResponse
from pirewall.ipc.server import UnixSocketRpcServer
from pirewall.ipc.state import CoreStateStore

__all__ = [
    "BaseRpcClient",
    "CoreRpcDispatcher",
    "CoreStateStore",
    "RpcOperation",
    "RpcRequest",
    "RpcResponse",
    "UnixSocketRpcClient",
    "UnixSocketRpcServer",
]

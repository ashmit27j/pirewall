"""`POST /api/v1/firewall/kill-switch` (ADDENDUM.md A8)."""

from fastapi import APIRouter

from pirewall.api.app import RpcClientDep
from pirewall.core.models.event import SecurityEvent

router = APIRouter(prefix="/api/v1/firewall", tags=["firewall"])


@router.post("/kill-switch", response_model=SecurityEvent)
def kill_switch(rpc_client: RpcClientDep) -> SecurityEvent:
    """Emergency rollback: SHADOW mode + every active adaptive rule removed (ADDENDUM.md A8).

    Calls through to `FirewallManager.revert_to_base` — the same
    authenticated/Admin-PC-restricted path as every other write endpoint,
    no lower-security bypass.
    """
    return rpc_client.kill_switch()

"""`POST /api/v1/rules/{id}/disable|remove|approve|reject` (spec §28, ADDENDUM.md A7).

Every one of these calls through the RPC client into
`pirewall.firewall.manager.FirewallManager` — the one authorized deploy
path (CLAUDE.md) — never touches the firewall backend directly.
"""

from fastapi import APIRouter, HTTPException

from pirewall.api.app import RpcClientDep
from pirewall.core.models.rule import FirewallRule

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


def _or_404(rule: FirewallRule | None) -> FirewallRule:
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found or not in an actionable state")
    return rule


@router.post("/{rule_id}/disable", response_model=FirewallRule)
def disable_rule(rule_id: str, rpc_client: RpcClientDep) -> FirewallRule:
    return _or_404(rpc_client.disable_rule(rule_id))


@router.post("/{rule_id}/remove", response_model=FirewallRule)
def remove_rule(rule_id: str, rpc_client: RpcClientDep) -> FirewallRule:
    return _or_404(rpc_client.remove_rule(rule_id))


@router.post("/{rule_id}/approve", response_model=FirewallRule)
def approve_rule(rule_id: str, rpc_client: RpcClientDep) -> FirewallRule:
    """Approve a `PENDING_APPROVAL` rule (ADDENDUM.md A7) — deploys through the normal manager path."""
    return _or_404(rpc_client.approve_rule(rule_id))


@router.post("/{rule_id}/reject", response_model=FirewallRule)
def reject_rule(rule_id: str, rpc_client: RpcClientDep) -> FirewallRule:
    """Reject a `PENDING_APPROVAL` rule (ADDENDUM.md A7). Never deploys."""
    return _or_404(rpc_client.reject_rule(rule_id))

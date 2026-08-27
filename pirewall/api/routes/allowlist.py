"""`GET/POST/DELETE /api/v1/allowlist` (ADDENDUM.md A2)."""

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException

from pirewall.api.app import RpcClientDep, SessionDep
from pirewall.api.schemas import AllowlistCreateRequest, MessageResponse
from pirewall.core.models.allowlist import AllowlistEntry

router = APIRouter(prefix="/api/v1/allowlist", tags=["allowlist"])


@router.get("", response_model=list[AllowlistEntry])
def list_allowlist(rpc_client: RpcClientDep) -> list[AllowlistEntry]:
    return rpc_client.list_allowlist()


@router.post("", response_model=AllowlistEntry)
def add_allowlist_entry(
    body: AllowlistCreateRequest, rpc_client: RpcClientDep, session: SessionDep
) -> AllowlistEntry:
    entry = AllowlistEntry(
        target=body.target,
        port=body.port,
        protocol=body.protocol,
        reason=body.reason,
        created_at=datetime.now(UTC),
        created_by=session.username,
    )
    return rpc_client.add_allowlist_entry(entry)


@router.delete("/{entry_id}", response_model=MessageResponse)
def remove_allowlist_entry(entry_id: str, rpc_client: RpcClientDep) -> MessageResponse:
    removed = rpc_client.remove_allowlist_entry(entry_id)
    if not removed:
        raise HTTPException(status_code=404, detail="allowlist entry not found")
    return MessageResponse(message="removed")

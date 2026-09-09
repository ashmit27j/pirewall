"""`/api/v1/portal/...` — captive-portal administration (ADDENDUM_3.md C1, C3).

The *admin* side of the portal, served by pirewall-api to the Admin PC only,
over the same session-authenticated, Admin-PC-restricted surface as every
other route here. It has nothing to do with `pirewall-portal`, which serves
LAN clients over a different socket with a dispatcher that cannot reach any
of these operations.

Like every other route in this package, these reach pirewall-core solely
through the typed RPC client — never `pirewall.firewall.manager`
(ADDENDUM.md A4).
"""

from ipaddress import AddressValueError, IPv4Address

from fastapi import APIRouter, HTTPException

from pirewall.api.app import RpcClientDep, SessionDep
from pirewall.api.schemas import MessageResponse, PortalUserCreateRequest, PortalUserResponse
from pirewall.core.models.portal import PortalSession, PortalUser

router = APIRouter(prefix="/api/v1/portal", tags=["portal"])


@router.get("/users", response_model=list[PortalUser])
def list_users(rpc_client: RpcClientDep) -> list[PortalUser]:
    """Every LAN account. Password hashes are part of `PortalUser`; nothing reversible is returned."""
    return rpc_client.portal_list_users()


@router.post("/users", response_model=PortalUserResponse)
def add_user(
    body: PortalUserCreateRequest, rpc_client: RpcClientDep, session: SessionDep
) -> PortalUserResponse:
    """Create an account. Omitting `password` generates one, returned here exactly once."""
    user, generated = rpc_client.portal_add_user(
        username=body.username,
        created_by=session.username,
        password=body.password,
        note=body.note,
    )
    return PortalUserResponse(user=user, generated_password=generated)


@router.post("/users/{username}/password", response_model=PortalUserResponse)
def reset_password(username: str, rpc_client: RpcClientDep) -> PortalUserResponse:
    """Generate a new password for an account and end its live sessions."""
    user, generated = rpc_client.portal_set_password(username)
    return PortalUserResponse(user=user, generated_password=generated)


@router.delete("/users/{username}", response_model=MessageResponse)
def remove_user(username: str, rpc_client: RpcClientDep) -> MessageResponse:
    if not rpc_client.portal_remove_user(username):
        raise HTTPException(status_code=404, detail="portal user not found")
    return MessageResponse(message="removed")


@router.get("/sessions", response_model=list[PortalSession])
def list_sessions(rpc_client: RpcClientDep) -> list[PortalSession]:
    """Currently signed-in LAN devices."""
    return rpc_client.portal_list_sessions()


@router.post("/sessions/{client_ip}/logout", response_model=MessageResponse)
def force_logout(client_ip: str, rpc_client: RpcClientDep) -> MessageResponse:
    """Disconnect one device: removes its nft set element immediately."""
    if not rpc_client.portal_force_logout(_parse_ip(client_ip)):
        raise HTTPException(status_code=404, detail="no active session for that address")
    return MessageResponse(message="disconnected")


def _parse_ip(raw: str) -> IPv4Address:
    try:
        return IPv4Address(raw)
    except (AddressValueError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid client address: {raw!r}") from exc


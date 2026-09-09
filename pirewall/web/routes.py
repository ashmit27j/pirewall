"""Control panel page routes (spec §30). Renders from RPC-fetched state only — no side effects on GET."""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from pirewall.api.app import RpcClientDep
from pirewall.core.exceptions import RpcError
from pirewall.core.models.portal import PortalSession, PortalUser
from pirewall.ipc.client import BaseRpcClient
from pirewall.web.render import render_dashboard, render_login_page

public_router = APIRouter(prefix="/control-panel", tags=["web"])
protected_router = APIRouter(prefix="/control-panel", tags=["web"])


@public_router.get("/login", response_class=HTMLResponse)
def login_page() -> HTMLResponse:
    return HTMLResponse(render_login_page())


@protected_router.get("", response_class=HTMLResponse)
def dashboard(rpc_client: RpcClientDep) -> HTMLResponse:
    status = rpc_client.get_status()
    rules = rpc_client.list_rules()
    events = rpc_client.list_events()
    threats = rpc_client.list_threats()
    models = rpc_client.list_models()
    allowlist = rpc_client.list_allowlist()
    capture_stats = rpc_client.get_capture_stats()
    detections = rpc_client.list_detections()
    portal_users, portal_sessions = _portal_state(rpc_client)
    return HTMLResponse(
        render_dashboard(
            status,
            rules,
            events,
            threats,
            models,
            allowlist,
            capture_stats,
            detections,
            portal_users,
            portal_sessions,
        )
    )


def _portal_state(
    rpc_client: BaseRpcClient,
) -> tuple[list[PortalUser] | None, list[PortalSession] | None]:
    """Portal accounts and sessions, or `(None, None)` when the portal is disabled.

    pirewall-core answers these operations with an error when
    `portal.enabled` is false. That is a configuration state, not a failure,
    so it is turned into `None` — which `render_dashboard` renders as "no
    portal panels at all" rather than as two misleading empty tables. A core
    that is genuinely *down* still raises, and is still reported by the
    503 handler in `pirewall.api.app`.
    """
    try:
        return rpc_client.portal_list_users(), rpc_client.portal_list_sessions()
    except RpcError:
        return None, None

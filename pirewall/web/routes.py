"""Control panel page routes (spec §30). Renders from RPC-fetched state only — no side effects on GET."""

from pathlib import Path
from typing import Final

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response

from pirewall.api.app import RpcClientDep
from pirewall.core.exceptions import RpcError
from pirewall.core.models.identity import Binding
from pirewall.core.models.portal import PortalSession, PortalUser
from pirewall.ipc.client import BaseRpcClient
from pirewall.ipc.protocol_v2 import EngineStats, GuardModes, OffenderEntry
from pirewall.web.render import render_dashboard, render_login_page
from pirewall.web.v2_panel import V2PanelState

public_router = APIRouter(prefix="/control-panel", tags=["web"])
protected_router = APIRouter(prefix="/control-panel", tags=["web"])


@public_router.get("/login", response_class=HTMLResponse)
def login_page() -> HTMLResponse:
    return HTMLResponse(render_login_page())


#: Served from the repository rather than embedded, so the sign-in page and
#: every panel page share one cacheable request instead of carrying ~200 KB
#: of base64 each. Public because the sign-in page needs it before there is
#: a session; it is a logo, not information about the network.
_LOGO_PATH: Final = Path(__file__).resolve().parents[2] / "deploy" / "web" / "pirewall-logo.png"


@public_router.get("/logo.png", include_in_schema=False)
def logo() -> Response:
    """The pirewall mark. 404s rather than erroring if the file is absent."""
    try:
        data = _LOGO_PATH.read_bytes()
    except OSError:
        raise HTTPException(status_code=404, detail="logo not installed") from None
    return Response(
        content=data,
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@protected_router.get("", response_class=HTMLResponse)
def dashboard(rpc_client: RpcClientDep) -> HTMLResponse:
    """The Overview page."""
    return _render_page(rpc_client, "")


@protected_router.get("/{page}", response_class=HTMLResponse)
def dashboard_page(page: str, rpc_client: RpcClientDep) -> HTMLResponse:
    """One of the other nav pages. An unknown slug renders rather than 500s."""
    return _render_page(rpc_client, page)


def _render_page(rpc_client: BaseRpcClient, page: str) -> HTMLResponse:
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
            v2=_v2_state(rpc_client),
            page=page,
        )
    )


def _v2_state(rpc_client: BaseRpcClient) -> V2PanelState:
    """The v2 section's data, each part fetched on its own so one failure cannot hide the rest.

    pirewall-core reports an error, rather than an empty value, for a v2
    view it cannot serve (no set backend, tables deleted by panic, counters
    not published yet). That is shown in the panel, not turned into a 503:
    the rest of the dashboard is still accurate.
    """
    guards: GuardModes | None = None
    guards_error: str | None = None
    try:
        guards = rpc_client.get_guard_modes()
    except RpcError as exc:
        guards_error = str(exc)
    errors: list[str] = []
    offenders: tuple[OffenderEntry, ...] = ()
    bindings: tuple[Binding, ...] = ()
    engine: EngineStats | None = None
    try:
        offenders = rpc_client.list_offenders()
        bindings = rpc_client.list_bindings()
    except RpcError as exc:
        errors.append(f"v2 status unavailable: {exc}")
    try:
        engine = rpc_client.get_engine_stats()
    except RpcError as exc:
        errors.append(f"engine counters unavailable: {exc}")
    return V2PanelState(
        guards=guards,
        guards_error=guards_error,
        offenders=offenders,
        bindings=bindings,
        engine=engine,
        errors=tuple(errors),
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

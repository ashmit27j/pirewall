"""Control panel page routes (spec §30). Renders from RPC-fetched state only — no side effects on GET."""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from pirewall.api.app import RpcClientDep
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
    return HTMLResponse(render_dashboard(status, rules, events, threats, models, allowlist))

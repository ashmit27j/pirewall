"""Portal page and API routes (ADDENDUM_3.md C1, C4).

Module-level router rather than closures inside the app factory, matching
`pirewall/api/routes/`. Every handler derives the client address from the
connection's peer, never from a header, and every decision it reports comes
from pirewall-core — this module contains no policy of its own.
"""

from typing import Any
from urllib.parse import parse_qsl

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from pirewall.core.models.portal import PortalClientStatus, PortalSession
from pirewall.portal.app import (
    COOKIE_MAX_AGE_SECONDS,
    PORTAL_COOKIE_NAME,
    ClientIpDep,
    ConfigDep,
    RpcClientDep,
    portal_status,
)
from pirewall.portal.render import render_blocked_page, render_keepalive_page, render_login_page

router = APIRouter(tags=["portal"])

# A sign-in form is a few hundred bytes; anything larger is not a login.
_MAX_LOGIN_BODY_BYTES = 8192

# The URLs each OS fetches to decide "is this network captive?". A 302 to
# the portal is what makes the sign-in sheet pop up by itself. These are
# well-known, unauthenticated probe endpoints; answering them is the
# documented way a portal announces itself, alongside DHCP option 114.
CAPTIVE_PROBE_PATHS = (
    "/generate_204",               # Android
    "/gen_204",                    # Android (older)
    "/hotspot-detect.html",        # iOS, macOS
    "/library/test/success.html",  # iOS (older)
    "/connecttest.txt",            # Windows
    "/ncsi.txt",                   # Windows (older)
    "/success.txt",                # Firefox
    "/canonical.html",             # Ubuntu / NetworkManager
)


@router.get("/portal", response_class=HTMLResponse)
def login_page(
    request: Request, config: ConfigDep, rpc_client: RpcClientDep, client_ip: ClientIpDep
) -> Response:
    """The captive-portal landing page. Already-signed-in clients go straight through."""
    token = request.cookies.get(PORTAL_COOKIE_NAME)
    state = rpc_client.portal_keepalive(token, client_ip)
    if state.status is PortalClientStatus.BLOCKED:
        return HTMLResponse(
            render_blocked_page(network_name=config.portal.network_name, message=state.message),
            status_code=403,
        )
    if state.status is PortalClientStatus.AUTHENTICATED:
        return RedirectResponse("/portal/connected", status_code=303)
    status = portal_status(rpc_client)
    return HTMLResponse(
        render_login_page(
            network_name=config.portal.network_name,
            error=request.query_params.get("error", ""),
            demo_accounts_present=bool(status.get("demo_accounts_present")),
            contact_message=config.portal.contact_message,
        )
    )


async def _read_credentials(request: Request) -> tuple[str, str]:
    """Parse `username`/`password` from a urlencoded form body, using only stdlib.

    FastAPI's `Form()` would be the obvious way to write this, but declaring
    one makes FastAPI require `python-multipart` at import time — a
    dependency outside CLAUDE.md's allowed list, pulled in for a parser the
    stdlib already has. A browser posting a plain `<form>` sends
    `application/x-www-form-urlencoded`, which `parse_qsl` handles exactly.

    A body that is missing, oversized, or undecodable yields empty
    credentials, which then fail authentication normally — there is no
    separate error path for a malformed login to probe.
    """
    raw = await request.body()
    if len(raw) > _MAX_LOGIN_BODY_BYTES:
        return "", ""
    try:
        fields = dict(parse_qsl(raw.decode("utf-8"), keep_blank_values=True))
    except UnicodeDecodeError:
        return "", ""
    return fields.get("username", ""), fields.get("password", "")


@router.post("/portal/login")
async def login(
    request: Request,
    config: ConfigDep,
    rpc_client: RpcClientDep,
    client_ip: ClientIpDep,
) -> Response:
    """Authenticate and, on success, hand the client its session cookie."""
    from pirewall.core.exceptions import RpcError

    username, password = await _read_credentials(request)
    try:
        # Off the event loop: the RPC call blocks on a socket round trip and
        # on pirewall-core's scrypt verification, which is deliberately slow.
        session: PortalSession = await run_in_threadpool(
            rpc_client.portal_login, username, password, client_ip
        )
    except RpcError as exc:
        # Every user-visible login failure — bad credentials, throttled,
        # already blocked — arrives as an RpcError carrying the message
        # pirewall-core decided the client may see. Re-rendered on the login
        # page rather than surfaced as an HTTP error, so the user gets a
        # form back rather than a browser error sheet.
        status: dict[str, Any] = await run_in_threadpool(portal_status, rpc_client)
        return HTMLResponse(
            render_login_page(
                network_name=config.portal.network_name,
                error=str(exc),
                demo_accounts_present=bool(status.get("demo_accounts_present")),
                contact_message=config.portal.contact_message,
            ),
            status_code=401,
        )
    response = RedirectResponse("/portal/connected", status_code=303)
    response.set_cookie(
        PORTAL_COOKIE_NAME,
        session.token,
        httponly=True,
        # The portal is plaintext HTTP by necessity (ADDENDUM_3.md C5): a
        # self-signed certificate breaks OS captive-portal detection.
        # `secure=True` here would stop the cookie being sent at all.
        secure=False,
        samesite="lax",
        max_age=COOKIE_MAX_AGE_SECONDS,
        path="/portal",
    )
    return response


@router.get("/portal/connected", response_class=HTMLResponse)
def connected(
    request: Request, config: ConfigDep, rpc_client: RpcClientDep, client_ip: ClientIpDep
) -> Response:
    """The keepalive page: status, and the countdown to automatic sign-out."""
    token = request.cookies.get(PORTAL_COOKIE_NAME)
    state = rpc_client.portal_keepalive(token, client_ip)
    if state.status is PortalClientStatus.BLOCKED:
        return HTMLResponse(
            render_blocked_page(network_name=config.portal.network_name, message=state.message),
            status_code=403,
        )
    if state.status is not PortalClientStatus.AUTHENTICATED:
        return RedirectResponse("/portal", status_code=303)
    return HTMLResponse(
        render_keepalive_page(
            network_name=config.portal.network_name,
            username=state.username or "",
            client_ip=str(state.client_ip),
            seconds_remaining=state.seconds_remaining,
            keepalive_interval_seconds=config.portal.keepalive_interval_seconds,
            contact_message=config.portal.contact_message,
        )
    )


@router.get("/portal/api/keepalive")
def keepalive(request: Request, rpc_client: RpcClientDep, client_ip: ClientIpDep) -> JSONResponse:
    """One poll from the keepalive page. The countdown is corrected from this, every time."""
    token = request.cookies.get(PORTAL_COOKIE_NAME)
    state = rpc_client.portal_keepalive(token, client_ip)
    return JSONResponse(state.model_dump(mode="json"))


@router.post("/portal/logout")
def logout(request: Request, rpc_client: RpcClientDep, client_ip: ClientIpDep) -> Response:
    """End this client's own session and drop its forwarding authorization."""
    token = request.cookies.get(PORTAL_COOKIE_NAME)
    if token:
        rpc_client.portal_logout(token, client_ip)
    response = RedirectResponse("/portal", status_code=303)
    response.delete_cookie(PORTAL_COOKIE_NAME, path="/portal")
    return response


@router.get("/portal/health")
def health() -> dict[str, str]:
    """Liveness of the portal process itself — deliberately says nothing about core."""
    return {"status": "ok"}


def _redirect_to_portal() -> Response:
    return RedirectResponse("/portal", status_code=302)


def install_captive_probe_routes(app: FastAPI) -> None:
    """Answer every OS captive-probe URL, `/`, and any unknown path with a redirect.

    The nat chain redirects *every* unauthenticated port-80 request to this
    process, whatever URL the client was actually asking for, so a 404 body
    would be the wrong answer to nearly all of them.
    """
    for path in CAPTIVE_PROBE_PATHS:
        app.add_api_route(path, _redirect_to_portal, methods=["GET"], include_in_schema=False)
    app.add_api_route("/", _redirect_to_portal, methods=["GET"], include_in_schema=False)
    app.add_exception_handler(404, lambda _request, _exc: _redirect_to_portal())

"""pirewall-portal FastAPI app factory (ADDENDUM_3.md C1).

The LAN-facing half of the captive portal. This process:

* never imports `pirewall.capture`, `pirewall.firewall.backend`, or
  `pirewall.firewall.manager` (asserted by
  `tests/security/test_api_process_isolation.py`);
* holds no state — every decision is made by pirewall-core over the
  restricted portal RPC socket;
* serves **only** the routes in `pirewall.portal.routes`. There is no admin
  surface here to reach, and the dispatcher on the other end of its socket
  has no privileged operation to call.

`client_ip` always comes from the peer address of the TCP connection
(`request.client.host`), never from a header. uvicorn is started with
`proxy_headers=False` for the same reason pirewall-api is: honouring
`X-Forwarded-For` here would let any LAN client claim to be any address and
have it authorized for forwarding.
"""

from ipaddress import AddressValueError, IPv4Address
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from pirewall.config.models import PirewallConfig
from pirewall.core.exceptions import RpcError
from pirewall.ipc.client import BaseRpcClient
from pirewall.portal.render import render_blocked_page

PORTAL_COOKIE_NAME = "pirewall_portal_session"

# Long enough that a phone parked on the page keeps its cookie, short enough
# that a shared device does not carry a stale token forever. The session's
# real lifetime is the server's, not this.
COOKIE_MAX_AGE_SECONDS = 86400


def get_config(request: Request) -> PirewallConfig:
    config = request.app.state.pirewall_config
    assert isinstance(config, PirewallConfig)
    return config


def get_rpc_client(request: Request) -> BaseRpcClient:
    client = request.app.state.pirewall_rpc_client
    assert isinstance(client, BaseRpcClient)
    return client


def client_address(request: Request) -> IPv4Address:
    """The peer address of this connection, as an `IPv4Address`.

    Fails closed. A request with no peer information, or a peer that is not
    a literal IPv4 address, is refused rather than defaulted — this value
    decides who gets forwarded.
    """
    host = request.client.host if request.client else None
    if host is None:
        raise HTTPException(status_code=400, detail="could not determine client address")
    try:
        return IPv4Address(host)
    except (AddressValueError, ValueError) as exc:
        # IPv6 clients land here. v1 is IPv4-only (ADDENDUM.md A5) and the
        # portal grants IPv4 set elements, so there is nothing honest to do
        # with a v6 peer but say so.
        raise HTTPException(
            status_code=400, detail="this network authenticates IPv4 clients only"
        ) from exc


ConfigDep = Annotated[PirewallConfig, Depends(get_config)]
RpcClientDep = Annotated[BaseRpcClient, Depends(get_rpc_client)]
ClientIpDep = Annotated[IPv4Address, Depends(client_address)]


def portal_status(rpc_client: BaseRpcClient) -> dict[str, Any]:
    """Portal prerequisites, degrading to safe defaults if core is unreachable.

    A missing key reads as "off" everywhere it is consumed, so an
    unreachable core cannot accidentally *suppress* the demo-account
    warning by making the page think it answered.
    """
    try:
        return rpc_client.portal_status()
    except RpcError:
        return {}


def handle_core_unavailable(request: Request, exc: Exception) -> Response:
    """An unreachable core is reported, never a traceback (ADDENDUM.md A6).

    503 rather than 500: this process is fine, its dependency is not.
    Typed as `Exception` because that is the signature Starlette's handler
    registry requires; only `RpcError` is ever routed here.
    """
    config = request.app.state.pirewall_config
    assert isinstance(config, PirewallConfig)
    if request.url.path.startswith("/portal/api/"):
        return JSONResponse(
            {"status": "unavailable", "message": "The network controller is unreachable."},
            status_code=503,
        )
    return HTMLResponse(
        render_blocked_page(
            network_name=config.portal.network_name,
            message=(
                "The network controller is temporarily unreachable, so sign-in is "
                f"unavailable. {config.portal.contact_message}"
            ),
        ),
        status_code=503,
    )


def create_app(config: PirewallConfig, rpc_client: BaseRpcClient) -> FastAPI:
    """Build the pirewall-portal app. `rpc_client` must be bound to the *portal* socket."""
    # Imported here, not at module scope, to keep the import cycle
    # (routes needs the dependency aliases above) local and obvious.
    from pirewall.portal import routes

    app = FastAPI(title="pirewall portal", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.pirewall_config = config
    app.state.pirewall_rpc_client = rpc_client
    app.add_exception_handler(RpcError, handle_core_unavailable)
    app.include_router(routes.router)
    routes.install_captive_probe_routes(app)
    return app

"""pirewall-api FastAPI app factory (spec §28, §29).

Never imports `pirewall.firewall.manager`, `pirewall.firewall.backend`, or
`pirewall.capture` (ADDENDUM.md A4, enforced by
`tests/security/test_api_process_isolation.py`) — every route reaches
pirewall-core exclusively through the injected `BaseRpcClient`.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.requests import HTTPConnection

from pirewall.api.auth import Authenticator, Session, SessionStore, enforce_admin_pc_ip
from pirewall.config.models import PirewallConfig
from pirewall.core.exceptions import AuthenticationError, RpcError
from pirewall.ipc.client import BaseRpcClient
from pirewall.web.render import render_core_unavailable_page

SESSION_COOKIE_NAME = "pirewall_session"


# `HTTPConnection` rather than `Request`: it is the common base of `Request`
# and `WebSocket`, so these three resolve on the WebSocket event stream as
# well as on every HTTP route. A `Request`-annotated dependency cannot be
# satisfied during a WebSocket handshake — FastAPI has no `Request` to pass.
def get_config(connection: HTTPConnection) -> PirewallConfig:
    config = connection.app.state.pirewall_config
    assert isinstance(config, PirewallConfig)
    return config


def get_rpc_client(connection: HTTPConnection) -> BaseRpcClient:
    client = connection.app.state.pirewall_rpc_client
    assert isinstance(client, BaseRpcClient)
    return client


def get_authenticator(connection: HTTPConnection) -> Authenticator:
    authenticator = connection.app.state.pirewall_authenticator
    assert isinstance(authenticator, Authenticator)
    return authenticator


ConfigDep = Annotated[PirewallConfig, Depends(get_config)]
RpcClientDep = Annotated[BaseRpcClient, Depends(get_rpc_client)]
AuthenticatorDep = Annotated[Authenticator, Depends(get_authenticator)]


def require_admin_pc(request: Request, config: ConfigDep) -> None:
    """Spec §29: restrict administrative access to the configured Admin PC IP."""
    client_host = request.client.host if request.client else None
    try:
        enforce_admin_pc_ip(client_host, str(config.admin.admin_pc_ip), config.security.restrict_to_admin_pc)
    except AuthenticationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def _extract_token(request: Request) -> str | None:
    header = request.headers.get("authorization")
    if header and header.lower().startswith("bearer "):
        return header[len("bearer ") :]
    return request.cookies.get(SESSION_COOKIE_NAME)


def require_session(request: Request, authenticator: AuthenticatorDep) -> Session:
    token = _extract_token(request)
    if token is None:
        raise HTTPException(status_code=401, detail="missing session token")
    try:
        return authenticator.authenticate(token, datetime.now(UTC))
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


SessionDep = Annotated[Session, Depends(require_session)]


def _handle_core_unavailable(request: Request, exc: Exception) -> Response:
    """An unreachable pirewall-core is a reportable state, not a 500 (ADDENDUM.md A6, spec §26).

    A6's justification for the A4 process split is that pirewall-api
    outlives a pirewall-core crash-loop and can therefore say so. Letting
    `RpcError` escape as an unhandled 500 wastes exactly that property, and
    surfaces a traceback where an operator needs a diagnosis.

    503 rather than 500: pirewall-api itself is healthy, its dependency is
    not — and 503 tells a polling Admin PC to retry.

    Typed as `Exception` because that is the signature Starlette's handler
    registry requires; only `RpcError` is ever routed here.
    """
    if request.url.path.startswith("/control-panel"):
        return HTMLResponse(render_core_unavailable_page(str(exc)), status_code=503)
    return JSONResponse({"detail": f"pirewall-core is unreachable: {exc}"}, status_code=503)


def create_app(
    config: PirewallConfig,
    rpc_client: BaseRpcClient,
    authenticator: Authenticator | None = None,
) -> FastAPI:
    """Build the pirewall-api FastAPI app.

    `authenticator` is injectable so tests can supply a fixed session/
    credential setup without going through real password hashing timings.
    """
    # Import routers lazily to keep any accidental heavy/forbidden import
    # (ADDENDUM.md A4) local to this one function, easy to spot in review.
    from pirewall.api.routes import allowlist, events_stream, firewall, health, read, rules
    from pirewall.api.routes import auth as auth_routes
    from pirewall.api.routes import config as config_routes
    from pirewall.web import routes as web_routes

    app = FastAPI(title="pirewall control panel", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.pirewall_config = config
    app.state.pirewall_rpc_client = rpc_client
    app.state.pirewall_authenticator = authenticator or Authenticator(
        config.authentication.admin_username,
        config.authentication.admin_password_hash,
        SessionStore(config.authentication.token_expiry_seconds),
    )

    if config.api.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(config.api.cors_origins),
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.add_exception_handler(RpcError, _handle_core_unavailable)

    protected = [Depends(require_admin_pc), Depends(require_session)]
    admin_pc_only = [Depends(require_admin_pc)]

    app.include_router(health.router)
    app.include_router(auth_routes.public_router, dependencies=admin_pc_only)
    app.include_router(auth_routes.protected_router, dependencies=protected)
    app.include_router(read.router, dependencies=protected)
    app.include_router(config_routes.router, dependencies=protected)
    app.include_router(events_stream.router, dependencies=protected)
    app.include_router(rules.router, dependencies=protected)
    app.include_router(allowlist.router, dependencies=protected)
    app.include_router(firewall.router, dependencies=protected)
    app.include_router(web_routes.public_router, dependencies=admin_pc_only)
    app.include_router(web_routes.protected_router, dependencies=protected)

    return app

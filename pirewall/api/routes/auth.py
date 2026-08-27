"""`POST /api/v1/auth/login`, `/logout` (spec §29).

Failed logins are reported into pirewall-core's shared audit trail via
`AUTHENTICATION_FAILURE` (spec §31) — pirewall-api holds no event log of
its own (ADDENDUM.md A4).
"""

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response

from pirewall.api.app import SESSION_COOKIE_NAME as _COOKIE_NAME
from pirewall.api.app import AuthenticatorDep, RpcClientDep, SessionDep
from pirewall.api.schemas import LoginRequest, LoginResponse, MessageResponse
from pirewall.core.enums import EventSeverity, SecurityEventType
from pirewall.core.exceptions import AuthenticationError
from pirewall.core.models.event import SecurityEvent

public_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
protected_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@public_router.post("/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    authenticator: AuthenticatorDep,
    rpc_client: RpcClientDep,
) -> LoginResponse:
    now = datetime.now(UTC)
    try:
        session = authenticator.login(body.username, body.password, now)
    except AuthenticationError as exc:
        rpc_client.record_event(
            SecurityEvent(
                timestamp=now,
                severity=EventSeverity.WARNING,
                event_type=SecurityEventType.AUTHENTICATION_FAILURE,
                subsystem="api.auth",
                reason=f"login failed for username {body.username!r}",
            )
        )
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    response.set_cookie(
        _COOKIE_NAME,
        session.token,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        expires=session.expires_at,
    )
    return LoginResponse(token=session.token, expires_at=session.expires_at)


@protected_router.post("/logout", response_model=MessageResponse)
def logout(response: Response, session: SessionDep, authenticator: AuthenticatorDep) -> MessageResponse:
    authenticator.logout(session.token)
    response.delete_cookie(_COOKIE_NAME)
    return MessageResponse(message="logged out")

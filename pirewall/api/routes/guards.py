"""v2 admin routes: guard modes, panic, offenders, bindings, engine stats (docs/V2_CONTRACTS.md §9).

Every route sits behind the same Admin-PC + session dependencies as the
rest of the API (`pirewall.api.app`). Two of them change the kernel:

* `POST /api/v1/guards/{guard}` flips one static guard. Switching to
  **enforce** starts dropping LAN traffic, so it needs the admin password
  again (ADDENDUM_4.md D2), refused with 403 and counted by the login
  throttle when wrong, exactly like an allowlist addition. Switching to
  observe only ever drops less, so the session is enough. pirewall-core
  audits every flip either way.
* `POST /api/v1/firewall/panic` deletes the v2 tables (D5). It needs the
  typed confirmation `{"confirm": "panic"}` and is audited at CRITICAL.
  Restoring is re-running `pirewall-start` on the Pi.

The reads are served by pirewall-core from published snapshots, outside its
RPC lock, so they answer while the pipeline is busy.
"""

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request

from pirewall.api.app import AuthenticatorDep, LoginThrottleDep, RpcClientDep, SessionDep
from pirewall.api.schemas import GuardModeRequest, PanicRequest
from pirewall.api.throttle import record_failed_authentication, refuse_if_locked_out
from pirewall.core.enums import GuardMode, GuardName
from pirewall.core.models.identity import Binding
from pirewall.ipc.protocol_v2 import EngineStats, GuardModes, OffenderEntry, PanicResult

router = APIRouter(prefix="/api/v1", tags=["v2"])


@router.get("/guards", response_model=GuardModes)
def get_guard_modes(rpc_client: RpcClientDep) -> GuardModes:
    """Every guard's mode as last read back from the kernel's verdict chains."""
    return rpc_client.get_guard_modes()


@router.post("/guards/{guard}", response_model=GuardModes)
def set_guard_mode(
    guard: GuardName,
    body: GuardModeRequest,
    request: Request,
    rpc_client: RpcClientDep,
    session: SessionDep,
    authenticator: AuthenticatorDep,
    throttle: LoginThrottleDep,
) -> GuardModes:
    """Flip one guard. ENFORCE needs `password`: 422 without it, 403 (and a throttle count) if wrong."""
    if body.mode is GuardMode.ENFORCE:
        now = datetime.now(UTC)
        client_host = request.client.host if request.client else None
        refuse_if_locked_out(throttle, client_host, now)
        if body.password is None:
            raise HTTPException(
                status_code=422, detail="switching a guard to enforce needs the admin password again"
            )
        if not authenticator.confirm_password(body.password.get_secret_value()):
            record_failed_authentication(
                throttle,
                rpc_client,
                client_host,
                now,
                f"password re-confirmation failed for guard {guard.value} -> enforce by {session.username!r}",
            )
            raise HTTPException(status_code=403, detail="password confirmation failed")
    return rpc_client.set_guard_mode(guard, body.mode, session.username)


@router.post("/firewall/panic", response_model=PanicResult)
def panic(body: PanicRequest, rpc_client: RpcClientDep, session: SessionDep) -> PanicResult:
    """Delete `inet pirewall_adaptive`, `inet pirewall_static` and `arp pirewall_static_arp` only.

    `body.confirm` must be the literal "panic" (422 otherwise). The response
    carries the exact restore command.
    """
    del body  # validated by the schema; its only field is the confirmation
    return rpc_client.panic(session.username)


@router.get("/offenders", response_model=list[OffenderEntry])
def list_offenders(rpc_client: RpcClientDep) -> list[OffenderEntry]:
    """The latest `@offenders` poll. Empty until the phase 17 kernel poller publishes one."""
    return list(rpc_client.list_offenders())


@router.get("/bindings", response_model=list[Binding])
def list_bindings(rpc_client: RpcClientDep) -> list[Binding]:
    """The current IP<->MAC bindings (lease file plus `[[antispoof.static]]`)."""
    return list(rpc_client.list_bindings())


@router.get("/engine", response_model=EngineStats)
def get_engine_stats(rpc_client: RpcClientDep) -> EngineStats:
    """Capture/flow engine counters: backend, ring support, frames, drops, shedding, panics."""
    return rpc_client.get_engine_stats()

"""`GET /api/v1/events/stream` — live `SecurityEvent` push over Server-Sent Events (spec §31).

Why SSE rather than a WebSocket
-------------------------------

This stream is strictly one-way: pirewall-core produces events, the Admin
PC watches them, and nothing is ever sent upstream over this channel. SSE
is plain HTTP chunked transfer, so it needs no protocol library beyond the
uvicorn already pinned in `pyproject.toml` — a WebSocket endpoint returns
404 under uvicorn unless `websockets` or `wsproto` is also installed, which
`CLAUDE.md`'s dependency list does not include. It also rides the same TLS,
the same `require_admin_pc`/`require_session` dependencies, and the same
cookie as every other route, and browsers implement `EventSource` natively
with automatic reconnection.

Why this is a poll-and-push bridge, not a real subscription
-----------------------------------------------------------

`SecurityEvent`s are produced in the *other* process. pirewall-api reaches
pirewall-core over one synchronous request/response `AF_UNIX` RPC socket
(ADDENDUM.md A4) with a deliberately closed operation set — there is no
subscribe/notify operation, and adding one would mean giving the privileged
process a long-lived push channel into the unprivileged one. So this
endpoint polls `list_events()` on an interval and forwards whatever is new.

The consequence, stated plainly: **latency is up to `_POLL_SECONDS`, and an
event can be missed** if more than `api.history_size` events are produced
between two polls (pirewall-core's history buffer is bounded, so the oldest
are evicted). This is a live *view*, not a delivery guarantee. The audit
trail of record is `GET /api/v1/events`, and — where configured — Wazuh,
which pirewall-core forwards to directly.

Wire format
-----------

Standard SSE. Each message is `event: <name>` plus a single-line JSON
`data:` field, terminated by a blank line:

```text
event: security_event
data: {"id": "...", "event_type": "threat_detected", ...}

event: error
data: {"detail": "pirewall-core is unreachable: ..."}

: keep-alive
```

`json.dumps` never emits a raw newline inside a string (it escapes them as
`\\n`), so one event is always exactly one `data:` line — which is what
keeps the framing unambiguous.
"""

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

from pirewall.api.app import RpcClientDep
from pirewall.core.exceptions import RpcError
from pirewall.core.models.event import SecurityEvent
from pirewall.ipc.client import BaseRpcClient

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["events"])

# How often pirewall-core is polled for new events. Half a second keeps the
# control panel feeling live while costing one tiny RPC round-trip per
# connected client per tick — the Admin PC is the only client.
_POLL_SECONDS = 0.5
# Events replayed on connect so a freshly opened panel is not blank.
_INITIAL_BACKLOG = 25
# Polls with nothing to send before a comment frame goes out. SSE comments
# are ignored by `EventSource` but keep the connection from being reaped by
# an idle timeout somewhere in between.
_KEEPALIVE_EVERY_N_POLLS = 30

_EVENT_NAME = "security_event"
_ERROR_NAME = "error"


def _sse(name: str, payload: dict[str, Any]) -> str:
    """Format one SSE message. `dict[str, Any]`: a JSON envelope, as at every API boundary."""
    return f"event: {name}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"


def _select_new(
    events: list[SecurityEvent], seen: set[str], first_pass: bool
) -> list[SecurityEvent]:
    """New events since the last poll, or a bounded backlog on the first pass."""
    if first_pass:
        return events[-_INITIAL_BACKLOG:]
    return [event for event in events if event.id not in seen]


async def event_source(rpc_client: BaseRpcClient) -> AsyncIterator[str]:
    """Poll pirewall-core and yield SSE frames until the client goes away.

    Public rather than private because it is the entire testable surface of
    this endpoint: Starlette's `TestClient` cannot read a never-ending
    `StreamingResponse` (it blocks before the first line, verified against
    a minimal FastAPI app), so the streaming behaviour has to be exercised
    by driving this generator directly.

    Ends when the consumer stops iterating — Starlette closes the generator
    on client disconnect, which surfaces here as `GeneratorExit`/
    `CancelledError` and needs no handling of its own.
    """
    # Ids seen in the previous poll. Bounded by `api.history_size` because it
    # is replaced (not merged) each pass, so a long-lived connection cannot
    # grow this without limit.
    seen: set[str] = set()
    first_pass = True
    quiet_polls = 0
    while True:
        try:
            events = await run_in_threadpool(rpc_client.list_events)
        except RpcError as exc:
            # A6: an unreachable core is a reportable state, not a dropped
            # connection. Keep streaming — core may be mid-restart.
            yield _sse(_ERROR_NAME, {"detail": f"pirewall-core is unreachable: {exc}"})
            await asyncio.sleep(_POLL_SECONDS)
            continue

        fresh = _select_new(events, seen, first_pass)
        seen = {event.id for event in events}
        first_pass = False

        if fresh:
            quiet_polls = 0
            for event in fresh:
                yield _sse(_EVENT_NAME, event.model_dump(mode="json"))
        else:
            quiet_polls += 1
            if quiet_polls >= _KEEPALIVE_EVERY_N_POLLS:
                quiet_polls = 0
                yield ": keep-alive\n\n"
        await asyncio.sleep(_POLL_SECONDS)


@router.get("/events/stream")
def stream_events(rpc_client: RpcClientDep) -> StreamingResponse:
    """Stream `SecurityEvent`s to the Admin PC as they are recorded by pirewall-core.

    Authentication and the Admin-PC restriction come from the router's own
    dependencies, identically to every other endpoint — there is nothing
    special about this route's access control.
    """
    return StreamingResponse(
        event_source(rpc_client),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            # Belt and braces if the Admin PC ever sits behind a reverse
            # proxy: buffering an event stream defeats the point of it.
            "X-Accel-Buffering": "no",
        },
    )

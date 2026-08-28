"""The two API surfaces added with the entry points: `GET /config` and the event stream.

`GET /api/v1/config` is read-only by design — there is no write counterpart
anywhere in the API, because a control panel that could rewrite
`enforcement_mode` or `admin_pc_ip` over HTTP would make a compromised
session equivalent to owning the firewall (spec §45).

`GET /api/v1/events/stream` is Server-Sent Events, not a WebSocket: SSE is
plain chunked HTTP, so it works on the uvicorn already pinned and inherits
the router's ordinary authentication rather than needing a hand-rolled
handshake check.
"""

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from pirewall.api.routes.events_stream import event_source
from pirewall.core.enums import EventSeverity, SecurityEventType
from pirewall.core.exceptions import RpcError
from pirewall.core.models.event import SecurityEvent
from pirewall.ipc.client import BaseRpcClient
from tests.helpers.api import auth_headers, login, make_harness

NOW = datetime(2026, 1, 1, tzinfo=UTC)

_STREAM_URL = "/api/v1/events/stream"

# Called with the running frame count after each frame the generator yields.
OnFrame = Callable[[int], None] | None


def _event(reason: str) -> SecurityEvent:
    return SecurityEvent(
        timestamp=NOW,
        severity=EventSeverity.WARNING,
        event_type=SecurityEventType.THREAT_DETECTED,
        subsystem="test",
        reason=reason,
    )


class TestConfigEndpoint:
    def test_returns_the_running_configuration(self) -> None:
        harness = make_harness(NOW)
        token = login(harness)

        response = harness.get("/api/v1/config", headers=auth_headers(token))

        assert response.status_code == 200
        body: dict[str, Any] = response.json()
        assert body["firewall"]["enforcement_mode"] == "shadow"
        assert body["network"]["wan_interface"] == "eth0"
        assert body["failure"]["mode"] == "fail_open"

    def test_secret_bearing_fields_are_redacted(self) -> None:
        """A password hash is offline-crackable; TLS paths are reconnaissance."""
        harness = make_harness(NOW)
        token = login(harness)

        body: dict[str, Any] = harness.get("/api/v1/config", headers=auth_headers(token)).json()

        assert body["authentication"]["admin_password_hash"] == "***redacted***"
        assert body["api"]["tls_cert_path"] == "***redacted***"
        assert body["api"]["tls_key_path"] == "***redacted***"
        # The real hash must not appear anywhere in the response.
        assert harness.config.authentication.admin_password_hash not in str(body)

    def test_unset_optionals_stay_null_rather_than_looking_redacted(self) -> None:
        """Wazuh disabled means there is no host to hide, not a hidden host."""
        harness = make_harness(NOW)
        token = login(harness)

        body: dict[str, Any] = harness.get("/api/v1/config", headers=auth_headers(token)).json()

        assert body["integration"]["wazuh_host"] is None
        assert body["integration"]["wazuh_enabled"] is False

    def test_requires_a_session(self) -> None:
        harness = make_harness(NOW)
        assert harness.get("/api/v1/config").status_code == 401

    def test_requires_the_admin_pc(self) -> None:
        """spec §29 applies to the config dump like every other admin endpoint."""
        harness = make_harness(NOW, client_address=("192.168.1.99", 5555))
        assert harness.get("/api/v1/config").status_code == 403

    def test_there_is_no_write_counterpart(self) -> None:
        harness = make_harness(NOW)
        token = login(harness)
        for method in (harness.post, harness.delete):
            response = method("/api/v1/config", headers=auth_headers(token))
            assert response.status_code == 405


class TestEventStreamRoute:
    """Route-level access control for `GET /api/v1/events/stream`.

    Only the handshake is asserted through `TestClient`. It cannot read a
    never-ending `StreamingResponse` at all — verified against a minimal
    FastAPI app, where `client.stream(...)` blocks before yielding a single
    line — so the streaming behaviour itself is tested against the real
    generator in `TestEventSource` below, and end to end against real
    uvicorn (see docs/DEPLOYMENT_COMPLETE.md).
    """

    def test_requires_a_session(self) -> None:
        assert make_harness(NOW).get(_STREAM_URL).status_code == 401

    def test_requires_the_admin_pc(self) -> None:
        """spec §29 applies through the same router dependency as every other route."""
        harness = make_harness(NOW, client_address=("192.168.1.99", 5555))
        assert harness.get(_STREAM_URL).status_code == 403


def _drive(client: BaseRpcClient, frames_wanted: int, on_frame: OnFrame = None) -> list[str]:
    """Run the real SSE generator until it has produced `frames_wanted` frames.

    `on_frame` is called after each frame, so a test can record a new event
    mid-stream and assert it gets pushed on the next poll — the property
    that makes this a live stream rather than a one-shot dump.
    """

    async def run() -> list[str]:
        frames: list[str] = []
        async for frame in event_source(client):
            frames.append(frame)
            if on_frame is not None:
                on_frame(len(frames))
            if len(frames) >= frames_wanted:
                break
        return frames

    return asyncio.run(run())


def _parse(frame: str) -> tuple[str, Any]:
    """Split one SSE frame into `(event name, parsed data)`."""
    name = ""
    for line in frame.splitlines():
        if line.startswith("event:"):
            name = line[len("event:") :].strip()
        elif line.startswith("data:"):
            return name, json.loads(line[len("data:") :].strip())
    raise AssertionError(f"frame carried no data: {frame!r}")


class TestEventSource:
    """`event_source` — the poll-and-push bridge itself (spec §31, ADDENDUM.md A4/A6)."""

    def test_replays_a_bounded_backlog_on_connect(self) -> None:
        """A freshly opened panel should not be blank, but must not dump unbounded history."""
        harness = make_harness(NOW)
        for index in range(40):
            harness.state.record_event(_event(f"event-{index}"))

        frames = _drive(harness.rpc_client, frames_wanted=25)

        parsed = [_parse(frame) for frame in frames]
        assert {name for name, _ in parsed} == {"security_event"}
        # The 25 most recent, in order — not all 40.
        assert [payload["reason"] for _, payload in parsed] == [
            f"event-{index}" for index in range(15, 40)
        ]

    def test_pushes_events_recorded_after_the_stream_opened(self) -> None:
        harness = make_harness(NOW)
        harness.state.record_event(_event("already happened"))
        client = harness.rpc_client

        def _record_after_first(count: int) -> None:
            if count == 1:
                harness.state.record_event(_event("just now"))

        frames = _drive(client, frames_wanted=2, on_frame=_record_after_first)

        assert [_parse(frame)[1]["reason"] for frame in frames] == ["already happened", "just now"]

    def test_an_event_is_never_split_across_data_lines(self) -> None:
        """A newline inside a reason would break SSE framing if json.dumps did not escape it."""
        harness = make_harness(NOW)
        harness.state.record_event(_event("line one\nline two"))

        frames = _drive(harness.rpc_client, frames_wanted=1)

        assert frames[0].count("data:") == 1
        _, payload = _parse(frames[0])
        assert payload["reason"] == "line one\nline two"

    def test_an_unreachable_core_is_streamed_as_an_error_not_a_dropped_connection(self) -> None:
        """A6: pirewall-api outlives a crash-looping core specifically so it can say so."""
        harness = make_harness(NOW)
        client = harness.rpc_client

        def _dead(*_args: object, **_kwargs: object) -> None:
            raise RpcError("failed to reach pirewall-core at /run/pirewall/core.sock")

        setattr(client, "_call", _dead)  # noqa: B010 — deliberate stub of a private hook

        frames = _drive(client, frames_wanted=2)

        for frame in frames:
            name, payload = _parse(frame)
            assert name == "error"
            assert "pirewall-core is unreachable" in payload["detail"]

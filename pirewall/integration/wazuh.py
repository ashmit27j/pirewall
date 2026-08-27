"""Forward `SecurityEvent`s to Wazuh on the Admin PC (spec §32).

This is a forwarder, not a second SIEM: it shapes each `SecurityEvent` into
a structured JSON payload and hands it to a `WazuhTransport`. It never
stores, queries, correlates, or retains events itself — `CoreStateStore`
already holds the bounded recent-history buffer pirewall itself needs.

`SyslogWazuhTransport` speaks RFC 5424-ish syslog over TCP to the Wazuh
agent's syslog collector, the standard way to feed Wazuh from a
non-agent-installed source. It requires a real Wazuh agent listening on the
Admin PC and is therefore **Environment-dependent** — see
`docs/PROGRESS.md`. `pirewall.integration.fake.FakeWazuhTransport` exercises
`WazuhForwarder`'s payload shaping without any real network I/O.
"""

import json
import socket
from typing import Protocol, runtime_checkable

from pirewall.core.exceptions import IntegrationError
from pirewall.core.models.event import SecurityEvent

_SOURCE = "pirewall"


@runtime_checkable
class WazuhTransport(Protocol):
    """Contract for sending one already-formatted message to Wazuh."""

    def send(self, message: str) -> None:
        """Deliver `message`. Raises `pirewall.core.exceptions.IntegrationError` on failure."""
        ...


def format_event(event: SecurityEvent) -> dict[str, object]:
    """Shape a `SecurityEvent` into a structured, Wazuh-correlation-friendly dict.

    Excludes fields that are `None` so the resulting JSON only ever carries
    information that's actually known about the event (spec §31 "do not
    include unnecessary sensitive information").
    """
    payload: dict[str, object] = {
        "source": _SOURCE,
        "id": event.id,
        "timestamp": event.timestamp.isoformat(),
        "severity": event.severity.value,
        "event_type": event.event_type.value,
        "subsystem": event.subsystem,
    }
    if event.source is not None:
        payload["source_ip"] = str(event.source)
    if event.destination is not None:
        payload["destination_ip"] = str(event.destination)
    if event.protocol is not None:
        payload["protocol"] = event.protocol.value
    if event.flow_id is not None:
        payload["flow_id"] = event.flow_id
    if event.threat_score is not None:
        payload["threat_score"] = event.threat_score
    if event.decision is not None:
        payload["decision"] = event.decision.value
    if event.rule_id is not None:
        payload["rule_id"] = event.rule_id
    if event.reason is not None:
        payload["reason"] = event.reason
    if event.model_version is not None:
        payload["model_version"] = event.model_version
    return payload


class WazuhForwarder:
    """Shapes `SecurityEvent`s to JSON and hands them to a `WazuhTransport`."""

    def __init__(self, transport: WazuhTransport, *, enabled: bool) -> None:
        self._transport = transport
        self._enabled = enabled

    def forward(self, event: SecurityEvent) -> None:
        """Forward `event` if enabled. A no-op when `enabled=False` (spec §37 opt-in integration)."""
        if not self._enabled:
            return
        message = json.dumps(format_event(event), sort_keys=True)
        self._transport.send(message)


class SyslogWazuhTransport:
    """Real `WazuhTransport`: sends each message as one line over a TCP syslog connection.

    Opens and closes a connection per message rather than holding one open —
    pirewall-core emits events at human-scale, not high-frequency-trading
    scale, so simplicity wins over connection reuse here. Requires a real
    Wazuh agent/forwarder listening at `host:port` on the Admin PC —
    **Environment-dependent**, cannot be exercised on a dev machine.
    """

    def __init__(self, host: str, port: int, *, timeout_seconds: float = 5.0) -> None:
        self._host = host
        self._port = port
        self._timeout_seconds = timeout_seconds

    def send(self, message: str) -> None:
        try:
            with socket.create_connection(
                (self._host, self._port), timeout=self._timeout_seconds
            ) as sock:
                sock.sendall(message.encode("utf-8") + b"\n")
        except OSError as exc:
            raise IntegrationError(
                f"failed to forward event to Wazuh at {self._host}:{self._port}: {exc}"
            ) from exc

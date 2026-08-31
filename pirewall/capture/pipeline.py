"""Ties `PacketCapture` and `pirewall.capture.parser` into one capture loop (spec §6, §7)."""

import logging
from collections.abc import Callable, Iterator
from datetime import UTC, datetime

from pirewall.capture.interfaces import PacketCapture
from pirewall.capture.parser import parse_packet
from pirewall.core.enums import EventSeverity, Protocol, SecurityEventType
from pirewall.core.exceptions import PacketParseError
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.packet import PacketMetadata

_logger = logging.getLogger(__name__)

EventSink = Callable[[SecurityEvent], None]

# ADDENDUM_2.md B4/B5's own port-443 heuristic for "is this traffic worth
# TLS-record-layer inspection at all" — applied here too, purely so this
# hot loop doesn't invoke `on_tcp_payload` (and its caller doesn't extract a
# payload slice) for the overwhelming majority of TCP traffic that plainly
# isn't a TLS connection.
_TLS_PORT = 443

type TcpPayloadSink = Callable[[PacketMetadata, bytes], None]


def capture_packets(
    capture: PacketCapture,
    on_event: EventSink | None = None,
    on_tcp_payload: TcpPayloadSink | None = None,
) -> Iterator[PacketMetadata]:
    """Read raw packets from `capture` and yield each one successfully parsed.

    A packet that fails to parse is recorded via `capture.record_malformed()`
    and logged, then skipped — it is never raised to the caller. This is
    what makes "malformed packets must never crash pirewall" (spec §7) true
    at the loop level, not just inside the parser.

    `on_event`, when provided, also gets a `CAPTURE_ERROR` `SecurityEvent`
    per malformed packet (spec §26/§31) — optional because this module has
    no owner for a shared event log of its own; whatever wires
    `pirewall-core`'s main loop together (Phase 8) supplies one, e.g.
    `pirewall.ipc.state.CoreStateStore.record_event`.

    `on_tcp_payload` (ADDENDUM_2.md B4/B5), when provided, is called with
    this module's already-parsed `PacketMetadata` plus the original raw
    frame bytes, for every successfully-parsed TCP packet on port 443 —
    never for anything else, and never with anything this loop couldn't
    already parse. This module does not itself extract or inspect payload
    bytes; it only hands the raw frame onward so a caller that wants to
    (`pirewall.runtime.core.CoreDaemon`, via `pirewall.capture.parser.
    extract_tcp_payload`) can, without this hot loop depending on the
    detection layer at all — same `Callable`-not-import pattern as
    `on_event` and `pirewall.flow.aggregator.FlowAggregator.on_new_flow`.
    """
    for captured in capture.read_packets():
        try:
            metadata = parse_packet(captured.raw, captured.captured_at)
        except PacketParseError as exc:
            capture.record_malformed()
            _logger.warning("dropping malformed packet: %s", exc)
            if on_event is not None:
                on_event(
                    SecurityEvent(
                        timestamp=datetime.now(UTC),
                        severity=EventSeverity.WARNING,
                        event_type=SecurityEventType.CAPTURE_ERROR,
                        subsystem="capture.pipeline",
                        reason=str(exc),
                    )
                )
            continue

        if (
            on_tcp_payload is not None
            and metadata.protocol is Protocol.TCP
            and _TLS_PORT in (metadata.source_port, metadata.destination_port)
        ):
            on_tcp_payload(metadata, captured.raw)
        yield metadata

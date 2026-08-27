"""Ties `PacketCapture` and `pirewall.capture.parser` into one capture loop (spec §6, §7)."""

import logging
from collections.abc import Callable, Iterator
from datetime import UTC, datetime

from pirewall.capture.interfaces import PacketCapture
from pirewall.capture.parser import parse_packet
from pirewall.core.enums import EventSeverity, SecurityEventType
from pirewall.core.exceptions import PacketParseError
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.packet import PacketMetadata

_logger = logging.getLogger(__name__)

EventSink = Callable[[SecurityEvent], None]


def capture_packets(capture: PacketCapture, on_event: EventSink | None = None) -> Iterator[PacketMetadata]:
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
    """
    for captured in capture.read_packets():
        try:
            yield parse_packet(captured.raw, captured.captured_at)
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

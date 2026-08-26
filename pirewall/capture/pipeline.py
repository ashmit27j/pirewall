"""Ties `PacketCapture` and `pirewall.capture.parser` into one capture loop (spec §6, §7)."""

import logging
from collections.abc import Iterator

from pirewall.capture.interfaces import PacketCapture
from pirewall.capture.parser import parse_packet
from pirewall.core.exceptions import PacketParseError
from pirewall.core.models.packet import PacketMetadata

_logger = logging.getLogger(__name__)


def capture_packets(capture: PacketCapture) -> Iterator[PacketMetadata]:
    """Read raw packets from `capture` and yield each one successfully parsed.

    A packet that fails to parse is recorded via `capture.record_malformed()`
    and logged, then skipped — it is never raised to the caller. This is
    what makes "malformed packets must never crash pirewall" (spec §7) true
    at the loop level, not just inside the parser.
    """
    for captured in capture.read_packets():
        try:
            yield parse_packet(captured.raw, captured.captured_at)
        except PacketParseError as exc:
            capture.record_malformed()
            _logger.warning("dropping malformed packet: %s", exc)

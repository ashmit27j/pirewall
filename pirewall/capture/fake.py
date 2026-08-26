"""`FakePacketCapture`: an in-memory `PacketCapture` for tests (spec §39).

Lets flow aggregation, feature extraction, and this phase's own capture-loop
tests run without root privileges or a real NIC.
"""

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime

from pirewall.capture.interfaces import CapturedPacket
from pirewall.core.exceptions import CaptureError
from pirewall.core.models.capture_stats import CaptureStatistics


class FakePacketCapture:
    """Yields packets from a caller-supplied in-memory sequence.

    `packets` may mix real packet bytes with `None` entries, each `None`
    simulating one packet the OS/socket dropped before it could be
    delivered (mirrors what `AFPacketCapture` reports via kernel drop
    statistics) — it is counted in `packets_dropped` but never yielded.
    """

    def __init__(self, interface: str, packets: Sequence[bytes | None]) -> None:
        self._interface = interface
        self._packets = packets
        self._running = False
        self._packets_seen = 0
        self._packets_dropped = 0
        self._packets_malformed = 0

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def read_packets(self) -> Iterator[CapturedPacket]:
        if not self._running:
            raise CaptureError("cannot read packets before start() is called")
        for packet in self._packets:
            if not self._running:
                return
            if packet is None:
                self._packets_dropped += 1
                continue
            self._packets_seen += 1
            yield CapturedPacket(raw=packet, captured_at=datetime.now(UTC))

    def record_malformed(self) -> None:
        self._packets_malformed += 1

    def statistics(self) -> CaptureStatistics:
        return CaptureStatistics(
            interface=self._interface,
            packets_seen=self._packets_seen,
            packets_dropped=self._packets_dropped,
            packets_malformed=self._packets_malformed,
        )

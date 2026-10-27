"""`FakePacketCapture`: an in-memory `PacketCapture` for tests (spec §39).

Lets flow aggregation, feature extraction, and this phase's own capture-loop
tests run without root privileges or a real NIC.
"""

import time
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from pirewall.capture.interfaces import CapturedPacket
from pirewall.core.exceptions import CaptureError
from pirewall.core.models.capture_stats import CaptureStatistics

if TYPE_CHECKING:
    from pirewall_native import FlowEngine  # pyright: ignore[reportMissingModuleSource]

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


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


class FakeFlowCapture:
    """An in-memory `FlowCapture` for tests: replays frames into a native `FlowEngine`.

    The test double for `pirewall.capture.native.NativePacketCapture` — the
    engine is the real one (the code under test), only the ring is faked.
    Frames are timestamped with the wall clock as they are fed, like
    `FakePacketCapture`; `None` entries count as kernel drops.
    """

    def __init__(self, interface: str, engine: "FlowEngine", packets: Sequence[bytes | None]) -> None:
        self._interface = interface
        self._engine = engine
        self._pending = list(packets)
        self._running = False
        self._dropped = 0

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def poll(self, timeout_ms: int) -> int:
        if not self._running:
            return 0
        if not self._pending:
            time.sleep(timeout_ms / 1000.0)
            return 0
        fed = 0
        for frame in self._pending:
            if frame is None:
                self._dropped += 1
                continue
            since_epoch = datetime.now(UTC) - _EPOCH
            microseconds = (since_epoch.days * 86_400 + since_epoch.seconds) * 1_000_000
            self._engine.feed(frame, microseconds + since_epoch.microseconds)
            fed += 1
        self._pending.clear()
        return fed

    def statistics(self) -> CaptureStatistics:
        seen, malformed = self._engine.counters()
        return CaptureStatistics(
            interface=self._interface,
            packets_seen=seen,
            packets_dropped=self._dropped,
            packets_malformed=malformed,
        )

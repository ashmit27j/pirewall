"""The `PacketCapture` contract (spec §6).

Hardware-dependent capture gets exactly one real implementation
(`pirewall.capture.af_packet.AFPacketCapture`) and one test double
(`pirewall.capture.fake.FakePacketCapture`) — every consumer of capture
(the future flow aggregator, and this phase's own tests) depends only on
this `Protocol`, never on a concrete implementation, per CLAUDE.md's
Protocol/Fake rule.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from pirewall.core.models.capture_stats import CaptureStatistics


@dataclass(frozen=True, slots=True)
class CapturedPacket:
    """A raw captured packet: bytes off the wire plus the time it was captured.

    Deliberately not a Pydantic model — this is an internal, hot-path
    plumbing type between capture and parsing, not a domain object that
    crosses a subsystem boundary (spec §9 lists `PacketMetadata`, the parsed
    result, as the domain model; the raw bytes never outlive parsing).
    """

    raw: bytes
    captured_at: datetime


@runtime_checkable
class PacketCapture(Protocol):
    """Contract for capturing raw packets from a network interface.

    Implementations must never retain `raw` bytes beyond what a single
    `read_packets()` consumer needs to parse them (spec §6 "avoid retaining
    raw packets unnecessarily").
    """

    def start(self) -> None:
        """Bind to the configured interface and begin capturing.

        Raises `pirewall.core.exceptions.CaptureError` if binding fails
        (interface down, insufficient privileges, unsupported platform).
        """
        ...

    def stop(self) -> None:
        """Gracefully release the capture resource (spec §6). Idempotent."""
        ...

    def read_packets(self) -> Iterator[CapturedPacket]:
        """Yield captured packets until `stop()` is called or capture ends."""
        ...

    def record_malformed(self) -> None:
        """Record that a packet yielded by `read_packets()` failed to parse.

        Parsing lives in a separate module (`pirewall.capture.parser`); the
        capture implementation is the single owner of capture statistics
        (spec §6 "expose capture statistics ... malformed count"), so the
        loop that parses packets reports failures back here.
        """
        ...

    def statistics(self) -> CaptureStatistics:
        """Return a snapshot of this capture session's counters."""
        ...

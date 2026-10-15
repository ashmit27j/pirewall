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
from ipaddress import IPv4Address
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


@dataclass(frozen=True, slots=True)
class TcpPayload:
    """One IPv4 TCP segment's payload, offered to the TLS structural detectors (ADDENDUM_2.md B4/B5).

    Internal hot-path plumbing like `CapturedPacket`, not a domain model.
    Produced by the Python capture loop (from `parser.extract_tcp_payload`)
    or by the native engine (pre-filtered to records the detectors can act
    on: a heartbeat or a ClientHello).
    """

    source_ip: IPv4Address
    destination_ip: IPv4Address
    source_port: int | None
    destination_port: int | None
    timestamp: datetime
    payload: bytes


@runtime_checkable
class FlowCapture(Protocol):
    """Contract for a capture that aggregates flows itself (the native engine).

    Where a `PacketCapture` yields packets for Python to parse and
    aggregate, a `FlowCapture` feeds an engine handle that does both
    natively; the caller then drains that engine for completed flows,
    new-flow signals and TLS candidate payloads. Real implementation:
    `pirewall.capture.native.NativePacketCapture`; test double:
    `pirewall.capture.fake.FakeFlowCapture`.
    """

    def start(self) -> None:
        """Bind to the interface. Raises `CaptureError` on failure."""
        ...

    def stop(self) -> None:
        """Stop polling and release the capture resource. Idempotent."""
        ...

    def poll(self, timeout_ms: int) -> int:
        """Wait up to `timeout_ms` for packets and feed every ready one into the engine.

        Returns how many were processed (0 on timeout or after `stop()`).
        Raises `CaptureError` on a capture failure.
        """
        ...

    def statistics(self) -> CaptureStatistics:
        """Return a snapshot of this capture session's counters."""
        ...

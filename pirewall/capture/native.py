"""`NativePacketCapture`: `AF_PACKET` `TPACKET_V3` capture via the native extension.

The real `FlowCapture` (see `pirewall.capture.interfaces`). Packets are read
from a memory-mapped ring the kernel fills in whole blocks, timestamped by
the kernel, and fed straight into a native `FlowEngine` with the GIL
released — they never become Python objects. This is what replaces
`AFPacketCapture` + `parse_packet` + `FlowAggregator.process_packet` on the
Pi, where those three, in Python, could not keep pace with a 10k pkt/s
flood (benchmarks/2026-09-10-attack-lab: 94% dropped).

Linux-only and privileged (`CAP_NET_RAW`), like `AFPacketCapture`;
Environment-dependent — see docs/PROGRESS.md for what has and has not been
exercised on real hardware. The engine arrives as an opaque handle; the
only thing taken from `pirewall.flow.native` is the error translation, so a
panic while feeding the ring surfaces as
`pirewall.core.exceptions.NativeEngineError` (a `CaptureError`).
"""

import importlib
from typing import TYPE_CHECKING

from pirewall.core.exceptions import CaptureError
from pirewall.core.models.capture_stats import CaptureStatistics
from pirewall.flow.native import translate_native_errors

if TYPE_CHECKING:
    from pirewall_native import (  # pyright: ignore[reportMissingModuleSource]
        FlowEngine,
        PacketRing,
    )

# Upper bound on packets handled per `poll` before control returns to Python
# to drain the engine — bounds how much work one drain has to convert.
_MAX_PACKETS_PER_POLL = 20_000


def _load_ring_class() -> "type[PacketRing] | None":
    try:
        module = importlib.import_module("pirewall_native")
    except ImportError:  # optional extension
        return None
    if not module.HAS_PACKET_RING:
        return None
    # `ModuleType` attributes are `Any` to the type checker; the stub in
    # typings/pirewall_native.pyi pins what this actually is.
    ring_class: type[PacketRing] = module.PacketRing
    return ring_class


_RING_CLASS = _load_ring_class()


def native_capture_available() -> bool:
    """Whether the native extension is installed *and* built with ring support (Linux)."""
    return _RING_CLASS is not None


class NativePacketCapture:
    """`FlowCapture` backed by a `TPACKET_V3` ring feeding a native `FlowEngine`."""

    def __init__(
        self,
        interface: str,
        engine: "FlowEngine",
        promiscuous: bool,
        block_size_bytes: int,
        block_count: int,
        block_timeout_ms: int,
    ) -> None:
        self._interface = interface
        self._engine = engine
        self._promiscuous = promiscuous
        self._block_size = block_size_bytes
        self._block_count = block_count
        self._block_timeout_ms = block_timeout_ms
        self._ring: PacketRing | None = None
        self._kernel_drops = 0

    def start(self) -> None:
        """Create and bind the ring. Raises `CaptureError` on any failure (A6 handles it)."""
        if self._ring is not None:
            return
        if _RING_CLASS is None:
            raise CaptureError(
                "native capture unavailable: pirewall_native is not installed or was built "
                "without AF_PACKET ring support (Linux only)"
            )
        try:
            self._ring = _RING_CLASS(
                self._interface,
                self._promiscuous,
                self._block_size,
                self._block_count,
                self._block_timeout_ms,
            )
        except (OSError, ValueError) as exc:
            raise CaptureError(f"failed to open capture ring on {self._interface}: {exc}") from exc

    def stop(self) -> None:
        """Stop polling and release the ring. Idempotent; returns within one poll timeout."""
        ring = self._ring
        if ring is None:
            return
        self._kernel_drops = ring.kernel_drops()
        ring.close()
        self._ring = None

    def poll(self, timeout_ms: int) -> int:
        """Feed every ready packet into the engine; 0 on timeout or once stopped.

        Raises `NativeEngineError` if the engine panicked mid-block (the rest
        of that block is lost; the ring itself keeps moving).
        """
        ring = self._ring
        if ring is None:
            return 0
        try:
            with translate_native_errors():
                return ring.poll(self._engine, timeout_ms, _MAX_PACKETS_PER_POLL)
        except OSError as exc:
            raise CaptureError(f"error reading capture ring on {self._interface}: {exc}") from exc

    def statistics(self) -> CaptureStatistics:
        """Seen/malformed from the engine (live, not tick-sampled); drops from the kernel."""
        with translate_native_errors():
            seen, malformed = self._engine.counters()
        ring = self._ring
        if ring is not None:
            self._kernel_drops = ring.kernel_drops()
        return CaptureStatistics(
            interface=self._interface,
            packets_seen=seen,
            packets_dropped=self._kernel_drops,
            packets_malformed=malformed,
        )

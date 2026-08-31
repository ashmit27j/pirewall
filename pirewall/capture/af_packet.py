"""`AFPacketCapture`: the real Linux AF_PACKET capture implementation (spec §6).

Linux-only and privileged (raw sockets require `CAP_NET_RAW`). Cannot be
exercised outside a real Raspberry Pi / Linux host with a real interface —
see `docs/PROGRESS.md` Phase 2 for the Environment-dependent label and what
a human needs to do to verify it.
"""

import socket
import struct
from collections.abc import Iterator
from datetime import UTC, datetime

from pirewall.capture.interfaces import CapturedPacket
from pirewall.core.exceptions import CaptureError
from pirewall.core.models.capture_stats import CaptureStatistics

_ETH_P_ALL = 0x0003

# Linux <linux/if_packet.h> constants. Not exposed by name in the stdlib
# `socket` module, so they're reproduced here directly from the kernel UAPI
# header (stable ABI, safe to hardcode).
_SOL_PACKET = 263
_PACKET_ADD_MEMBERSHIP = 1
_PACKET_MR_PROMISC = 1
_PACKET_STATISTICS = 6
# struct packet_mreq { int mr_ifindex; unsigned short mr_type, mr_alen;
#                       unsigned char mr_address[8]; }
_PACKET_MREQ_FORMAT = "IHH8s"
# struct tpacket_stats { unsigned int tp_packets, tp_drops; }
_PACKET_STATS_FORMAT = "II"


class AFPacketCapture:
    """`PacketCapture` backed by a Linux `AF_PACKET`/`SOCK_RAW` socket."""

    def __init__(
        self,
        interface: str,
        snap_len: int,
        promiscuous: bool,
        buffer_size_bytes: int,
    ) -> None:
        self._interface = interface
        self._snap_len = snap_len
        self._promiscuous = promiscuous
        self._buffer_size_bytes = buffer_size_bytes
        self._socket: socket.socket | None = None
        self._running = False
        self._packets_seen = 0
        self._packets_malformed = 0
        self._packets_dropped_cumulative = 0

    def start(self) -> None:
        """Bind an AF_PACKET socket to `interface`. Raises `CaptureError` on failure.

        Includes the "this platform has no `AF_PACKET` at all" case. That is
        an `AttributeError` from the stdlib, not an `OSError`, so without an
        explicit check it would escape as an untyped exception and crash
        whatever is running the capture loop — bypassing the caller's
        graceful "capture unavailable, keep serving" handling (ADDENDUM.md
        A6) and violating the rule that no subsystem lets a stdlib exception
        cross its boundary (spec §44, CLAUDE.md). It is reachable in
        practice: pirewall is developed on macOS and only deployed on Linux.
        """
        if self._socket is not None:
            return
        if not hasattr(socket, "AF_PACKET"):
            raise CaptureError(
                f"cannot capture on {self._interface}: this platform has no AF_PACKET support "
                "(packet capture requires Linux). Use pirewall.capture.fake.FakePacketCapture "
                "for development off-Linux."
            )
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
            sock.bind((self._interface, 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self._buffer_size_bytes)
            if self._promiscuous:
                self._enable_promiscuous(sock)
        except OSError as exc:
            raise CaptureError(
                f"failed to bind capture socket on {self._interface}: {exc}"
            ) from exc
        self._socket = sock
        self._running = True

    def _enable_promiscuous(self, sock: socket.socket) -> None:
        try:
            ifindex = socket.if_nametoindex(self._interface)
            mreq = struct.pack(_PACKET_MREQ_FORMAT, ifindex, _PACKET_MR_PROMISC, 0, b"")
            sock.setsockopt(_SOL_PACKET, _PACKET_ADD_MEMBERSHIP, mreq)
        except OSError as exc:
            raise CaptureError(
                f"failed to enable promiscuous mode on {self._interface}: {exc}"
            ) from exc

    def stop(self) -> None:
        """Close the capture socket. Idempotent."""
        self._running = False
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def read_packets(self) -> Iterator[CapturedPacket]:
        """Yield packets until `stop()` closes the socket.

        Raises `CaptureError` on a read failure that isn't simply the
        socket having been closed by a concurrent `stop()`.
        """
        if self._socket is None:
            raise CaptureError("cannot read packets before start() is called")
        sock = self._socket
        while self._running:
            try:
                raw = sock.recv(self._snap_len)
            except OSError as exc:
                if not self._running:
                    return
                raise CaptureError(f"error reading from capture socket: {exc}") from exc
            self._packets_seen += 1
            yield CapturedPacket(raw=raw, captured_at=datetime.now(UTC))

    def record_malformed(self) -> None:
        self._packets_malformed += 1

    def statistics(self) -> CaptureStatistics:
        return CaptureStatistics(
            interface=self._interface,
            packets_seen=self._packets_seen,
            packets_dropped=self._read_kernel_drops(),
            packets_malformed=self._packets_malformed,
        )

    def _read_kernel_drops(self) -> int:
        """Best-effort: kernel-reported drops via `PACKET_STATISTICS` (spec §6).

        The kernel zeroes `tp_drops` every time it's read via this
        `getsockopt` — so the raw value from one call is only the count
        *since the previous read*, not a lifetime total. `statistics()`
        exports `packets_dropped` as a cumulative counter (matching
        `packets_seen`/`packets_malformed`), so this accumulates each read's
        delta into `self._packets_dropped_cumulative` and returns the
        running sum rather than the raw per-read value — otherwise a
        dashboard differencing consecutive readings as a counter would see
        it drop and compute a negative rate (`benchmarks/2026-08-30/REPORT.md`
        §4). Returns the last known cumulative total if the socket isn't
        open or the kernel doesn't support this getsockopt, never resetting
        it — this is "detect drops where possible", not a hard requirement,
        and a transient read failure must not make the exported total go
        backwards either.
        """
        if self._socket is None:
            return self._packets_dropped_cumulative
        try:
            raw = self._socket.getsockopt(
                _SOL_PACKET, _PACKET_STATISTICS, struct.calcsize(_PACKET_STATS_FORMAT)
            )
        except OSError:
            return self._packets_dropped_cumulative
        _received, dropped_since_last_read = struct.unpack(_PACKET_STATS_FORMAT, raw)
        self._packets_dropped_cumulative += dropped_since_last_read
        return self._packets_dropped_cumulative

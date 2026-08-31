"""`AFPacketCapture`'s cumulative packet-drop counter (`benchmarks/2026-08-30/REPORT.md` §4).

The kernel zeroes `tp_drops` every time `PACKET_STATISTICS` is read via
`getsockopt`, so a single raw reading is only the delta since the previous
read, not a lifetime total. `AFPacketCapture._read_kernel_drops` must
accumulate those deltas so `CaptureStatistics.packets_dropped` behaves like
every other counter it's exported alongside (`packets_seen`,
`packets_malformed`) — monotonically non-decreasing across ticks — rather
than a raw per-read value a dashboard would see go up and down.

The real `getsockopt` call itself is not exercised here (that needs a real
Linux `AF_PACKET` socket, Environment-dependent per `docs/PROGRESS.md`
Phase 2); this simulates the kernel's reset-on-read behavior directly
against a fake socket object standing in for `capture._socket`.
"""

import socket
import struct
from typing import cast

from pirewall.capture.af_packet import AFPacketCapture


class _FakeStatsSocket:
    """Stands in for `socket.socket`, returning one `PACKET_STATISTICS` reading per call.

    Each entry in `drop_sequence` is what the kernel would report as
    `tp_drops` *since the previous read* — exactly the reset-on-read
    behavior `_read_kernel_drops`'s docstring describes.
    """

    def __init__(self, drop_sequence: list[int]) -> None:
        self._drop_sequence = list(drop_sequence)
        self._call_count = 0

    def getsockopt(self, _level: int, _optname: int, _buflen: int) -> bytes:
        dropped_since_last_read = self._drop_sequence[self._call_count]
        self._call_count += 1
        return struct.pack("II", 0, dropped_since_last_read)


def _capture_with_fake_socket(drop_sequence: list[int]) -> AFPacketCapture:
    capture = AFPacketCapture(interface="eth0", snap_len=65535, promiscuous=False, buffer_size_bytes=1024)
    capture._socket = cast(socket.socket, _FakeStatsSocket(drop_sequence))  # pyright: ignore[reportPrivateUsage]
    return capture


def test_packets_dropped_accumulates_across_consecutive_kernel_reset_reads() -> None:
    """Two consecutive reads reporting 5 then 3 (post-reset) must total 8, not 3."""
    capture = _capture_with_fake_socket([5, 3])

    first = capture.statistics().packets_dropped
    second = capture.statistics().packets_dropped

    assert first == 5
    assert second == 8


def test_packets_dropped_never_goes_backwards_across_many_reads() -> None:
    capture = _capture_with_fake_socket([2, 0, 7, 1])

    readings = [capture.statistics().packets_dropped for _ in range(4)]

    assert readings == [2, 2, 9, 10]
    assert readings == sorted(readings)


def test_packets_dropped_is_zero_before_any_socket_is_open() -> None:
    capture = AFPacketCapture(interface="eth0", snap_len=65535, promiscuous=False, buffer_size_bytes=1024)

    assert capture.statistics().packets_dropped == 0

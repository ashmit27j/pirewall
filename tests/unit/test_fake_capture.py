"""`FakePacketCapture`: behaves like the `PacketCapture` protocol for tests.

Also covers the one `AFPacketCapture` failure path that *is* testable off
Linux: refusing to start on a platform with no `AF_PACKET` support.
"""

import pytest

from pirewall.capture.af_packet import AFPacketCapture
from pirewall.capture.fake import FakePacketCapture
from pirewall.core.exceptions import CaptureError


def test_yields_only_real_packets_and_counts_drops() -> None:
    capture = FakePacketCapture("eth-test", [b"packet-1", None, b"packet-2", None, None])
    capture.start()

    packets = list(capture.read_packets())

    assert [p.raw for p in packets] == [b"packet-1", b"packet-2"]
    stats = capture.statistics()
    assert stats.packets_seen == 2
    assert stats.packets_dropped == 3
    assert stats.packets_malformed == 0


def test_record_malformed_increments_statistics() -> None:
    capture = FakePacketCapture("eth-test", [b"packet-1"])
    capture.start()
    list(capture.read_packets())
    capture.record_malformed()
    capture.record_malformed()

    assert capture.statistics().packets_malformed == 2


def test_reading_before_start_raises_capture_error() -> None:
    capture = FakePacketCapture("eth-test", [b"packet-1"])
    with pytest.raises(CaptureError):
        list(capture.read_packets())


def test_stop_ends_iteration_early() -> None:
    capture = FakePacketCapture("eth-test", [b"packet-1", b"packet-2", b"packet-3"])
    capture.start()

    collected: list[bytes] = []
    for packet in capture.read_packets():
        collected.append(packet.raw)
        if len(collected) == 1:
            capture.stop()

    assert collected == [b"packet-1"]


def test_statistics_report_configured_interface() -> None:
    capture = FakePacketCapture("lan0", [])
    assert capture.statistics().interface == "lan0"


def test_af_packet_capture_reports_an_unsupported_platform_as_a_typed_error() -> None:
    """A platform with no `AF_PACKET` must raise `CaptureError`, not a stdlib `AttributeError`.

    `socket.AF_PACKET` is Linux-only, so on macOS (where pirewall is
    developed) `socket.socket(socket.AF_PACKET, ...)` raises `AttributeError`
    — which is not an `OSError` and so was not caught. It escaped untyped
    and crashed `pirewall.runtime.core.CoreDaemon.start()` with a traceback,
    bypassing the "capture unavailable, keep serving RPC so the Admin PC can
    see why" path A6 asks for. Found by running the real daemon.

    On Linux this asserts the complementary property: the failure is still a
    `CaptureError` (no such interface / no CAP_NET_RAW), never an untyped one.
    """
    capture = AFPacketCapture(
        interface="pirewall-nonexistent0",
        snap_len=65535,
        promiscuous=False,
        buffer_size_bytes=4096,
    )
    with pytest.raises(CaptureError):
        capture.start()

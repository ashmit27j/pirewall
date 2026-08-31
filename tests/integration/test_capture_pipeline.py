"""End-to-end capture -> parse pipeline (spec §6, §7) against `FakePacketCapture`."""

from pirewall.capture.fake import FakePacketCapture
from pirewall.capture.pipeline import capture_packets
from pirewall.core.enums import Protocol, SecurityEventType
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.packet import PacketMetadata
from tests.helpers.packets import eth, ipv4_header, tcp_header, udp_header


def _valid_tcp_packet(destination_port: int = 443) -> bytes:
    tcp = tcp_header(51234, destination_port, flags=0x02)
    ip = ipv4_header(protocol=6, total_length=20 + len(tcp))
    return eth(0x0800) + ip + tcp


def _valid_udp_packet() -> bytes:
    udp = udp_header(53, 12345, length=8)
    ip = ipv4_header(protocol=17, total_length=20 + len(udp))
    return eth(0x0800) + ip + udp


def test_capture_to_parse_pipeline_end_to_end() -> None:
    scripted: list[bytes | None] = [
        _valid_tcp_packet(),
        b"\x00" * 10,  # malformed: truncated ethernet header
        None,  # simulated OS-level drop
        _valid_udp_packet(),
        b"garbage packet that is not a real frame at all!!",  # malformed
        None,  # simulated OS-level drop
    ]
    capture = FakePacketCapture("eth-test", scripted)
    capture.start()

    parsed = list(capture_packets(capture))

    assert [p.protocol for p in parsed] == [Protocol.TCP, Protocol.UDP]

    stats = capture.statistics()
    assert stats.packets_seen == 4  # 2 valid + 2 malformed-but-yielded-by-capture
    assert stats.packets_dropped == 2  # the two simulated OS-level drops
    assert stats.packets_malformed == 2  # the two packets that failed to parse


def test_malformed_packets_emit_capture_error_events_when_a_sink_is_supplied() -> None:
    scripted: list[bytes | None] = [_valid_tcp_packet(), b"\x00" * 10, b"garbage!!"]
    capture = FakePacketCapture("eth-test", scripted)
    capture.start()

    events: list[SecurityEvent] = []
    parsed = list(capture_packets(capture, on_event=events.append))

    assert len(parsed) == 1
    assert len(events) == 2
    assert all(event.event_type is SecurityEventType.CAPTURE_ERROR for event in events)
    assert all(event.subsystem == "capture.pipeline" for event in events)


def test_no_events_emitted_when_no_sink_supplied() -> None:
    capture = FakePacketCapture("eth-test", [b"\x00" * 10])
    capture.start()
    list(capture_packets(capture))  # must not raise even without a sink


def test_on_tcp_payload_fires_for_port_443_traffic_only() -> None:
    """ADDENDUM_2.md B4/B5: the callback is invoked for TCP/443, never for other TCP or UDP."""
    scripted: list[bytes | None] = [
        _valid_tcp_packet(destination_port=443),
        _valid_tcp_packet(destination_port=8080),
        _valid_udp_packet(),
    ]
    capture = FakePacketCapture("eth-test", scripted)
    capture.start()

    calls: list[tuple[PacketMetadata, bytes]] = []
    list(capture_packets(capture, on_tcp_payload=lambda metadata, raw: calls.append((metadata, raw))))

    assert len(calls) == 1
    metadata, raw = calls[0]
    assert metadata.protocol is Protocol.TCP
    assert metadata.destination_port == 443
    assert raw == scripted[0]


def test_no_tcp_payload_callback_invoked_when_none_supplied() -> None:
    capture = FakePacketCapture("eth-test", [_valid_tcp_packet(destination_port=443)])
    capture.start()
    list(capture_packets(capture))  # must not raise without on_tcp_payload

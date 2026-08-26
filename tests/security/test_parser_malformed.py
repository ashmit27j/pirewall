"""Malformed/truncated packets must never crash the parser (spec §7, §39).

Every case here must raise `PacketParseError` — nothing else, and never an
uncaught exception (a bare `IndexError`/`struct.error`/`ValueError` would
mean garbage input could crash the capture loop).
"""

from datetime import UTC, datetime

import pytest

from pirewall.capture.parser import parse_packet
from pirewall.core.exceptions import PacketParseError
from tests.helpers.packets import eth, ipv4_header, ipv6_header, tcp_header

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_empty_bytes_raises_parse_error() -> None:
    with pytest.raises(PacketParseError):
        parse_packet(b"", NOW)


def test_truncated_ethernet_header_raises_parse_error() -> None:
    with pytest.raises(PacketParseError):
        parse_packet(b"\x00" * 10, NOW)


def test_unsupported_ethertype_raises_parse_error() -> None:
    raw = eth(0x8863)  # PPPoE discovery — not IPv4/IPv6
    with pytest.raises(PacketParseError):
        parse_packet(raw, NOW)


def test_truncated_ipv4_header_raises_parse_error() -> None:
    raw = eth(0x0800) + b"\x45\x00\x00\x14"  # only 4 bytes of a 20-byte IPv4 header
    with pytest.raises(PacketParseError):
        parse_packet(raw, NOW)


def test_ipv4_wrong_version_raises_parse_error() -> None:
    ip = bytearray(ipv4_header(protocol=6, total_length=40))
    ip[0] = (6 << 4) | 5  # claim version 6 under an IPv4 ethertype
    raw = eth(0x0800) + bytes(ip) + tcp_header(1, 2, flags=0)
    with pytest.raises(PacketParseError):
        parse_packet(raw, NOW)


def test_ipv4_invalid_ihl_raises_parse_error() -> None:
    ip = bytearray(ipv4_header(protocol=6, total_length=40))
    ip[0] = (4 << 4) | 2  # IHL of 2 words = 8 bytes, below the 20-byte minimum
    raw = eth(0x0800) + bytes(ip)
    with pytest.raises(PacketParseError):
        parse_packet(raw, NOW)


def test_ipv4_total_length_exceeds_captured_data_raises_parse_error() -> None:
    ip = ipv4_header(protocol=6, total_length=9000)  # far larger than what follows
    raw = eth(0x0800) + ip + tcp_header(1, 2, flags=0)
    with pytest.raises(PacketParseError):
        parse_packet(raw, NOW)


def test_truncated_ipv6_header_raises_parse_error() -> None:
    raw = eth(0x86DD) + b"\x60\x00\x00\x00"  # only 4 of 40 IPv6 header bytes
    with pytest.raises(PacketParseError):
        parse_packet(raw, NOW)


def test_ipv6_wrong_version_raises_parse_error() -> None:
    ip = bytearray(ipv6_header(next_header=6, payload_length=20))
    ip[0] = 4 << 4  # claim version 4 under an IPv6 ethertype
    raw = eth(0x86DD) + bytes(ip) + tcp_header(1, 2, flags=0)
    with pytest.raises(PacketParseError):
        parse_packet(raw, NOW)


def test_truncated_tcp_header_raises_parse_error() -> None:
    ip = ipv4_header(protocol=6, total_length=20 + 10)
    raw = eth(0x0800) + ip + b"\x00" * 10  # 10 bytes, below the 20-byte TCP minimum
    with pytest.raises(PacketParseError):
        parse_packet(raw, NOW)


def test_tcp_invalid_data_offset_raises_parse_error() -> None:
    tcp = bytearray(tcp_header(1, 2, flags=0x02))
    tcp[12] = 2 << 4  # data offset of 2 words = 8 bytes, below the 20-byte minimum
    ip = ipv4_header(protocol=6, total_length=20 + len(tcp))
    raw = eth(0x0800) + ip + bytes(tcp)
    with pytest.raises(PacketParseError):
        parse_packet(raw, NOW)


def test_truncated_tcp_options_raises_parse_error() -> None:
    tcp = bytearray(tcp_header(1, 2, flags=0x02))
    tcp[12] = 10 << 4  # data offset claims 40 bytes of header
    ip = ipv4_header(protocol=6, total_length=20 + len(tcp))
    raw = eth(0x0800) + ip + bytes(tcp)  # but only 20 bytes actually follow
    with pytest.raises(PacketParseError):
        parse_packet(raw, NOW)


def test_truncated_udp_header_raises_parse_error() -> None:
    ip = ipv4_header(protocol=17, total_length=20 + 4)
    raw = eth(0x0800) + ip + b"\x00\x50\x00\x35"  # 4 bytes, below the 8-byte UDP minimum
    with pytest.raises(PacketParseError):
        parse_packet(raw, NOW)


def test_truncated_icmp_header_raises_parse_error() -> None:
    ip = ipv4_header(protocol=1, total_length=20 + 2)
    raw = eth(0x0800) + ip + b"\x08\x00"  # 2 bytes, below the 4-byte ICMP minimum
    with pytest.raises(PacketParseError):
        parse_packet(raw, NOW)


@pytest.mark.parametrize("cut", [1, 5, 14, 18, 25, 30])
def test_various_truncation_points_never_raise_uncaught_exception(cut: int) -> None:
    tcp = tcp_header(51234, 443, flags=0x02)
    ip = ipv4_header(protocol=6, total_length=20 + len(tcp))
    full = eth(0x0800) + ip + tcp

    truncated = full[:cut]
    with pytest.raises(PacketParseError):
        parse_packet(truncated, NOW)


def test_random_garbage_never_raises_uncaught_exception() -> None:
    garbage_samples = [
        bytes(range(256))[:60],
        b"\xff" * 100,
        b"\x00" * 14 + b"\x08\x00" + b"\xff" * 30,
    ]
    for garbage in garbage_samples:
        with pytest.raises(PacketParseError):
            parse_packet(garbage, NOW)

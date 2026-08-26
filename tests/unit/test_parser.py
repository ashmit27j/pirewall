"""`pirewall.capture.parser`: valid packets parse correctly."""

from datetime import UTC, datetime

from pirewall.capture.parser import parse_packet
from pirewall.core.enums import AddressFamily, Protocol
from tests.helpers.packets import eth, ipv4_header, ipv6_header, tcp_header, udp_header

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_valid_ipv4_tcp_syn_packet() -> None:
    tcp = tcp_header(51234, 443, flags=0x02)  # SYN
    ip = ipv4_header(protocol=6, total_length=20 + len(tcp))
    raw = eth(0x0800) + ip + tcp

    metadata = parse_packet(raw, NOW)

    assert metadata.address_family is AddressFamily.IPV4
    assert metadata.protocol is Protocol.TCP
    assert metadata.source_port == 51234
    assert metadata.destination_port == 443
    assert metadata.tcp_flags is not None
    assert metadata.tcp_flags.syn is True
    assert metadata.tcp_flags.ack is False
    assert metadata.payload_length == 0


def test_valid_ipv4_udp_packet_with_payload() -> None:
    payload = b"hello"
    udp = udp_header(53, 12345, length=8 + len(payload)) + payload
    ip = ipv4_header(protocol=17, total_length=20 + len(udp))
    raw = eth(0x0800) + ip + udp

    metadata = parse_packet(raw, NOW)

    assert metadata.protocol is Protocol.UDP
    assert metadata.source_port == 53
    assert metadata.destination_port == 12345
    assert metadata.payload_length == len(payload)


def test_valid_ipv4_icmp_packet() -> None:
    icmp = b"\x08\x00\x00\x00" + b"\x00\x00\x00\x00"  # echo request + rest-of-header
    ip = ipv4_header(protocol=1, total_length=20 + len(icmp))
    raw = eth(0x0800) + ip + icmp

    metadata = parse_packet(raw, NOW)

    assert metadata.protocol is Protocol.ICMP
    assert metadata.source_port is None
    assert metadata.destination_port is None


def test_valid_ipv6_tcp_packet() -> None:
    tcp = tcp_header(1234, 22, flags=0x10)  # ACK
    ip = ipv6_header(next_header=6, payload_length=len(tcp))
    raw = eth(0x86DD) + ip + tcp

    metadata = parse_packet(raw, NOW)

    assert metadata.address_family is AddressFamily.IPV6
    assert metadata.protocol is Protocol.TCP
    assert metadata.destination_port == 22
    assert metadata.tcp_flags is not None
    assert metadata.tcp_flags.ack is True


def test_valid_ipv6_icmpv6_packet() -> None:
    icmpv6 = b"\x80\x00\x00\x00"  # echo request
    ip = ipv6_header(next_header=58, payload_length=len(icmpv6))
    raw = eth(0x86DD) + ip + icmpv6

    metadata = parse_packet(raw, NOW)

    assert metadata.protocol is Protocol.ICMPV6


def test_unknown_ip_protocol_reported_as_other() -> None:
    body = b"\x00" * 8
    ip = ipv4_header(protocol=47, total_length=20 + len(body))  # GRE
    raw = eth(0x0800) + ip + body

    metadata = parse_packet(raw, NOW)

    assert metadata.protocol is Protocol.OTHER
    assert metadata.source_port is None

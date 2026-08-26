"""Hand-built raw packet bytes shared by parser unit and security tests."""

import struct
from ipaddress import IPv4Address, IPv6Address

DST_MAC = b"\xaa\xbb\xcc\xdd\xee\xff"
SRC_MAC = b"\x11\x22\x33\x44\x55\x66"


def eth(ethertype: int) -> bytes:
    return DST_MAC + SRC_MAC + struct.pack("!H", ethertype)


def ipv4_header(
    protocol: int,
    total_length: int,
    src: str = "10.0.0.5",
    dst: str = "10.0.0.10",
) -> bytes:
    version_ihl = (4 << 4) | 5
    return (
        bytes([version_ihl])
        + b"\x00"
        + struct.pack("!H", total_length)
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x40"
        + bytes([protocol])
        + b"\x00\x00"
        + IPv4Address(src).packed
        + IPv4Address(dst).packed
    )


def ipv6_header(next_header: int, payload_length: int, src: str = "::1", dst: str = "::2") -> bytes:
    version_tc_fl = (6 << 28).to_bytes(4, "big")
    return (
        version_tc_fl
        + struct.pack("!H", payload_length)
        + bytes([next_header])
        + b"\x40"
        + IPv6Address(src).packed
        + IPv6Address(dst).packed
    )


def tcp_header(src_port: int, dst_port: int, flags: int, data_offset_words: int = 5) -> bytes:
    return (
        struct.pack("!HH", src_port, dst_port)
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + bytes([data_offset_words << 4])
        + bytes([flags])
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
    )


def udp_header(src_port: int, dst_port: int, length: int) -> bytes:
    return struct.pack("!HH", src_port, dst_port) + struct.pack("!H", length) + b"\x00\x00"

"""Parses Ethernet -> IPv4/IPv6 -> TCP/UDP/ICMP/ICMPv6 into `PacketMetadata` (spec §7).

Stops at L3/L4 headers — never touches application payload. Every failure
mode (truncation, invalid header lengths, unsupported ethertypes/protocols)
raises `PacketParseError`; nothing else can escape `parse_packet` (see the
top-level `except Exception` guard at the bottom of this module).

Known limitations, documented rather than silently handled:

* No 802.1Q VLAN tag support — an Ethernet frame with ethertype 0x8100 is
  treated as unsupported. Not required by spec §7; add if real deployment
  traffic needs it.
* IPv6 extension headers (hop-by-hop, routing, fragment, ...) are not
  walked — if `next_header` names one, the "L4" protocol is reported as
  `Protocol.OTHER` rather than skipping past the extension header to find
  the real transport header.
"""

import struct
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from pirewall.core.enums import AddressFamily, Protocol
from pirewall.core.exceptions import PacketParseError
from pirewall.core.models.common import TcpFlags
from pirewall.core.models.packet import PacketMetadata

_ETH_HEADER_LEN = 14
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD

_IPV4_MIN_HEADER_LEN = 20
_IPV6_HEADER_LEN = 40

_IP_PROTO_ICMP = 1
_IP_PROTO_TCP = 6
_IP_PROTO_UDP = 17
_IP_PROTO_ICMPV6 = 58

_TCP_MIN_HEADER_LEN = 20
_UDP_HEADER_LEN = 8
_ICMP_MIN_HEADER_LEN = 4

_TCP_FLAG_FIN = 0x01
_TCP_FLAG_SYN = 0x02
_TCP_FLAG_RST = 0x04
_TCP_FLAG_PSH = 0x08
_TCP_FLAG_ACK = 0x10
_TCP_FLAG_URG = 0x20


class _L4Info:
    """Internal scratch result of parsing a transport-layer header."""

    __slots__ = ("destination_port", "header_length", "protocol", "source_port", "tcp_flags")

    def __init__(
        self,
        protocol: Protocol,
        source_port: int | None,
        destination_port: int | None,
        tcp_flags: TcpFlags | None,
        header_length: int,
    ) -> None:
        self.protocol = protocol
        self.source_port = source_port
        self.destination_port = destination_port
        self.tcp_flags = tcp_flags
        self.header_length = header_length


def parse_packet(raw: bytes, captured_at: datetime) -> PacketMetadata:
    """Parse one raw Ethernet frame into `PacketMetadata`.

    Raises `PacketParseError` for any malformed, truncated, or unsupported
    input — callers (the capture loop) are expected to catch this, count
    it via `PacketCapture.record_malformed()`, log it, and continue.
    """
    try:
        return _parse_packet(raw, captured_at)
    except PacketParseError:
        raise
    except Exception as exc:  # belt-and-suspenders: nothing else may escape
        raise PacketParseError(f"unexpected error parsing packet: {exc}") from exc


def _parse_packet(raw: bytes, captured_at: datetime) -> PacketMetadata:
    if len(raw) < _ETH_HEADER_LEN:
        raise PacketParseError(f"truncated Ethernet header: {len(raw)} bytes")

    ethertype = struct.unpack("!H", raw[12:14])[0]

    if ethertype == _ETHERTYPE_IPV4:
        return _parse_ipv4(raw, _ETH_HEADER_LEN, captured_at)
    if ethertype == _ETHERTYPE_IPV6:
        return _parse_ipv6(raw, _ETH_HEADER_LEN, captured_at)
    raise PacketParseError(f"unsupported ethertype 0x{ethertype:04x}")


def _parse_ipv4(raw: bytes, offset: int, captured_at: datetime) -> PacketMetadata:
    if len(raw) < offset + _IPV4_MIN_HEADER_LEN:
        raise PacketParseError("truncated IPv4 header")

    version = raw[offset] >> 4
    if version != 4:
        raise PacketParseError(f"unexpected IP version {version} under IPv4 ethertype")

    ihl = (raw[offset] & 0x0F) * 4
    if ihl < _IPV4_MIN_HEADER_LEN:
        raise PacketParseError(f"invalid IPv4 IHL: {ihl} bytes")
    if len(raw) < offset + ihl:
        raise PacketParseError("truncated IPv4 header options")

    total_length = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
    if total_length < ihl:
        raise PacketParseError("IPv4 total_length shorter than header length")
    if len(raw) < offset + total_length:
        raise PacketParseError("IPv4 total_length exceeds captured data")

    ip_protocol = raw[offset + 9]
    source_ip = IPv4Address(bytes(raw[offset + 12 : offset + 16]))
    destination_ip = IPv4Address(bytes(raw[offset + 16 : offset + 20]))

    l4_offset = offset + ihl
    l4_available = total_length - ihl
    l4 = _parse_l4(raw, l4_offset, ip_protocol, l4_available)

    payload_length = l4_available - l4.header_length
    if payload_length < 0:
        raise PacketParseError("IPv4 payload shorter than transport header")

    return PacketMetadata(
        timestamp=captured_at,
        address_family=AddressFamily.IPV4,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=l4.protocol,
        source_port=l4.source_port,
        destination_port=l4.destination_port,
        tcp_flags=l4.tcp_flags,
        total_length=total_length,
        payload_length=payload_length,
    )


def _parse_ipv6(raw: bytes, offset: int, captured_at: datetime) -> PacketMetadata:
    if len(raw) < offset + _IPV6_HEADER_LEN:
        raise PacketParseError("truncated IPv6 header")

    version = raw[offset] >> 4
    if version != 6:
        raise PacketParseError(f"unexpected IP version {version} under IPv6 ethertype")

    declared_payload_length = struct.unpack("!H", raw[offset + 4 : offset + 6])[0]
    next_header = raw[offset + 6]
    source_ip = IPv6Address(bytes(raw[offset + 8 : offset + 24]))
    destination_ip = IPv6Address(bytes(raw[offset + 24 : offset + 40]))

    l4_offset = offset + _IPV6_HEADER_LEN
    available = len(raw) - l4_offset
    l4_available = min(declared_payload_length, available)
    l4 = _parse_l4(raw, l4_offset, next_header, l4_available)

    payload_length = l4_available - l4.header_length
    if payload_length < 0:
        raise PacketParseError("IPv6 payload shorter than transport header")

    return PacketMetadata(
        timestamp=captured_at,
        address_family=AddressFamily.IPV6,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=l4.protocol,
        source_port=l4.source_port,
        destination_port=l4.destination_port,
        tcp_flags=l4.tcp_flags,
        total_length=_IPV6_HEADER_LEN + declared_payload_length,
        payload_length=payload_length,
    )


def _parse_l4(raw: bytes, offset: int, ip_protocol: int, available: int) -> _L4Info:
    if ip_protocol == _IP_PROTO_TCP:
        return _parse_tcp(raw, offset, available)
    if ip_protocol == _IP_PROTO_UDP:
        return _parse_udp(raw, offset, available)
    if ip_protocol == _IP_PROTO_ICMP:
        return _parse_icmp(raw, offset, available, Protocol.ICMP)
    if ip_protocol == _IP_PROTO_ICMPV6:
        return _parse_icmp(raw, offset, available, Protocol.ICMPV6)
    return _L4Info(Protocol.OTHER, None, None, None, 0)


def _parse_tcp(raw: bytes, offset: int, available: int) -> _L4Info:
    if available < _TCP_MIN_HEADER_LEN or len(raw) < offset + _TCP_MIN_HEADER_LEN:
        raise PacketParseError("truncated TCP header")

    source_port, destination_port = struct.unpack("!HH", raw[offset : offset + 4])
    data_offset = (raw[offset + 12] >> 4) * 4
    if data_offset < _TCP_MIN_HEADER_LEN:
        raise PacketParseError(f"invalid TCP data offset: {data_offset} bytes")
    if available < data_offset or len(raw) < offset + data_offset:
        raise PacketParseError("truncated TCP header options")

    flags_byte = raw[offset + 13]
    flags = TcpFlags(
        fin=bool(flags_byte & _TCP_FLAG_FIN),
        syn=bool(flags_byte & _TCP_FLAG_SYN),
        rst=bool(flags_byte & _TCP_FLAG_RST),
        psh=bool(flags_byte & _TCP_FLAG_PSH),
        ack=bool(flags_byte & _TCP_FLAG_ACK),
        urg=bool(flags_byte & _TCP_FLAG_URG),
    )
    return _L4Info(Protocol.TCP, source_port, destination_port, flags, data_offset)


def _parse_udp(raw: bytes, offset: int, available: int) -> _L4Info:
    if available < _UDP_HEADER_LEN or len(raw) < offset + _UDP_HEADER_LEN:
        raise PacketParseError("truncated UDP header")
    source_port, destination_port = struct.unpack("!HH", raw[offset : offset + 4])
    return _L4Info(Protocol.UDP, source_port, destination_port, None, _UDP_HEADER_LEN)


def _parse_icmp(raw: bytes, offset: int, available: int, protocol: Protocol) -> _L4Info:
    if available < _ICMP_MIN_HEADER_LEN or len(raw) < offset + _ICMP_MIN_HEADER_LEN:
        raise PacketParseError(f"truncated {protocol.value} header")
    return _L4Info(protocol, None, None, None, _ICMP_MIN_HEADER_LEN)


def extract_tcp_payload(raw: bytes) -> bytes | None:
    """Return one IPv4/TCP packet's raw payload bytes, or `None` for anything else.

    **Only for ADDENDUM_2.md B4/B5's narrow TLS record-layer/ClientHello
    structural parsing.** `parse_packet` above — the one path every other
    consumer (flow aggregation, feature extraction, ML) actually uses —
    never returns payload bytes at all, deliberately (spec §7 "do not
    perform application-payload inspection as part of the core detection
    pipeline"; see `pirewall.detection.tls_heartbeat`'s module docstring
    for why the narrow TLS use case is a different category of work from
    that). This function duplicates a small amount of `_parse_ipv4`/
    `_parse_tcp`'s offset arithmetic rather than threading a payload slice
    through `PacketMetadata` — deliberately: that would put payload bytes
    one field away from every consumer of the primary parse path, which is
    exactly the exposure spec §7 exists to avoid.

    Degrades to `None` for anything that isn't cleanly parseable as
    IPv4/TCP with a complete header — truncated, malformed, non-IPv4,
    non-TCP. Never raises.
    """
    try:
        return _extract_tcp_payload(raw)
    except Exception:  # belt-and-suspenders, matching parse_packet's own guard
        return None


def _extract_tcp_payload(raw: bytes) -> bytes | None:
    if len(raw) < _ETH_HEADER_LEN + _IPV4_MIN_HEADER_LEN:
        return None
    if struct.unpack("!H", raw[12:14])[0] != _ETHERTYPE_IPV4:
        return None

    offset = _ETH_HEADER_LEN
    if (raw[offset] >> 4) != 4:
        return None
    ihl = (raw[offset] & 0x0F) * 4
    if ihl < _IPV4_MIN_HEADER_LEN or len(raw) < offset + ihl:
        return None
    if raw[offset + 9] != _IP_PROTO_TCP:
        return None

    total_length = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
    l4_offset = offset + ihl
    if len(raw) < l4_offset + _TCP_MIN_HEADER_LEN:
        return None
    data_offset = (raw[l4_offset + 12] >> 4) * 4
    if data_offset < _TCP_MIN_HEADER_LEN or len(raw) < l4_offset + data_offset:
        return None

    payload_offset = l4_offset + data_offset
    # Bounded by the IPv4 header's own declared total_length, then by
    # whatever was actually captured — never read past either.
    payload_end = min(offset + total_length, len(raw))
    if payload_offset > payload_end:
        return None
    return raw[payload_offset:payload_end]

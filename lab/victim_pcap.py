"""Read the victim-side capture `lab/capture.sh` writes, for TTM (critique_safety_eval.md, metrics).

Two link types, one per victim:

* **Ethernet (1)**: `tcpdump` inside the `labvictim` netns (forward path,
  Victim B). What arrives there got through every pirewall table.
* **NFLOG (239)**: the input path (Victim A, the Pi itself). `tcpdump` on
  the LAN interface sees frames *before* netfilter, so it cannot show what
  got through; `capture.sh --side input` instead loads a lab-only tap table
  whose input-hook rule runs after every pirewall input chain (priority 150) and logs
  to an NFLOG group, so the capture holds exactly the packets the Pi's
  stack accepted.

Raw IPv4 (101, 228) is accepted too. Classic pcap only (what `tcpdump -w`
writes); headers only, so a small snaplen is fine. Stdlib only.
"""

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import Final

__all__ = ["VictimPacket", "read_victim_pcap"]

LINKTYPE_ETHERNET: Final = 1
LINKTYPE_RAW: Final = 101
LINKTYPE_IPV4: Final = 228
LINKTYPE_NFLOG: Final = 239
_NFULA_PAYLOAD: Final = 9
_PROTOCOLS: Final = {1: "icmp", 6: "tcp", 17: "udp"}


@dataclass(frozen=True, slots=True)
class VictimPacket:
    """One IPv4 packet that reached the victim."""

    at: float
    src: IPv4Address
    dst: IPv4Address
    proto: str
    dport: int | None


def _ipv4(data: bytes, at: float) -> VictimPacket | None:
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    proto = _PROTOCOLS.get(data[9], str(data[9]))
    dport = None
    if proto in ("tcp", "udp") and len(data) >= ihl + 4:
        dport = struct.unpack_from("!H", data, ihl + 2)[0]
    return VictimPacket(at, IPv4Address(data[12:16]), IPv4Address(data[16:20]), proto, dport)


def _nflog_payload(data: bytes) -> bytes | None:
    """The NFULA_PAYLOAD TLV of one NFLOG record (TLV header fields are host-endian: little-endian)."""
    offset = 4
    while offset + 4 <= len(data):
        length, kind = struct.unpack_from("<HH", data, offset)
        if length < 4:
            return None
        if kind & 0x7FFF == _NFULA_PAYLOAD:
            return data[offset + 4 : offset + length]
        offset += (length + 3) & ~3
    return None


def read_victim_pcap(path: Path) -> Iterator[VictimPacket]:
    """Every IPv4 packet in a classic pcap of a supported link type."""
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) < 24:
            return
        magic = struct.unpack_from("<I", header)[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian = ">"
        else:
            raise ValueError(f"{path}: not a classic pcap (pcapng is not supported here)")
        nanos = magic in (0xA1B23C4D, 0x4D3CB2A1)
        linktype = struct.unpack_from(endian + "I", header, 20)[0] & 0x0FFFFFFF
        if linktype not in (LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_NFLOG):
            raise ValueError(f"{path}: unsupported link type {linktype}")
        while True:
            record = stream.read(16)
            if len(record) < 16:
                return
            seconds, fraction, captured, _original = struct.unpack(endian + "IIII", record)
            data = stream.read(captured)
            if len(data) < captured:
                return
            at = seconds + fraction / (1e9 if nanos else 1e6)
            if linktype == LINKTYPE_ETHERNET:
                if len(data) < 14 or struct.unpack_from("!H", data, 12)[0] != 0x0800:
                    continue
                packet = _ipv4(data[14:], at)
            elif linktype == LINKTYPE_NFLOG:
                payload = _nflog_payload(data)
                packet = None if payload is None else _ipv4(payload, at)
            else:
                packet = _ipv4(data, at)
            if packet is not None:
                yield packet

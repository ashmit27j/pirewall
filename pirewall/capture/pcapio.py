"""Stdlib-only pcap/pcapng reading and pcap writing (ADDENDUM_4.md D6/D7).

What makes "train on our own pcaps" possible: frames read here go through
the *same* flow engine live capture uses (`pirewall.capture.replay`,
`scripts/dataset/pcap_to_flows.py`), so training and runtime features come
from one code path.

Reading:

* classic pcap, either byte order, microsecond (`0xa1b2c3d4`) or
  nanosecond (`0xa1b23c4d`) timestamps;
* pcapng: Section Header, Interface Description (with `if_tsresol` and
  `if_tsoffset`), Enhanced Packet and the obsolete Packet block. Simple
  Packet blocks carry no timestamp and are skipped and counted; every other
  block type is skipped;
* Ethernet (`LINKTYPE_ETHERNET` = 1) only. Frames from any other link type
  are skipped and counted, never guessed at;
* snaplen-truncated records are returned as captured (`len(data) <
  original_length`). The engine then sees exactly what a live capture with
  that snaplen would see, which for a cut IPv4 packet is "malformed". So a
  training capture needs the full snaplen; `truncated_records` counts it.

Timestamps come back as whole microseconds since the Unix epoch, the
engine's clock. Finer resolutions are floored, which is what the kernel
ring path does with its nanosecond timestamps (`native/src/capture.rs`).

Writing is classic pcap only, microsecond or nanosecond: enough for
fixtures, the lab mock generator (phase 18) and the Pi benchmark.
"""

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Self

from pirewall.core.exceptions import CaptureError

LINKTYPE_ETHERNET = 1

_PCAP_MAGIC_US = 0xA1B2C3D4
_PCAP_MAGIC_NS = 0xA1B23C4D
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D
_PCAPNG_IDB = 0x00000001
_PCAPNG_OPB = 0x00000002
_PCAPNG_SPB = 0x00000003
_PCAPNG_EPB = 0x00000006
_OPT_END = 0
_OPT_IF_TSRESOL = 9
_OPT_IF_TSOFFSET = 14

# No real frame is near this; a larger length field means a corrupt file,
# and refusing it keeps one bad header from allocating gigabytes.
_MAX_RECORD_BYTES = 1 << 18
_MAX_BLOCK_BYTES = 1 << 24

PCAP_SUFFIXES = (".pcap", ".pcapng", ".cap")


class PcapFormatError(CaptureError):
    """The file is not a pcap/pcapng this reader understands, or is corrupt."""


@dataclass(frozen=True, slots=True)
class PcapRecord:
    """One captured frame: its bytes, when, and how long it was on the wire."""

    data: bytes
    ts_us: int
    original_length: int


@dataclass(slots=True)
class PcapStats:
    """What a reader skipped or found odd while reading one file."""

    records: int = 0
    truncated_records: int = 0
    skipped_non_ethernet: int = 0
    skipped_without_timestamp: int = 0
    truncated_tail: bool = False
    link_types: set[int] = field(default_factory=set[int])


def _floor_to_us(units: int, per_second: int) -> int:
    """`units` ticks of 1/`per_second` s as whole microseconds, floored."""
    return (units * 1_000_000) // per_second


class PcapReader:
    """Iterate the Ethernet frames of one pcap or pcapng file.

    Iterating yields `PcapRecord`s in file order; `stats` fills in as it
    goes. A file cut off mid-record (a capture killed while writing) ends
    the iteration with `stats.truncated_tail = True` rather than raising;
    anything else malformed raises `PcapFormatError`.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.stats = PcapStats()

    def __iter__(self) -> Iterator[PcapRecord]:
        with self.path.open("rb") as stream:
            head = stream.read(4)
            if len(head) < 4:
                raise PcapFormatError(f"{self.path}: too short to be a capture file")
            if struct.unpack("<I", head)[0] == _PCAPNG_SHB:
                yield from self._read_pcapng(stream, head)
            else:
                yield from self._read_pcap(stream, head)

    # ----------------------------------------------------------------- pcap

    def _read_pcap(self, stream: BinaryIO, head: bytes) -> Iterator[PcapRecord]:
        for endian in ("<", ">"):
            magic = struct.unpack(endian + "I", head)[0]
            if magic in (_PCAP_MAGIC_US, _PCAP_MAGIC_NS):
                break
        else:
            raise PcapFormatError(f"{self.path}: not a pcap or pcapng file (magic {head.hex()})")
        per_second = 1_000_000 if magic == _PCAP_MAGIC_US else 1_000_000_000
        rest = stream.read(20)
        if len(rest) < 20:
            raise PcapFormatError(f"{self.path}: truncated pcap file header")
        _major, _minor, _zone, _sigfigs, _snaplen, network = struct.unpack(endian + "HHiIII", rest)
        link_type = network & 0xFFFF  # the upper bits carry FCS information
        self.stats.link_types.add(link_type)
        record_header = struct.Struct(endian + "IIII")
        while True:
            raw_header = stream.read(record_header.size)
            if not raw_header:
                return
            if len(raw_header) < record_header.size:
                self.stats.truncated_tail = True
                return
            seconds, fraction, captured, original = record_header.unpack(raw_header)
            if captured > _MAX_RECORD_BYTES:
                raise PcapFormatError(f"{self.path}: record of {captured} bytes; the file is corrupt")
            data = stream.read(captured)
            if len(data) < captured:
                self.stats.truncated_tail = True
                return
            if link_type != LINKTYPE_ETHERNET:
                self.stats.skipped_non_ethernet += 1
                continue
            yield self._record(data, seconds * 1_000_000 + _floor_to_us(fraction, per_second), original)

    # --------------------------------------------------------------- pcapng

    def _read_pcapng(self, stream: BinaryIO, head: bytes) -> Iterator[PcapRecord]:
        endian = "<"
        # Per section: (link type, ticks per second, offset in seconds) by interface id.
        interfaces: list[tuple[int, int, int]] = []
        pending = head
        while True:
            raw = pending + stream.read(8 - len(pending))
            pending = b""
            if not raw:
                return
            if len(raw) < 8:
                self.stats.truncated_tail = True
                return
            block_type = struct.unpack(endian + "I", raw[:4])[0]
            if block_type == _PCAPNG_SHB:
                # The byte-order magic follows the length; it decides how to read both.
                order = stream.read(4)
                if len(order) < 4:
                    self.stats.truncated_tail = True
                    return
                if struct.unpack("<I", order)[0] == _PCAPNG_BYTE_ORDER_MAGIC:
                    endian = "<"
                elif struct.unpack(">I", order)[0] == _PCAPNG_BYTE_ORDER_MAGIC:
                    endian = ">"
                else:
                    raise PcapFormatError(f"{self.path}: bad pcapng byte-order magic")
                total = struct.unpack(endian + "I", raw[4:8])[0]
                body_prefix = order
                interfaces = []
            else:
                total = struct.unpack(endian + "I", raw[4:8])[0]
                body_prefix = b""
            if total < 12 or total % 4 or total > _MAX_BLOCK_BYTES:
                raise PcapFormatError(f"{self.path}: bad pcapng block length {total}")
            remainder = stream.read(total - 8 - len(body_prefix))
            if len(remainder) < total - 8 - len(body_prefix):
                self.stats.truncated_tail = True
                return
            body = (body_prefix + remainder)[:-4]  # drop the trailing length copy
            if block_type == _PCAPNG_IDB:
                interfaces.append(self._interface(body, endian))
            elif block_type in (_PCAPNG_EPB, _PCAPNG_OPB):
                record = self._packet_block(block_type, body, endian, interfaces)
                if record is not None:
                    yield record
            elif block_type == _PCAPNG_SPB:
                self.stats.skipped_without_timestamp += 1

    def _interface(self, body: bytes, endian: str) -> tuple[int, int, int]:
        if len(body) < 8:
            raise PcapFormatError(f"{self.path}: truncated interface description block")
        link_type = struct.unpack(endian + "H", body[:2])[0]
        self.stats.link_types.add(link_type)
        per_second, offset_seconds = 1_000_000, 0
        for code, value in self._options(body[8:], endian):
            if code == _OPT_IF_TSRESOL and len(value) >= 1:
                exponent = value[0] & 0x7F
                if exponent > 30:
                    raise PcapFormatError(f"{self.path}: unsupported timestamp resolution {value[0]:#x}")
                per_second = (2**exponent) if value[0] & 0x80 else (10**exponent)
            elif code == _OPT_IF_TSOFFSET and len(value) >= 8:
                offset_seconds = struct.unpack(endian + "q", value[:8])[0]
        return link_type, per_second, offset_seconds

    def _options(self, raw: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
        at = 0
        while at + 4 <= len(raw):
            code, length = struct.unpack(endian + "HH", raw[at : at + 4])
            if code == _OPT_END:
                return
            yield code, raw[at + 4 : at + 4 + length]
            at += 4 + length + (-length % 4)

    def _packet_block(
        self, block_type: int, body: bytes, endian: str, interfaces: list[tuple[int, int, int]]
    ) -> PcapRecord | None:
        if block_type == _PCAPNG_EPB:
            if len(body) < 20:
                raise PcapFormatError(f"{self.path}: truncated enhanced packet block")
            interface, high, low, captured, original = struct.unpack(endian + "IIIII", body[:20])
        else:  # the obsolete Packet Block: 16-bit interface id and drop count
            if len(body) < 20:
                raise PcapFormatError(f"{self.path}: truncated packet block")
            interface, _drops, high, low, captured, original = struct.unpack(endian + "HHIIII", body[:20])
        if interface >= len(interfaces):
            raise PcapFormatError(f"{self.path}: packet for undeclared interface {interface}")
        if captured > len(body) - 20 or captured > _MAX_RECORD_BYTES:
            raise PcapFormatError(f"{self.path}: packet length {captured} overruns its block")
        declared: tuple[int, int, int] = interfaces[int(interface)]
        link_type, per_second, offset_seconds = declared
        if link_type != LINKTYPE_ETHERNET:
            self.stats.skipped_non_ethernet += 1
            return None
        ticks = (int(high) << 32) | int(low)
        ts_us = offset_seconds * 1_000_000 + _floor_to_us(ticks, per_second)
        return self._record(body[20 : 20 + captured], ts_us, original)

    def _record(self, data: bytes, ts_us: int, original: int) -> PcapRecord:
        self.stats.records += 1
        if len(data) < original:
            self.stats.truncated_records += 1
        return PcapRecord(data=data, ts_us=ts_us, original_length=original)


def capture_files(source: Path | str) -> list[Path]:
    """`source` itself if it is a file, else its capture files (by suffix), sorted by name."""
    path = Path(source)
    if path.is_dir():
        files = sorted(p for p in path.iterdir() if p.is_file() and p.suffix.lower() in PCAP_SUFFIXES)
        if not files:
            raise PcapFormatError(f"{path}: no {'/'.join(PCAP_SUFFIXES)} files in this directory")
        return files
    if not path.is_file():
        raise PcapFormatError(f"{path}: no such capture file or directory")
    return [path]


class PcapWriter:
    """Write Ethernet frames as a classic pcap (microsecond or nanosecond timestamps).

    Use as a context manager, or call `close()`. Records longer than
    `snaplen` are truncated to it, with their original length kept, exactly
    as a capture with that snaplen would store them.
    """

    def __init__(self, path: Path | str, nanosecond: bool = False, snaplen: int = 65535) -> None:
        if snaplen <= 0:
            raise ValueError("snaplen must be positive")
        self._nanosecond = nanosecond
        self._snaplen = snaplen
        self._stream = Path(path).open("wb")  # noqa: SIM115 - closed by close()/__exit__
        magic = _PCAP_MAGIC_NS if nanosecond else _PCAP_MAGIC_US
        self._stream.write(struct.pack("<IHHiIII", magic, 2, 4, 0, 0, snaplen, LINKTYPE_ETHERNET))

    def write(self, data: bytes, ts_us: int, ts_ns_remainder: int = 0) -> None:
        """Append one frame captured at `ts_us` (+ `ts_ns_remainder` ns, nanosecond files only)."""
        if ts_us < 0:
            raise ValueError("pcap timestamps cannot precede the Unix epoch")
        if not 0 <= ts_ns_remainder < 1000:
            raise ValueError("ts_ns_remainder must be in [0, 1000)")
        seconds, micros = divmod(ts_us, 1_000_000)
        fraction = micros * 1000 + ts_ns_remainder if self._nanosecond else micros
        captured = data[: self._snaplen]
        self._stream.write(struct.pack("<IIII", seconds, fraction, len(captured), len(data)))
        self._stream.write(captured)

    def close(self) -> None:
        """Flush and close the file. Idempotent."""
        self._stream.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

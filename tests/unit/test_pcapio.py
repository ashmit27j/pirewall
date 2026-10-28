"""`pirewall.capture.pcapio`: pcap/pcapng reading and pcap writing, stdlib only.

Fixtures are generated in each test (with the writer, or by packing pcapng
blocks by hand), never committed as binaries.
"""

import struct
from pathlib import Path

import pytest

from pirewall.capture.pcapio import (
    LINKTYPE_ETHERNET,
    PcapFormatError,
    PcapReader,
    PcapWriter,
    capture_files,
)
from tests.helpers.traffic import T0_US, mixed_stream

FRAME_A = bytes(range(60))
FRAME_B = b"\xaa" * 1514


def _write(
    path: Path, frames: list[tuple[bytes, int]], nanosecond: bool = False, snaplen: int = 65535
) -> None:
    with PcapWriter(path, nanosecond=nanosecond, snaplen=snaplen) as writer:
        for data, ts_us in frames:
            writer.write(data, ts_us)


@pytest.mark.parametrize("nanosecond", [False, True])
def test_a_written_pcap_reads_back_identically(tmp_path: Path, nanosecond: bool) -> None:
    frames = mixed_stream(seed=7, sessions=60)
    path = tmp_path / "stream.pcap"
    _write(path, frames, nanosecond=nanosecond)
    reader = PcapReader(path)
    records = list(reader)
    assert [(r.data, r.ts_us) for r in records] == frames
    assert all(r.original_length == len(r.data) for r in records)
    assert reader.stats.records == len(frames)
    assert reader.stats.link_types == {LINKTYPE_ETHERNET}
    assert not reader.stats.truncated_tail


def test_nanosecond_timestamps_are_floored_to_microseconds(tmp_path: Path) -> None:
    path = tmp_path / "ns.pcap"
    with PcapWriter(path, nanosecond=True) as writer:
        writer.write(FRAME_A, T0_US, ts_ns_remainder=999)
    assert next(iter(PcapReader(path))).ts_us == T0_US


def test_big_endian_pcap_is_read(tmp_path: Path) -> None:
    path = tmp_path / "be.pcap"
    header = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack(">IIII", 1_000, 250, len(FRAME_A), len(FRAME_A)) + FRAME_A
    path.write_bytes(header + record)
    records = list(PcapReader(path))
    assert [(r.data, r.ts_us) for r in records] == [(FRAME_A, 1_000_000_250)]


def test_snaplen_truncated_records_keep_their_original_length(tmp_path: Path) -> None:
    path = tmp_path / "snap.pcap"
    _write(path, [(FRAME_B, T0_US), (FRAME_A, T0_US + 1)], snaplen=96)
    reader = PcapReader(path)
    first, second = list(reader)
    assert (len(first.data), first.original_length) == (96, 1514)
    assert (second.data, second.original_length) == (FRAME_A, 60)
    assert reader.stats.truncated_records == 1


def test_a_file_cut_off_mid_record_ends_cleanly_and_says_so(tmp_path: Path) -> None:
    path = tmp_path / "cut.pcap"
    _write(path, [(FRAME_A, T0_US), (FRAME_B, T0_US + 1)])
    path.write_bytes(path.read_bytes()[:-100])
    reader = PcapReader(path)
    assert [r.data for r in reader] == [FRAME_A]
    assert reader.stats.truncated_tail


def test_non_ethernet_link_types_are_skipped_and_counted(tmp_path: Path) -> None:
    path = tmp_path / "raw.pcap"
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)  # LINKTYPE_RAW
    path.write_bytes(header + struct.pack("<IIII", 1, 0, 4, 4) + b"\x45\x00\x00\x14")
    reader = PcapReader(path)
    assert list(reader) == []
    assert reader.stats.skipped_non_ethernet == 1


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"\x00\x01",
        b"not a capture file at all",
        struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, 1) + struct.pack("<IIII", 0, 0, 1 << 30, 1 << 30),
    ],
)
def test_garbage_and_absurd_lengths_are_refused(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "bad.pcap"
    path.write_bytes(content)
    with pytest.raises(PcapFormatError):
        list(PcapReader(path))


# ------------------------------------------------------------------ pcapng


def _block(block_type: int, body: bytes, endian: str = "<") -> bytes:
    body += b"\x00" * (-len(body) % 4)
    total = len(body) + 12
    return struct.pack(endian + "II", block_type, total) + body + struct.pack(endian + "I", total)


def _option(code: int, value: bytes, endian: str = "<") -> bytes:
    return struct.pack(endian + "HH", code, len(value)) + value + b"\x00" * (-len(value) % 4)


def _shb(endian: str = "<") -> bytes:
    return _block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def _idb(link_type: int, options: bytes = b"", endian: str = "<") -> bytes:
    end = struct.pack(endian + "HH", 0, 0) if options else b""
    return _block(1, struct.pack(endian + "HHI", link_type, 0, 65535) + options + end, endian)


def _epb(interface: int, ticks: int, data: bytes, original: int | None = None, endian: str = "<") -> bytes:
    original = len(data) if original is None else original
    head = struct.pack(endian + "IIIII", interface, ticks >> 32, ticks & 0xFFFFFFFF, len(data), original)
    return _block(6, head + data, endian)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_enhanced_packets_honour_each_interfaces_resolution(tmp_path: Path, endian: str) -> None:
    ns = _option(9, b"\x09", endian)  # if_tsresol = 10^-9
    two = _option(9, b"\x94", endian)  # if_tsresol = 2^-20
    offset = _option(14, struct.pack(endian + "q", 100), endian)  # if_tsoffset = +100 s
    content = (
        _shb(endian)
        + _idb(1, endian=endian)  # 0: microseconds (default)
        + _idb(1, ns, endian)  # 1: nanoseconds
        + _idb(1, two + offset, endian)  # 2: binary fractions, offset
        + _idb(105, endian=endian)  # 3: 802.11, skipped
        + _block(5, b"\x00" * 8, endian)  # an Interface Statistics block, ignored
        + _epb(0, T0_US, FRAME_A, endian=endian)
        + _epb(1, T0_US * 1000 + 999, FRAME_B[:100], original=1514, endian=endian)
        + _epb(2, 3 << 20, FRAME_A, endian=endian)
        + _epb(3, 0, FRAME_A, endian=endian)
        + _block(3, struct.pack(endian + "I", len(FRAME_A)) + FRAME_A, endian)  # SPB: no timestamp
    )
    path = tmp_path / "multi.pcapng"
    path.write_bytes(content)
    reader = PcapReader(path)
    records = list(reader)
    assert [(r.data, r.ts_us, r.original_length) for r in records] == [
        (FRAME_A, T0_US, 60),
        (FRAME_B[:100], T0_US, 1514),
        (FRAME_A, 103_000_000, 60),
    ]
    assert reader.stats.skipped_non_ethernet == 1
    assert reader.stats.skipped_without_timestamp == 1
    assert reader.stats.truncated_records == 1
    assert reader.stats.link_types == {1, 105}


def test_pcapng_with_a_second_section_resets_its_interfaces(tmp_path: Path) -> None:
    content = (
        _shb()
        + _idb(1)
        + _epb(0, 5, FRAME_A)
        + _shb(">")
        + _idb(1, endian=">")
        + _epb(0, 6, FRAME_B, endian=">")
    )
    path = tmp_path / "two.pcapng"
    path.write_bytes(content)
    assert [(r.data, r.ts_us) for r in PcapReader(path)] == [(FRAME_A, 5), (FRAME_B, 6)]


def test_pcapng_packets_for_undeclared_interfaces_are_refused(tmp_path: Path) -> None:
    path = tmp_path / "orphan.pcapng"
    path.write_bytes(_shb() + _epb(0, 5, FRAME_A))
    with pytest.raises(PcapFormatError, match="undeclared interface"):
        list(PcapReader(path))


def test_pcapng_cut_off_mid_block_ends_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "cut.pcapng"
    path.write_bytes((_shb() + _idb(1) + _epb(0, 5, FRAME_A) + _epb(0, 6, FRAME_B))[:-10])
    reader = PcapReader(path)
    assert [r.data for r in reader] == [FRAME_A]
    assert reader.stats.truncated_tail


def test_capture_files_lists_a_directory_in_name_order(tmp_path: Path) -> None:
    for name in ("b.pcapng", "a.pcap", "c.cap", "notes.txt"):
        (tmp_path / name).write_bytes(b"")
    assert [p.name for p in capture_files(tmp_path)] == ["a.pcap", "b.pcapng", "c.cap"]
    assert capture_files(tmp_path / "a.pcap") == [tmp_path / "a.pcap"]
    with pytest.raises(PcapFormatError):
        capture_files(tmp_path / "missing.pcap")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(PcapFormatError):
        capture_files(empty)


def test_the_writer_refuses_impossible_timestamps(tmp_path: Path) -> None:
    with PcapWriter(tmp_path / "x.pcap") as writer, pytest.raises(ValueError):
        writer.write(FRAME_A, -1)

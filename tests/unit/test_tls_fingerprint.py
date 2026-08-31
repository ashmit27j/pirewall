"""`pirewall.detection.tls_fingerprint`: JA3 ClientHello fingerprinting (ADDENDUM_2.md B5)."""

import struct
from pathlib import Path

import pytest

from pirewall.detection.tls_fingerprint import (
    compute_ja3,
    load_known_tool_fingerprints,
    match_known_tool,
)

_HANDSHAKE = 22
_CLIENT_HELLO = 1
_TLS_1_2_RECORD_VERSION = b"\x03\x03"


def _extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def _client_hello(
    *,
    client_version: int = 0x0301,
    cipher_suites: tuple[int, ...] = (47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4),
    extensions: bytes | None = None,
    session_id: bytes = b"",
) -> bytes:
    if extensions is None:
        extensions = (
            _extension(0, b"")
            + _extension(10, struct.pack("!H", 6) + struct.pack("!3H", 23, 24, 25))
            + _extension(11, bytes([1]) + bytes([0]))
        )
    body = (
        struct.pack("!H", client_version)
        + b"\x00" * 32  # random
        + bytes([len(session_id)])
        + session_id
        + struct.pack("!H", len(cipher_suites) * 2)
        + struct.pack(f"!{len(cipher_suites)}H", *cipher_suites)
        + b"\x01\x00"  # one compression method: null
        + struct.pack("!H", len(extensions))
        + extensions
    )
    fragment = bytes([_CLIENT_HELLO]) + len(body).to_bytes(3, "big") + body
    record = bytes([_HANDSHAKE]) + _TLS_1_2_RECORD_VERSION + struct.pack("!H", len(fragment)) + fragment
    return record


def test_matches_the_official_ja3_specification_example() -> None:
    """The exact worked example from the JA3 README (salesforce/ja3): known string and hash."""
    packet = _client_hello()

    fingerprint = compute_ja3(packet)

    assert fingerprint is not None
    assert fingerprint.ja3_string == "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
    assert fingerprint.ja3_hash == "ada70206e40642a3e4461f35503241d5"


def test_grease_values_are_excluded_from_every_field() -> None:
    """RFC 8701 GREASE values must not change the fingerprint (JA3 spec requirement)."""
    grease_cipher = 0x0A0A
    grease_extension = 0x2A2A
    baseline = compute_ja3(_client_hello())
    assert baseline is not None

    with_grease = _client_hello(
        cipher_suites=(grease_cipher, 47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4),
        extensions=(
            _extension(grease_extension, b"\x00\x00")
            + _extension(0, b"")
            + _extension(10, struct.pack("!H", 6) + struct.pack("!3H", 23, 24, 25))
            + _extension(11, bytes([1]) + bytes([0]))
        ),
    )
    fingerprint = compute_ja3(with_grease)

    assert fingerprint is not None
    assert fingerprint.ja3_hash == baseline.ja3_hash


def test_match_known_tool_finds_a_seeded_fingerprint() -> None:
    packet = _client_hello()
    fingerprint = compute_ja3(packet)
    assert fingerprint is not None

    known_hashes = {fingerprint.ja3_hash: "test-attack-tool"}
    match = match_known_tool(fingerprint, known_hashes)

    assert match is not None
    assert match.tool == "test-attack-tool"
    assert match.ja3_hash == fingerprint.ja3_hash


def test_a_different_ordinary_clienthello_does_not_match() -> None:
    """A browser-shaped ClientHello with a different cipher list must not match another tool's hash."""
    seeded = compute_ja3(_client_hello())
    assert seeded is not None
    known_hashes = {seeded.ja3_hash: "test-attack-tool"}

    browser_like = _client_hello(
        client_version=0x0303,
        cipher_suites=(4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392),
    )
    fingerprint = compute_ja3(browser_like)
    assert fingerprint is not None

    assert fingerprint.ja3_hash != seeded.ja3_hash
    assert match_known_tool(fingerprint, known_hashes) is None


def test_non_handshake_record_returns_none() -> None:
    application_data = bytes([23]) + _TLS_1_2_RECORD_VERSION + struct.pack("!H", 5) + b"hello"
    assert compute_ja3(application_data) is None


def test_handshake_record_that_is_not_a_clienthello_returns_none() -> None:
    server_hello_type = 2
    fragment = bytes([server_hello_type]) + (4).to_bytes(3, "big") + b"\x00" * 4
    record = bytes([_HANDSHAKE]) + _TLS_1_2_RECORD_VERSION + struct.pack("!H", len(fragment)) + fragment
    assert compute_ja3(record) is None


def test_empty_payload_does_not_crash() -> None:
    assert compute_ja3(b"") is None


def test_truncated_record_does_not_crash() -> None:
    assert compute_ja3(bytes([_HANDSHAKE, 0x03])) is None


def test_truncated_clienthello_body_does_not_crash() -> None:
    fragment = bytes([_CLIENT_HELLO]) + (500).to_bytes(3, "big") + b"\x03\x03"  # claims 500 bytes, has 2
    record = bytes([_HANDSHAKE]) + _TLS_1_2_RECORD_VERSION + struct.pack("!H", len(fragment)) + fragment
    compute_ja3(record)  # must not raise


def test_garbage_bytes_do_not_crash() -> None:
    compute_ja3(b"\x16\x03\x03\xff\xff\x01\x00\x00")


# --- load_known_tool_fingerprints ---


def test_load_known_tool_fingerprints_from_the_real_seed_file() -> None:
    """The seed file this project ships must actually load and be non-empty."""
    table = load_known_tool_fingerprints(Path("config/known_tool_fingerprints.toml"))
    assert len(table) >= 1
    assert all(len(h) == 32 for h in table)
    assert "Nikto" in table.values() or any("Nikto" in v for v in table.values())


def test_load_known_tool_fingerprints_missing_file_degrades_to_empty(tmp_path: Path) -> None:
    assert load_known_tool_fingerprints(tmp_path / "nonexistent.toml") == {}


def test_load_known_tool_fingerprints_malformed_toml_degrades_to_empty(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("this is not [ valid toml", encoding="utf-8")
    assert load_known_tool_fingerprints(path) == {}


def test_load_known_tool_fingerprints_invalid_schema_degrades_to_empty(tmp_path: Path) -> None:
    path = tmp_path / "bad_schema.toml"
    path.write_text('[[fingerprint]]\nhash = ""\ntool = "x"\n', encoding="utf-8")  # empty hash: invalid
    assert load_known_tool_fingerprints(path) == {}


def test_load_known_tool_fingerprints_lowercases_hashes(tmp_path: Path) -> None:
    path = tmp_path / "mixed_case.toml"
    path.write_text('[[fingerprint]]\nhash = "ABCDEF00"\ntool = "example"\n', encoding="utf-8")
    table = load_known_tool_fingerprints(path)
    assert table == {"abcdef00": "example"}


@pytest.mark.parametrize("value", [0x0A0A, 0x1A1A, 0xFAFA])
def test_is_grease_recognizes_reserved_values(value: int) -> None:
    from pirewall.detection.tls_fingerprint import _is_grease  # pyright: ignore[reportPrivateUsage]

    assert _is_grease(value) is True


def test_is_grease_does_not_flag_ordinary_cipher_suite_values() -> None:
    from pirewall.detection.tls_fingerprint import _is_grease  # pyright: ignore[reportPrivateUsage]

    assert _is_grease(47) is False
    assert _is_grease(49161) is False

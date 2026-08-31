"""`pirewall.detection.tls_heartbeat`: Heartbleed (CVE-2014-0160) length-mismatch check (ADDENDUM_2.md B4)."""

import struct

from pirewall.detection.tls_heartbeat import check_heartbleed

_HEARTBEAT = 24
_HANDSHAKE = 22
_APPLICATION_DATA = 23
_TLS_1_2 = b"\x03\x03"


def _record(content_type: int, fragment: bytes, declared_length: int | None = None) -> bytes:
    length = len(fragment) if declared_length is None else declared_length
    return bytes([content_type]) + _TLS_1_2 + struct.pack("!H", length) + fragment


def test_heartbleed_signature_is_detected() -> None:
    """The literal CVE-2014-0160 proof-of-concept shape: a 3-byte fragment claiming 16384 bytes."""
    fragment = b"\x01" + struct.pack("!H", 16384)  # request, claimed payload_length=16384
    packet = _record(_HEARTBEAT, fragment)  # record.length == len(fragment) == 3, no payload/padding

    match = check_heartbleed(packet)

    assert match is not None
    assert match.claimed_payload_length == 16384
    assert match.available_bytes == 0


def test_well_formed_heartbeat_does_not_trigger() -> None:
    payload = b"ping!"
    padding = b"\x00" * 16
    fragment = b"\x01" + struct.pack("!H", len(payload)) + payload + padding
    packet = _record(_HEARTBEAT, fragment)

    assert check_heartbleed(packet) is None


def test_handshake_record_does_not_trigger() -> None:
    packet = _record(_HANDSHAKE, b"\x01\x00\x00\x10" + b"\x00" * 16)  # a ClientHello-shaped fragment
    assert check_heartbleed(packet) is None


def test_application_data_record_does_not_trigger() -> None:
    packet = _record(_APPLICATION_DATA, b"\x00" * 40)
    assert check_heartbleed(packet) is None


def test_empty_payload_does_not_crash() -> None:
    assert check_heartbleed(b"") is None


def test_truncated_record_header_does_not_crash() -> None:
    assert check_heartbleed(bytes([_HEARTBEAT, 0x03])) is None


def test_heartbeat_fragment_too_short_for_a_header_does_not_crash() -> None:
    # Declares a heartbeat record but the fragment is only 2 bytes — too
    # short to even contain the 3-byte heartbeat message header.
    packet = _record(_HEARTBEAT, b"\x01\x00")
    assert check_heartbleed(packet) is None


def test_declared_length_exceeding_captured_bytes_does_not_crash_or_falsely_match() -> None:
    """A record claiming a longer fragment than was actually captured must degrade gracefully."""
    fragment = b"\x01" + struct.pack("!H", 5) + b"hello" + b"\x00" * 16
    # Declare a length far beyond what's actually appended.
    packet = _record(_HEARTBEAT, fragment, declared_length=60000)

    # Must not raise, and must not fabricate a match from bytes that were
    # never actually present.
    result = check_heartbleed(packet)
    assert result is None


def test_garbage_after_a_valid_looking_header_does_not_crash() -> None:
    packet = bytes([_HEARTBEAT]) + _TLS_1_2 + b"\xff\xff" + b"\x01\x02"
    check_heartbleed(packet)  # must not raise

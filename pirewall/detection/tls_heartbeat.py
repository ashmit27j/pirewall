"""Heartbleed (CVE-2014-0160) detector — TLS record-layer length check (ADDENDUM_2.md B4).

**Why this is not "payload inspection" in the sense spec §7 rules out.**
Spec §7 forbids application-payload inspection as part of the core
detection pipeline — the concern being decrypted/decodable *application
content* (an HTTP body, a file transfer, message text). A TLS record
header and a heartbeat message header are neither: they are sent in
**cleartext, by protocol design**, before any encrypted application data
exists on the connection, and this module parses exactly two fixed-width
integer fields out of them — the record's declared length and the
heartbeat's claimed payload length. That is the same category of work as
`pirewall.capture.parser` reading a TCP header's data-offset field, not
content decryption or decoding. It cannot see, and never touches, anything
that was ever encrypted. This distinction matters enough to the paper's
honesty about "no payload inspection" that it is stated here explicitly,
not left implicit.

**TLS record structure** (RFC 8446 §5.1 — unchanged at this layer since
TLS 1.0/RFC 2246):

    struct {
        ContentType type;         // 1 byte
        ProtocolVersion version;  // 2 bytes
        uint16 length;            // 2 bytes -- length of `fragment`
        opaque fragment[length];
    } TLSPlaintext;

**Heartbeat message structure** (RFC 6520 §4 — the `fragment` of a
content-type-24, i.e. Heartbeat, record):

    struct {
        HeartbeatMessageType type;  // 1 byte: 1 = request, 2 = response
        uint16 payload_length;
        opaque payload[payload_length];
        opaque padding[padding_length];  // >= 16 bytes, RFC-mandated
    } HeartbeatMessage;

**CVE-2014-0160 (Heartbleed).** A vulnerable server trusts the
attacker-supplied `payload_length` field when building its response,
copying that many bytes from its own heap regardless of how many bytes the
*record itself* actually contained — leaking adjacent memory. The
detectable signature, visible on the wire before any response and without
decrypting anything, is exactly that mismatch: `payload_length` claims more
bytes than the record's own fragment could possibly hold. This is the same
network-based detection technique security scanners used against
CVE-2014-0160 in 2014 (the reference Python proof-of-concept and
contemporary Snort/Suricata signatures all check this same field
relationship) — not a technique invented for this project.
"""

import struct
from dataclasses import dataclass

_RECORD_HEADER_LEN = 5
_CONTENT_TYPE_HEARTBEAT = 24
_HEARTBEAT_HEADER_LEN = 3  # 1 byte message type + 2 byte payload_length

# Every other field in the record and heartbeat headers, validated before the
# length comparison is trusted.
#
# This matters far more than it looks. `check_heartbleed` is handed raw TCP
# payload bytes from anywhere in a stream, and a mid-stream segment does not
# begin at a TLS record boundary — on an established connection those bytes
# are ciphertext. Checking only `payload[0] == 24` therefore fires on roughly
# one segment in 256 *by chance*, and ciphertext then yields a large random
# "claimed_payload_length" that all but always exceeds the fragment, so the
# mismatch test passes too. On a real deployment that produced a CRITICAL
# BLOCK against ordinary HTTPS browsing within minutes.
#
# Constraining the surrounding fields removes that: a random 6-byte prefix
# has to satisfy the content type (1/256), a legal protocol version (~5 of
# 65536), a legal heartbeat message type (2/256) and a record length inside
# TLS's own limit, which together is vanishingly unlikely to occur by chance.
_LEGAL_VERSIONS = frozenset({0x0300, 0x0301, 0x0302, 0x0303, 0x0304})

# RFC 8446 §5.1: TLSPlaintext.length must not exceed 2^14; TLSCiphertext adds
# at most 256 bytes of expansion. Anything larger is not a TLS record.
_MAX_RECORD_LENGTH = 2**14 + 256

_HEARTBEAT_REQUEST = 1
_HEARTBEAT_RESPONSE = 2
_LEGAL_HEARTBEAT_TYPES = frozenset({_HEARTBEAT_REQUEST, _HEARTBEAT_RESPONSE})


@dataclass(frozen=True, slots=True)
class HeartbleedMatch:
    """One TLS record whose heartbeat `payload_length` exceeds what the record actually holds."""

    claimed_payload_length: int
    available_bytes: int


def check_heartbleed(payload: bytes) -> HeartbleedMatch | None:
    """Scan `payload` (raw TCP payload bytes) for a Heartbleed-signature TLS heartbeat record.

    `available_bytes` is measured against what was actually captured, not
    against the record's own (attacker-controlled) declared length — a
    Python byte-slice past the end of `payload` simply yields fewer bytes,
    it never raises, so a record claiming a length larger than what's
    present is graceful, not an error.

    Degrades to `None` for anything that doesn't cleanly parse as a TLS
    heartbeat record — too short, a different content type, or a heartbeat
    fragment too short to even contain a heartbeat message header. Never
    raises: this must not be able to crash the capture pipeline on
    malformed or non-TLS traffic seen on port 443.
    """
    try:
        return _check_heartbleed(payload)
    except Exception:  # belt-and-suspenders, matching pirewall.capture.parser's own guard
        return None


def _check_heartbleed(payload: bytes) -> HeartbleedMatch | None:
    if len(payload) < _RECORD_HEADER_LEN:
        return None
    if payload[0] != _CONTENT_TYPE_HEARTBEAT:
        return None

    # Validate every other field of both headers before trusting the length
    # comparison. Without this the check fires on ciphertext that merely
    # happens to start with byte 24 — see `_LEGAL_VERSIONS` above.
    version = struct.unpack("!H", payload[1:3])[0]
    if version not in _LEGAL_VERSIONS:
        return None

    declared_length = struct.unpack("!H", payload[3:5])[0]
    if declared_length < _HEARTBEAT_HEADER_LEN or declared_length > _MAX_RECORD_LENGTH:
        return None

    fragment = payload[_RECORD_HEADER_LEN : _RECORD_HEADER_LEN + declared_length]
    if len(fragment) < _HEARTBEAT_HEADER_LEN:
        return None

    if fragment[0] not in _LEGAL_HEARTBEAT_TYPES:
        return None

    claimed_payload_length = struct.unpack("!H", fragment[1:3])[0]
    available_bytes = len(fragment) - _HEARTBEAT_HEADER_LEN
    if claimed_payload_length > available_bytes:
        return HeartbleedMatch(
            claimed_payload_length=claimed_payload_length, available_bytes=available_bytes
        )
    return None

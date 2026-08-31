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
    content_type = payload[0]
    if content_type != _CONTENT_TYPE_HEARTBEAT:
        return None

    declared_length = struct.unpack("!H", payload[3:5])[0]
    fragment = payload[_RECORD_HEADER_LEN : _RECORD_HEADER_LEN + declared_length]
    if len(fragment) < _HEARTBEAT_HEADER_LEN:
        return None

    claimed_payload_length = struct.unpack("!H", fragment[1:3])[0]
    available_bytes = len(fragment) - _HEARTBEAT_HEADER_LEN
    if claimed_payload_length > available_bytes:
        return HeartbleedMatch(
            claimed_payload_length=claimed_payload_length, available_bytes=available_bytes
        )
    return None

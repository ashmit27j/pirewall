"""TLS ClientHello fingerprinting (JA3-style) for known attack tooling (ADDENDUM_2.md B5).

**Why this is "lookahead", not payload inspection.** The ClientHello —
cipher suites offered, extensions, elliptic curves, EC point formats — is
sent **in cleartext, by protocol design**, before any encrypted data exists
on the connection; it is the client announcing its own TLS capabilities to
negotiate with, not application content. Reading it is the same category
of work as `pirewall.detection.tls_heartbeat` reading a heartbeat length
field, or `pirewall.capture.parser` reading a TCP header — never content
decryption or decoding.

**Algorithm: JA3** (John Althouse, Jeff Atkinson, Josh Atkins; Salesforce,
2017), <https://github.com/salesforce/ja3> — implemented from that
specification, not an invented variant. Five fields are read from the
ClientHello: TLS version, cipher suites, extension types, elliptic curves
(the `supported_groups` extension, type 10), and EC point formats
(extension type 11). GREASE values (RFC 8701 — reserved values of the form
`0x?A?A` a client sends to test extensibility, randomized per connection)
are excluded from every field, exactly as the JA3 specification requires,
because otherwise an identical client would hash differently on every
connection. The five fields are joined
`"TLSVersion,Cipher-Cipher-...,Ext-Ext-...,Curve-Curve-...,PointFormat-..."`
(comma between fields, hyphen between values, an absent field left empty)
and MD5-hashed — MD5 here is the specification's own choice for a
compact, comparable identifier, not a security control.

**Honest limitation, stated plainly (this is real but partial coverage,
not a general solution):** this detects known, *unmodified* tooling only.
An attacker who randomizes their TLS library's cipher/extension ordering,
or simply uses a different TLS stack, produces a different JA3 hash
trivially — there is no cryptographic or structural reason a real attacker
couldn't evade this. `config/known_tool_fingerprints.toml` (the seed list
this module matches against) also needs an ongoing maintenance process to
stay useful; see that file's own header for where its entries came from
and how stale they can get.
"""

import hashlib
import struct
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from pydantic import Field, ValidationError

from pirewall.core.models.common import PirewallModel

_HANDSHAKE_CONTENT_TYPE = 22
_CLIENT_HELLO_HANDSHAKE_TYPE = 1
_RANDOM_LEN = 32
_EXT_SUPPORTED_GROUPS = 10
_EXT_EC_POINT_FORMATS = 11


def _is_grease(value: int) -> bool:
    """RFC 8701: a GREASE value's two bytes are identical, and end in the nibble 0xA."""
    high, low = value >> 8, value & 0xFF
    return high == low and (low & 0x0F) == 0x0A


@dataclass(frozen=True, slots=True)
class ClientHelloFingerprint:
    """One ClientHello's JA3 string and hash."""

    ja3_string: str
    ja3_hash: str


@dataclass(frozen=True, slots=True)
class KnownToolMatch:
    """A `ClientHelloFingerprint` that matched an entry in the known-tool table."""

    tool: str
    ja3_hash: str


def compute_ja3(payload: bytes) -> ClientHelloFingerprint | None:
    """Compute the JA3 fingerprint of a ClientHello found in `payload`, or `None`.

    Degrades to `None` for anything that isn't cleanly a TLS Handshake
    record carrying a ClientHello — truncated, a different content type, a
    different handshake type, or a ClientHello fragmented across more than
    one TLS record (a real, disclosed limitation: this only ever looks at
    one captured TCP payload slice). Never raises.
    """
    try:
        return _compute_ja3(payload)
    except Exception:  # belt-and-suspenders, matching parse_packet's own guard
        return None


def _uint16(data: bytes) -> int:
    return int(struct.unpack("!H", data)[0])


def _compute_ja3(payload: bytes) -> ClientHelloFingerprint | None:
    if len(payload) < 5 or payload[0] != _HANDSHAKE_CONTENT_TYPE:
        return None
    record_length = _uint16(payload[3:5])
    fragment = payload[5 : 5 + record_length]
    if len(fragment) < 4 or fragment[0] != _CLIENT_HELLO_HANDSHAKE_TYPE:
        return None

    hello_length = int.from_bytes(fragment[1:4], "big")
    body = fragment[4 : 4 + hello_length]
    offset: int = 0

    if len(body) < offset + 2:
        return None
    client_version = _uint16(body[offset : offset + 2])
    offset += 2 + _RANDOM_LEN

    if len(body) < offset + 1:
        return None
    session_id_length: int = body[offset]
    offset += 1 + session_id_length

    if len(body) < offset + 2:
        return None
    cipher_suites_length = _uint16(body[offset : offset + 2])
    offset += 2
    cipher_suites = _parse_uint16_list(body[offset : offset + cipher_suites_length])
    offset += cipher_suites_length

    if len(body) < offset + 1:
        return None
    compression_methods_length: int = body[offset]
    offset += 1 + compression_methods_length

    extensions, elliptic_curves, ec_point_formats = _parse_extensions(body[offset:])

    ja3_string = ",".join(
        (
            str(client_version),
            "-".join(str(value) for value in cipher_suites if not _is_grease(value)),
            "-".join(str(value) for value in extensions if not _is_grease(value)),
            "-".join(str(value) for value in elliptic_curves if not _is_grease(value)),
            "-".join(str(value) for value in ec_point_formats),
        )
    )
    ja3_hash = hashlib.md5(ja3_string.encode("ascii"), usedforsecurity=False).hexdigest()
    return ClientHelloFingerprint(ja3_string=ja3_string, ja3_hash=ja3_hash)


def _parse_uint16_list(data: bytes) -> list[int]:
    if len(data) % 2 != 0:
        return []
    return [int(value) for value in struct.unpack(f"!{len(data) // 2}H", data)]


def _parse_extensions(remainder: bytes) -> tuple[list[int], list[int], list[int]]:
    """Parse the ClientHello's optional trailing extensions block, if present."""
    if len(remainder) < 2:
        return [], [], []
    extensions_length = _uint16(remainder[0:2])
    block = remainder[2 : 2 + extensions_length]

    extension_types: list[int] = []
    elliptic_curves: list[int] = []
    ec_point_formats: list[int] = []
    offset: int = 0
    while offset + 4 <= len(block):
        extension_type = _uint16(block[offset : offset + 2])
        extension_length = _uint16(block[offset + 2 : offset + 4])
        extension_data = block[offset + 4 : offset + 4 + extension_length]
        offset += 4 + extension_length
        extension_types.append(extension_type)

        if extension_type == _EXT_SUPPORTED_GROUPS and len(extension_data) >= 2:
            list_length = _uint16(extension_data[0:2])
            elliptic_curves = _parse_uint16_list(extension_data[2 : 2 + list_length])
        elif extension_type == _EXT_EC_POINT_FORMATS and len(extension_data) >= 1:
            list_length = extension_data[0]
            ec_point_formats = list(extension_data[1 : 1 + list_length])

    return extension_types, elliptic_curves, ec_point_formats


def match_known_tool(
    fingerprint: ClientHelloFingerprint, known_hashes: Mapping[str, str]
) -> KnownToolMatch | None:
    """Look up `fingerprint.ja3_hash` (already lowercase hex) in `known_hashes`."""
    tool = known_hashes.get(fingerprint.ja3_hash)
    if tool is None:
        return None
    return KnownToolMatch(tool=tool, ja3_hash=fingerprint.ja3_hash)


class _FingerprintEntry(PirewallModel):
    """One `[[fingerprint]]` table in `config/known_tool_fingerprints.toml`."""

    hash: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    # `tested`/`source` are documentation for a human reading the TOML file
    # (see that file's own header) — not read by the loader, but accepted
    # rather than rejected as a stray field.
    tested: str | None = None
    source: str | None = None


class _FingerprintFile(PirewallModel):
    fingerprint: tuple[_FingerprintEntry, ...] = Field(default_factory=tuple)


def load_known_tool_fingerprints(path: Path) -> dict[str, str]:
    """Load `path` (TOML, see `config/known_tool_fingerprints.toml`) into `{ja3_hash: tool_name}`.

    Degrades to an empty table for a missing file or malformed/invalid
    content — same "must not prevent pirewall-core from starting"
    principle `pirewall.detection.coordinator.load_models` established for
    missing ML artifacts. An empty table simply means no JA3 matches are
    ever reported; every other detector keeps working.
    """
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
        parsed = _FingerprintFile.model_validate(raw)
    except (OSError, tomllib.TOMLDecodeError, ValidationError):
        return {}
    return {entry.hash.lower(): entry.tool for entry in parsed.fingerprint}

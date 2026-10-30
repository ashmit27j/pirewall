"""The canonical, versioned feature schema (spec §11, §15).

This is the single source of truth for feature names, order, units, and
semantics. `pirewall.features.extractor` (runtime), Phase 4's dataset
adapters, and Phase 5's inference path must all import from here — no module
may define its own feature list.

**Two frozen versions live here.** `SCHEMA_VERSION` (3.0.0) is the phase-19
native-engine schema used by the v2 pipeline's D2/D3 models. `2.0.0` is kept
computable, unchanged, for the v1 models that still run under
`engine = "v1"`; the extractor projects one shared set of primitive values
through whichever version's column list the caller asks for. A model is only
ever fed a vector carrying the version it was trained on (the loader and
per-call check enforce this).

* 3.0.0 replaces the raw integer `destination_port` with a coarse service
  category (`destination_port_category`, `PortCategory`). Raw ports are
  identity/shortcut features (ADDENDUM_4.md D3, critique_ml.md §3) and must
  not be model inputs.
* 2.0.0 is frozen exactly as shipped: the same 23 rows, names and order, so
  vectors computed for v1 are bit-identical to before this module gained
  versioning.

**IPv4-only scope (ADDENDUM.md A5):** every feature here is defined in
terms of `pirewall.core.models.Flow`, which can only ever represent an
IPv4 flow (its `source_ip`/`destination_ip` fields are typed `IPv4Address`,
not a union) — there is no code path by which an IPv6 packet can reach
this schema. `pirewall.flow.aggregator.FlowAggregator` is what enforces
this upstream, by never routing an IPv6 `PacketMetadata` into the flow
table in the first place.
"""

from dataclasses import dataclass
from enum import IntEnum, StrEnum

SCHEMA_VERSION = "3.0.0"
"""The current canonical schema version (phase 19).

Every artifact trained after the schema freeze carries this version. The v1
models trained against 2.0.0 keep working through an explicit
`LEGACY_SCHEMA_VERSION` projection; see `feature_names`/`extract_features`.
"""

LEGACY_SCHEMA_VERSION = "2.0.0"
"""The frozen v1 schema: 23 columns, raw `destination_port` included.

Kept only so `engine = "v1"` can keep using the artifacts that were shipped
before phase 19. It is not a target for new training.
"""

SUPPORTED_SCHEMA_VERSIONS: tuple[str, ...] = (SCHEMA_VERSION, LEGACY_SCHEMA_VERSION)


class FeatureType(StrEnum):
    """The semantic category of a feature's value, for documentation/consumers."""

    DURATION = "duration"
    COUNT = "count"
    RATE = "rate"
    SIZE = "size"
    RATIO = "ratio"
    FLAG = "flag"
    PORT = "port"
    CATEGORY = "category"


class PortCategory(IntEnum):
    """Coarse destination-service bucket used by schema 3.0.0.

    The integer is a stable code, not an ordinal measurement: a tree model
    may split on it, but no consumer may read "web > dns" as a magnitude.
    The mapping is total over `int | None`; see `port_category`.
    """

    NONE = 0
    WEB = 1
    DNS = 2
    SSH = 3
    MAIL = 4
    OTHER_WELL_KNOWN = 5
    EPHEMERAL = 6


# Named buckets are deliberately narrow and documented. Everything else is
# decided by the IANA split (well-known < 1024, ephemeral >= 1024), so the
# mapping never depends on a data file or a runtime lookup.
_WEB_PORTS = frozenset({80, 443, 8080, 8443})
_DNS_PORTS = frozenset({53})
_SSH_PORTS = frozenset({22})
_MAIL_PORTS = frozenset({25, 110, 143, 465, 587, 993, 995})

PORT_CATEGORY_DESCRIPTIONS: dict[PortCategory, str] = {
    PortCategory.NONE: "no L4 destination port (e.g. ICMP)",
    PortCategory.WEB: "common HTTP(S): 80, 443, 8080, 8443",
    PortCategory.DNS: "DNS: 53",
    PortCategory.SSH: "SSH: 22",
    PortCategory.MAIL: "mail: 25, 110, 143, 465, 587, 993, 995",
    PortCategory.OTHER_WELL_KNOWN: "any other port in 0..1023",
    PortCategory.EPHEMERAL: "any port >= 1024 not in a named bucket",
}


def port_category(port: int | None) -> PortCategory:
    """Map a destination port (or `None`) to its coarse `PortCategory`.

    Total by construction: every `int | None` a validated `Flow` can carry
    lands in exactly one bucket.
    """
    if port is None:
        return PortCategory.NONE
    if port in _WEB_PORTS:
        return PortCategory.WEB
    if port in _DNS_PORTS:
        return PortCategory.DNS
    if port in _SSH_PORTS:
        return PortCategory.SSH
    if port in _MAIL_PORTS:
        return PortCategory.MAIL
    if port <= 1023:
        return PortCategory.OTHER_WELL_KNOWN
    return PortCategory.EPHEMERAL


@dataclass(frozen=True, slots=True)
class FeatureDefinition:
    """One entry in the canonical feature schema."""

    name: str
    feature_type: FeatureType
    unit: str
    description: str


# (name, feature_type, unit, description) — kept as a plain data table so each
# row stays short; converted into `FeatureDefinition`s below.
_FEATURE_TABLE_V2: tuple[tuple[str, FeatureType, str, str], ...] = (
    ("duration_seconds", FeatureType.DURATION, "seconds", "Time between the flow's first/last packet."),
    ("packet_count", FeatureType.COUNT, "packets", "Total packets observed in the flow."),
    ("forward_packet_count", FeatureType.COUNT, "packets", "Packets in the initiating direction."),
    ("backward_packet_count", FeatureType.COUNT, "packets", "Packets in the response direction."),
    ("payload_byte_count", FeatureType.SIZE, "bytes", "L4 payload bytes, both directions."),
    ("forward_payload_byte_count", FeatureType.SIZE, "bytes", "L4 payload bytes, initiating direction."),
    ("backward_payload_byte_count", FeatureType.SIZE, "bytes", "L4 payload bytes, response direction."),
    ("packets_per_second", FeatureType.RATE, "packets/second", "packet_count / duration (0 if 0)."),
    ("payload_bytes_per_second", FeatureType.RATE, "bytes/second", "payload_byte_count / duration (0 if 0)."),
    ("mean_payload_size", FeatureType.SIZE, "bytes", "Mean per-packet L4 payload size."),
    ("std_payload_size", FeatureType.SIZE, "bytes", "Sample std (n-1) of per-packet payload size."),
    ("min_payload_size", FeatureType.SIZE, "bytes", "Smallest per-packet payload (0 for a bare ACK)."),
    ("max_payload_size", FeatureType.SIZE, "bytes", "Largest per-packet payload."),
    ("mean_inter_arrival_seconds", FeatureType.DURATION, "seconds", "Mean inter-packet time."),
    ("std_inter_arrival_seconds", FeatureType.DURATION, "seconds", "Sample std (n-1) of inter-packet time."),
    ("min_inter_arrival_seconds", FeatureType.DURATION, "seconds", "Smallest inter-packet time."),
    ("max_inter_arrival_seconds", FeatureType.DURATION, "seconds", "Largest inter-packet time."),
    ("forward_backward_payload_ratio", FeatureType.RATIO, "ratio", "Forward/backward payload (0 if 0)."),
    ("destination_port", FeatureType.PORT, "port", "Destination port, or -1 if none (e.g. ICMP)."),
    ("protocol_is_tcp", FeatureType.FLAG, "boolean", "1.0 if the flow's protocol is TCP, else 0.0."),
    ("protocol_is_udp", FeatureType.FLAG, "boolean", "1.0 if the flow's protocol is UDP, else 0.0."),
    ("protocol_is_icmp", FeatureType.FLAG, "boolean", "1.0 if the flow's protocol is ICMP, else 0.0."),
    ("protocol_is_other", FeatureType.FLAG, "boolean", "1.0 if the protocol is none of TCP/UDP/ICMP."),
)

# 3.0.0 keeps every 2.0.0 row and meaning except the raw port, which becomes
# a documented category code. Kept as a separate literal table so a reviewer
# can diff the two frozen lists directly.
_FEATURE_TABLE_V3: tuple[tuple[str, FeatureType, str, str], ...] = (
    ("duration_seconds", FeatureType.DURATION, "seconds", "Time between the flow's first/last packet."),
    ("packet_count", FeatureType.COUNT, "packets", "Total packets observed in the flow."),
    ("forward_packet_count", FeatureType.COUNT, "packets", "Packets in the initiating direction."),
    ("backward_packet_count", FeatureType.COUNT, "packets", "Packets in the response direction."),
    ("payload_byte_count", FeatureType.SIZE, "bytes", "L4 payload bytes, both directions."),
    ("forward_payload_byte_count", FeatureType.SIZE, "bytes", "L4 payload bytes, initiating direction."),
    ("backward_payload_byte_count", FeatureType.SIZE, "bytes", "L4 payload bytes, response direction."),
    ("packets_per_second", FeatureType.RATE, "packets/second", "packet_count / duration (0 if 0)."),
    ("payload_bytes_per_second", FeatureType.RATE, "bytes/second", "payload_byte_count / duration (0 if 0)."),
    ("mean_payload_size", FeatureType.SIZE, "bytes", "Mean per-packet L4 payload size."),
    ("std_payload_size", FeatureType.SIZE, "bytes", "Sample std (n-1) of per-packet payload size."),
    ("min_payload_size", FeatureType.SIZE, "bytes", "Smallest per-packet payload (0 for a bare ACK)."),
    ("max_payload_size", FeatureType.SIZE, "bytes", "Largest per-packet payload."),
    ("mean_inter_arrival_seconds", FeatureType.DURATION, "seconds", "Mean inter-packet time."),
    ("std_inter_arrival_seconds", FeatureType.DURATION, "seconds", "Sample std (n-1) of inter-packet time."),
    ("min_inter_arrival_seconds", FeatureType.DURATION, "seconds", "Smallest inter-packet time."),
    ("max_inter_arrival_seconds", FeatureType.DURATION, "seconds", "Largest inter-packet time."),
    ("forward_backward_payload_ratio", FeatureType.RATIO, "ratio", "Forward/backward payload (0 if 0)."),
    (
        "destination_port_category",
        FeatureType.CATEGORY,
        "category code",
        "Coarse destination-service bucket: 0 none, 1 web, 2 dns, 3 ssh, 4 mail, "
        "5 other well-known (0..1023), 6 ephemeral (>=1024).",
    ),
    ("protocol_is_tcp", FeatureType.FLAG, "boolean", "1.0 if the flow's protocol is TCP, else 0.0."),
    ("protocol_is_udp", FeatureType.FLAG, "boolean", "1.0 if the flow's protocol is UDP, else 0.0."),
    ("protocol_is_icmp", FeatureType.FLAG, "boolean", "1.0 if the flow's protocol is ICMP, else 0.0."),
    ("protocol_is_other", FeatureType.FLAG, "boolean", "1.0 if the protocol is none of TCP/UDP/ICMP."),
)


def _definitions(
    table: tuple[tuple[str, FeatureType, str, str], ...],
) -> tuple[FeatureDefinition, ...]:
    return tuple(
        FeatureDefinition(name=name, feature_type=feature_type, unit=unit, description=description)
        for name, feature_type, unit, description in table
    )


LEGACY_FEATURE_DEFINITIONS: tuple[FeatureDefinition, ...] = _definitions(_FEATURE_TABLE_V2)
LEGACY_FEATURE_NAMES: tuple[str, ...] = tuple(
    definition.name for definition in LEGACY_FEATURE_DEFINITIONS
)

FEATURE_DEFINITIONS: tuple[FeatureDefinition, ...] = _definitions(_FEATURE_TABLE_V3)
FEATURE_NAMES: tuple[str, ...] = tuple(definition.name for definition in FEATURE_DEFINITIONS)

_DEFINITIONS_BY_VERSION: dict[str, tuple[FeatureDefinition, ...]] = {
    SCHEMA_VERSION: FEATURE_DEFINITIONS,
    LEGACY_SCHEMA_VERSION: LEGACY_FEATURE_DEFINITIONS,
}


def supports_schema_version(version: str) -> bool:
    """Whether `version` is one this build can compute and validate."""
    return version in _DEFINITIONS_BY_VERSION


def feature_definitions(version: str = SCHEMA_VERSION) -> tuple[FeatureDefinition, ...]:
    """The ordered definitions for `version`; raises `KeyError` if unknown."""
    return _DEFINITIONS_BY_VERSION[version]


def feature_names(version: str = SCHEMA_VERSION) -> tuple[str, ...]:
    """The ordered feature names for `version`; raises `KeyError` if unknown."""
    return tuple(definition.name for definition in feature_definitions(version))


for _names in (FEATURE_NAMES, LEGACY_FEATURE_NAMES):
    assert len(set(_names)) == len(_names), "duplicate feature name in schema"

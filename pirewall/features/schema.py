"""The canonical, versioned feature schema (spec §11, §15).

This is the single source of truth for feature names, order, units, and
semantics. `pirewall.features.extractor` (runtime), Phase 4's dataset
adapters, and Phase 5's inference path must all import `FEATURE_NAMES` /
`SCHEMA_VERSION` from here — no module may define its own feature list.

**IPv4-only scope (ADDENDUM.md A5):** every feature here is defined in
terms of `pirewall.core.models.Flow`, which can only ever represent an
IPv4 flow (its `source_ip`/`destination_ip` fields are typed `IPv4Address`,
not a union) — there is no code path by which an IPv6 packet can reach
this schema. `pirewall.flow.aggregator.FlowAggregator` is what enforces
this upstream, by never routing an IPv6 `PacketMetadata` into the flow
table in the first place.
"""

from dataclasses import dataclass
from enum import StrEnum

SCHEMA_VERSION = "1.0.0"


class FeatureType(StrEnum):
    """The semantic category of a feature's value, for documentation/consumers."""

    DURATION = "duration"
    COUNT = "count"
    RATE = "rate"
    SIZE = "size"
    RATIO = "ratio"
    FLAG = "flag"
    PORT = "port"


@dataclass(frozen=True, slots=True)
class FeatureDefinition:
    """One entry in the canonical feature schema."""

    name: str
    feature_type: FeatureType
    unit: str
    description: str


# (name, feature_type, unit, description) — kept as a plain data table so each
# row stays short; converted into `FeatureDefinition`s below.
_FEATURE_TABLE: tuple[tuple[str, FeatureType, str, str], ...] = (
    ("duration_seconds", FeatureType.DURATION, "seconds", "Time between the flow's first/last packet."),
    ("packet_count", FeatureType.COUNT, "packets", "Total packets observed in the flow."),
    ("byte_count", FeatureType.SIZE, "bytes", "Total bytes observed in the flow."),
    ("forward_packet_count", FeatureType.COUNT, "packets", "Packets in the initiating direction."),
    ("backward_packet_count", FeatureType.COUNT, "packets", "Packets in the response direction."),
    ("forward_byte_count", FeatureType.SIZE, "bytes", "Bytes in the initiating direction."),
    ("backward_byte_count", FeatureType.SIZE, "bytes", "Bytes in the response direction."),
    ("packets_per_second", FeatureType.RATE, "packets/second", "packet_count / duration (0 if 0)."),
    ("bytes_per_second", FeatureType.RATE, "bytes/second", "byte_count / duration (0 if duration is 0)."),
    ("mean_packet_size", FeatureType.SIZE, "bytes", "Mean packet size across the flow."),
    ("std_packet_size", FeatureType.SIZE, "bytes", "Std deviation of packet size."),
    ("min_packet_size", FeatureType.SIZE, "bytes", "Smallest packet observed."),
    ("max_packet_size", FeatureType.SIZE, "bytes", "Largest packet observed."),
    ("mean_inter_arrival_seconds", FeatureType.DURATION, "seconds", "Mean inter-packet time."),
    ("std_inter_arrival_seconds", FeatureType.DURATION, "seconds", "Std deviation of inter-packet time."),
    ("min_inter_arrival_seconds", FeatureType.DURATION, "seconds", "Smallest inter-packet time."),
    ("max_inter_arrival_seconds", FeatureType.DURATION, "seconds", "Largest inter-packet time."),
    ("syn_count", FeatureType.COUNT, "packets", "TCP SYN flags observed."),
    ("ack_count", FeatureType.COUNT, "packets", "TCP ACK flags observed."),
    ("fin_count", FeatureType.COUNT, "packets", "TCP FIN flags observed."),
    ("rst_count", FeatureType.COUNT, "packets", "TCP RST flags observed."),
    ("psh_count", FeatureType.COUNT, "packets", "TCP PSH flags observed."),
    ("urg_count", FeatureType.COUNT, "packets", "TCP URG flags observed."),
    ("forward_backward_byte_ratio", FeatureType.RATIO, "ratio", "forward/backward bytes (0 if 0)."),
    ("destination_port", FeatureType.PORT, "port", "Destination port, or -1 if none (e.g. ICMP)."),
    ("protocol_is_tcp", FeatureType.FLAG, "boolean", "1.0 if the flow's protocol is TCP, else 0.0."),
    ("protocol_is_udp", FeatureType.FLAG, "boolean", "1.0 if the flow's protocol is UDP, else 0.0."),
    ("protocol_is_icmp", FeatureType.FLAG, "boolean", "1.0 if the flow's protocol is ICMP, else 0.0."),
    ("protocol_is_other", FeatureType.FLAG, "boolean", "1.0 if the protocol is none of TCP/UDP/ICMP."),
)

FEATURE_DEFINITIONS: tuple[FeatureDefinition, ...] = tuple(
    FeatureDefinition(name=name, feature_type=feature_type, unit=unit, description=description)
    for name, feature_type, unit, description in _FEATURE_TABLE
)

FEATURE_NAMES: tuple[str, ...] = tuple(definition.name for definition in FEATURE_DEFINITIONS)

assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES), "duplicate feature name in schema"

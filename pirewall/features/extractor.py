"""`Flow -> FeatureVector`, deterministic and schema-driven (spec §11).

The one canonical feature-extraction layer — Phase 4's dataset adapters and
Phase 5's runtime inference both call `extract_features`, never
reimplementing this math (CLAUDE.md "one canonical feature-extraction
module").

**Versioned projection.** The primitive math below is computed once per
flow. `extract_features(flow, schema_version=...)` then projects that one
value map through the requested schema's frozen column list. Schema 2.0.0
therefore keeps producing exactly the vectors it always did (including the
raw `destination_port`), while 3.0.0 gets the coarse
`destination_port_category` instead. No second extractor exists.
"""

from pirewall.core.enums import Protocol
from pirewall.core.exceptions import FeatureExtractionError
from pirewall.core.models.feature_vector import FeatureVector
from pirewall.core.models.flow import Flow
from pirewall.features.schema import (
    SCHEMA_VERSION,
    feature_names,
    port_category,
)


def extract_features(flow: Flow, schema_version: str = SCHEMA_VERSION) -> FeatureVector:
    """Deterministically compute the `FeatureVector` for `flow` under `schema_version`.

    Pure function of `flow`'s own fields — no wall-clock or other hidden
    input, so calling this twice on an identical `Flow` always produces an
    identical `FeatureVector` (including `computed_at`, which is derived
    from `flow.last_seen` rather than `datetime.now()`).

    `schema_version` selects a frozen column projection (2.0.0 or 3.0.0);
    an unknown version is refused rather than silently mapped to the
    current one.
    """
    try:
        return _extract_features(flow, schema_version)
    except FeatureExtractionError:
        raise
    except Exception as exc:
        raise FeatureExtractionError(f"failed to extract features for flow {flow.flow_id}: {exc}") from exc


def _extract_features(flow: Flow, schema_version: str) -> FeatureVector:
    try:
        names = feature_names(schema_version)
    except KeyError as exc:
        raise FeatureExtractionError(
            f"unknown feature schema version {schema_version!r}; "
            "expected one of the frozen versions in pirewall.features.schema"
        ) from exc

    payload = flow.payload_stats
    if payload is None:
        # Never substitute zeros or IP-level sizes: that is exactly the
        # training/runtime mismatch schema 2.0.0 exists to remove.
        raise FeatureExtractionError(
            f"flow {flow.flow_id} has no payload_stats; schema {schema_version} requires them"
        )
    duration = flow.duration_seconds
    payload_total = float(payload.total_bytes)
    values_by_name: dict[str, float] = {
        "duration_seconds": duration,
        "packet_count": float(flow.packet_count),
        "forward_packet_count": float(flow.forward_packet_count),
        "backward_packet_count": float(flow.backward_packet_count),
        "payload_byte_count": payload_total,
        "forward_payload_byte_count": float(payload.forward_bytes),
        "backward_payload_byte_count": float(payload.backward_bytes),
        "packets_per_second": (flow.packet_count / duration) if duration > 0 else 0.0,
        "payload_bytes_per_second": (payload_total / duration) if duration > 0 else 0.0,
        "mean_payload_size": payload.mean_bytes,
        "std_payload_size": payload.std_bytes,
        "min_payload_size": float(payload.min_bytes),
        "max_payload_size": float(payload.max_bytes),
        "mean_inter_arrival_seconds": flow.inter_arrival_stats.mean_seconds,
        "std_inter_arrival_seconds": flow.inter_arrival_stats.std_seconds,
        "min_inter_arrival_seconds": flow.inter_arrival_stats.min_seconds,
        "max_inter_arrival_seconds": flow.inter_arrival_stats.max_seconds,
        "forward_backward_payload_ratio": (
            payload.forward_bytes / payload.backward_bytes if payload.backward_bytes > 0 else 0.0
        ),
        # Raw port: present only for the frozen 2.0.0 projection.
        "destination_port": (
            float(flow.destination_port) if flow.destination_port is not None else -1.0
        ),
        # Coarse category: present only for 3.0.0.
        "destination_port_category": float(port_category(flow.destination_port)),
        "protocol_is_tcp": 1.0 if flow.protocol is Protocol.TCP else 0.0,
        "protocol_is_udp": 1.0 if flow.protocol is Protocol.UDP else 0.0,
        "protocol_is_icmp": 1.0 if flow.protocol is Protocol.ICMP else 0.0,
        "protocol_is_other": 1.0
        if flow.protocol not in (Protocol.TCP, Protocol.UDP, Protocol.ICMP)
        else 0.0,
    }

    values = tuple(values_by_name[name] for name in names)

    return FeatureVector(
        flow_id=flow.flow_id,
        schema_version=schema_version,
        feature_names=names,
        values=values,
        computed_at=flow.last_seen,
    )

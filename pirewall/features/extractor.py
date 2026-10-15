"""`Flow -> FeatureVector`, deterministic and schema-driven (spec §11).

The one canonical feature-extraction layer — Phase 4's dataset adapters and
Phase 5's runtime inference both call `extract_features`, never
reimplementing this math (CLAUDE.md "one canonical feature-extraction
module").
"""

from pirewall.core.enums import Protocol
from pirewall.core.exceptions import FeatureExtractionError
from pirewall.core.models.feature_vector import FeatureVector
from pirewall.core.models.flow import Flow
from pirewall.features.schema import FEATURE_NAMES, SCHEMA_VERSION


def extract_features(flow: Flow) -> FeatureVector:
    """Deterministically compute the canonical `FeatureVector` for `flow`.

    Pure function of `flow`'s own fields — no wall-clock or other hidden
    input, so calling this twice on an identical `Flow` always produces an
    identical `FeatureVector` (including `computed_at`, which is derived
    from `flow.last_seen` rather than `datetime.now()`).
    """
    try:
        return _extract_features(flow)
    except FeatureExtractionError:
        raise
    except Exception as exc:
        raise FeatureExtractionError(f"failed to extract features for flow {flow.flow_id}: {exc}") from exc


def _extract_features(flow: Flow) -> FeatureVector:
    payload = flow.payload_stats
    if payload is None:
        # Never substitute zeros or IP-level sizes: that is exactly the
        # training/runtime mismatch schema 2.0.0 exists to remove.
        raise FeatureExtractionError(
            f"flow {flow.flow_id} has no payload_stats; schema {SCHEMA_VERSION} requires them"
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
        "destination_port": (
            float(flow.destination_port) if flow.destination_port is not None else -1.0
        ),
        "protocol_is_tcp": 1.0 if flow.protocol is Protocol.TCP else 0.0,
        "protocol_is_udp": 1.0 if flow.protocol is Protocol.UDP else 0.0,
        "protocol_is_icmp": 1.0 if flow.protocol is Protocol.ICMP else 0.0,
        "protocol_is_other": 1.0
        if flow.protocol not in (Protocol.TCP, Protocol.UDP, Protocol.ICMP)
        else 0.0,
    }

    values = tuple(values_by_name[name] for name in FEATURE_NAMES)

    return FeatureVector(
        flow_id=flow.flow_id,
        schema_version=SCHEMA_VERSION,
        feature_names=FEATURE_NAMES,
        values=values,
        computed_at=flow.last_seen,
    )

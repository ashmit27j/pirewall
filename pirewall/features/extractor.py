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
    duration = flow.duration_seconds
    values_by_name: dict[str, float] = {
        "duration_seconds": duration,
        "packet_count": float(flow.packet_count),
        "byte_count": float(flow.byte_count),
        "forward_packet_count": float(flow.forward_packet_count),
        "backward_packet_count": float(flow.backward_packet_count),
        "forward_byte_count": float(flow.forward_byte_count),
        "backward_byte_count": float(flow.backward_byte_count),
        "packets_per_second": (flow.packet_count / duration) if duration > 0 else 0.0,
        "bytes_per_second": (flow.byte_count / duration) if duration > 0 else 0.0,
        "mean_packet_size": flow.packet_size_stats.mean_bytes,
        "std_packet_size": flow.packet_size_stats.std_bytes,
        "min_packet_size": float(flow.packet_size_stats.min_bytes),
        "max_packet_size": float(flow.packet_size_stats.max_bytes),
        "mean_inter_arrival_seconds": flow.inter_arrival_stats.mean_seconds,
        "std_inter_arrival_seconds": flow.inter_arrival_stats.std_seconds,
        "min_inter_arrival_seconds": flow.inter_arrival_stats.min_seconds,
        "max_inter_arrival_seconds": flow.inter_arrival_stats.max_seconds,
        "syn_count": float(flow.tcp_flags.syn),
        "ack_count": float(flow.tcp_flags.ack),
        "fin_count": float(flow.tcp_flags.fin),
        "rst_count": float(flow.tcp_flags.rst),
        "psh_count": float(flow.tcp_flags.psh),
        "urg_count": float(flow.tcp_flags.urg),
        "forward_backward_byte_ratio": (
            flow.forward_byte_count / flow.backward_byte_count
            if flow.backward_byte_count > 0
            else 0.0
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

"""`extract_features`: determinism and correctness against a known `Flow` (spec §11)."""

import pytest

from pirewall.core.enums import Protocol
from pirewall.core.exceptions import FeatureExtractionError
from pirewall.features.extractor import extract_features
from pirewall.features.schema import FEATURE_NAMES, SCHEMA_VERSION
from tests.helpers.flows import make_flow


def test_extraction_is_deterministic() -> None:
    flow = make_flow()
    first = extract_features(flow)
    second = extract_features(flow)
    assert first == second


def test_feature_vector_carries_current_schema_version() -> None:
    flow = make_flow()
    vector = extract_features(flow)
    assert vector.schema_version == SCHEMA_VERSION
    assert vector.feature_names == FEATURE_NAMES


def test_feature_values_match_flow_fields() -> None:
    flow = make_flow(
        packet_count=10,
        byte_count=1000,
        forward_packet_count=6,
        backward_packet_count=4,
        forward_byte_count=600,
        backward_byte_count=400,
        duration_seconds=10.0,
        payload_stats={
            "forward_bytes": 360,
            "backward_bytes": 240,
            "min_bytes": 0,
            "max_bytes": 200,
            "mean_bytes": 60.0,
            "std_bytes": 70.0,
        },
    )
    vector = extract_features(flow)
    values = dict(zip(vector.feature_names, vector.values, strict=True))

    assert values["duration_seconds"] == 10.0
    assert values["packet_count"] == 10.0
    assert values["payload_byte_count"] == 600.0
    assert values["forward_payload_byte_count"] == 360.0
    assert values["backward_payload_byte_count"] == 240.0
    assert values["forward_packet_count"] == 6.0
    assert values["backward_packet_count"] == 4.0
    assert values["packets_per_second"] == 1.0
    assert values["payload_bytes_per_second"] == 60.0
    assert values["forward_backward_payload_ratio"] == 1.5
    assert values["min_payload_size"] == 0.0
    assert values["std_payload_size"] == 70.0
    assert values["destination_port"] == 443.0
    assert values["protocol_is_tcp"] == 1.0
    assert values["protocol_is_udp"] == 0.0


def test_zero_duration_flow_does_not_divide_by_zero() -> None:
    flow = make_flow(duration_seconds=0.0)
    vector = extract_features(flow)
    values = dict(zip(vector.feature_names, vector.values, strict=True))
    assert values["packets_per_second"] == 0.0
    assert values["payload_bytes_per_second"] == 0.0


def test_zero_backward_bytes_does_not_divide_by_zero() -> None:
    flow = make_flow(
        backward_byte_count=0, forward_byte_count=500, byte_count=500, backward_packet_count=4
    )
    vector = extract_features(flow)
    values = dict(zip(vector.feature_names, vector.values, strict=True))
    assert values["forward_backward_payload_ratio"] == 0.0


def test_icmp_flow_reports_no_destination_port_as_negative_one() -> None:
    flow = make_flow(protocol=Protocol.ICMP, source_port=None, destination_port=None)
    vector = extract_features(flow)
    values = dict(zip(vector.feature_names, vector.values, strict=True))
    assert values["destination_port"] == -1.0
    assert values["protocol_is_icmp"] == 1.0
    assert values["protocol_is_tcp"] == 0.0


def test_computed_at_derives_from_flow_last_seen_not_wall_clock() -> None:
    flow = make_flow()
    vector = extract_features(flow)
    assert vector.computed_at == flow.last_seen


def test_flow_without_payload_stats_is_refused_rather_than_zero_filled() -> None:
    """Schema 2.0.0 never falls back to IP-level sizes or zeros (the 1.0.0 skew)."""
    flow = make_flow().model_copy(update={"payload_stats": None})
    with pytest.raises(FeatureExtractionError, match="payload_stats"):
        extract_features(flow)


def test_ip_level_sizes_do_not_leak_into_features() -> None:
    """Changing only IP-level byte counts must not move any feature value."""
    payload = {
        "forward_bytes": 100,
        "backward_bytes": 50,
        "min_bytes": 0,
        "max_bytes": 100,
        "mean_bytes": 15.0,
        "std_bytes": 30.0,
    }
    small = make_flow(
        byte_count=1000, forward_byte_count=600, backward_byte_count=400, payload_stats=payload
    )
    large = make_flow(
        byte_count=3000, forward_byte_count=2000, backward_byte_count=1000, payload_stats=payload
    )
    assert extract_features(small).values == extract_features(large).values

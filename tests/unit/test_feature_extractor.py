"""`extract_features`: determinism and correctness against a known `Flow` (spec §11)."""

from pirewall.core.enums import Protocol
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
    )
    vector = extract_features(flow)
    values = dict(zip(vector.feature_names, vector.values, strict=True))

    assert values["duration_seconds"] == 10.0
    assert values["packet_count"] == 10.0
    assert values["byte_count"] == 1000.0
    assert values["forward_packet_count"] == 6.0
    assert values["backward_packet_count"] == 4.0
    assert values["packets_per_second"] == 1.0
    assert values["bytes_per_second"] == 100.0
    assert values["forward_backward_byte_ratio"] == 1.5
    assert values["destination_port"] == 443.0
    assert values["protocol_is_tcp"] == 1.0
    assert values["protocol_is_udp"] == 0.0


def test_zero_duration_flow_does_not_divide_by_zero() -> None:
    flow = make_flow(duration_seconds=0.0)
    vector = extract_features(flow)
    values = dict(zip(vector.feature_names, vector.values, strict=True))
    assert values["packets_per_second"] == 0.0
    assert values["bytes_per_second"] == 0.0


def test_zero_backward_bytes_does_not_divide_by_zero() -> None:
    flow = make_flow(backward_byte_count=0, forward_byte_count=500, byte_count=500)
    vector = extract_features(flow)
    values = dict(zip(vector.feature_names, vector.values, strict=True))
    assert values["forward_backward_byte_ratio"] == 0.0


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

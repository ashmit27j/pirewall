"""`Flow` domain model: valid construction and validation failures."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from pirewall.core.enums import Protocol
from pirewall.core.models.common import InterArrivalStats, PacketSizeStats
from pirewall.core.models.flow import Flow

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _make_flow(**overrides: object) -> Flow:
    defaults: dict[str, object] = {
        "flow_id": "flow-1",
        "source_ip": "10.0.0.5",
        "destination_ip": "93.184.216.34",
        "source_port": 51234,
        "destination_port": 443,
        "protocol": Protocol.TCP,
        "first_seen": NOW,
        "last_seen": NOW,
        "packet_count": 10,
        "byte_count": 1000,
        "forward_packet_count": 6,
        "backward_packet_count": 4,
        "forward_byte_count": 600,
        "backward_byte_count": 400,
        "packet_size_stats": PacketSizeStats(
            min_bytes=40, max_bytes=1500, mean_bytes=100.0, std_bytes=10.0
        ),
        "inter_arrival_stats": InterArrivalStats(
            min_seconds=0.001, max_seconds=1.0, mean_seconds=0.1, std_seconds=0.05
        ),
    }
    defaults.update(overrides)
    return Flow.model_validate(defaults)


def test_valid_flow_constructs() -> None:
    flow = _make_flow()
    assert flow.duration_seconds == 0.0
    assert flow.protocol is Protocol.TCP


def test_invalid_source_ip_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_flow(source_ip="not-an-ip")


def test_ipv6_source_ip_rejected() -> None:
    """IPv4-only for v1 (ADDENDUM.md A5) — Flow cannot hold an IPv6 address."""
    with pytest.raises(ValidationError):
        _make_flow(source_ip="2001:db8::1")


def test_out_of_range_port_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_flow(source_port=70000)


def test_negative_packet_count_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_flow(packet_count=-1)


def test_forward_backward_must_sum_to_total() -> None:
    with pytest.raises(ValidationError):
        _make_flow(forward_packet_count=1, backward_packet_count=1, packet_count=10)


def test_last_seen_before_first_seen_rejected() -> None:
    earlier = datetime(2025, 1, 1, tzinfo=UTC)
    with pytest.raises(ValidationError):
        _make_flow(first_seen=NOW, last_seen=earlier)


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_flow(first_seen=datetime(2026, 1, 1), last_seen=datetime(2026, 1, 1))

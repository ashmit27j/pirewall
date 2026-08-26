"""`pirewall.detection.behavior`: deterministic pattern detection over bounded state (spec §17)."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from pirewall.config.models import DetectionConfig
from pirewall.core.enums import BehaviorPatternType
from pirewall.detection.behavior import BehaviorAnalyzer
from tests.helpers.flows import make_flow

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _config(**overrides: object) -> DetectionConfig:
    return DetectionConfig.model_validate(overrides)


def test_no_patterns_for_a_single_ordinary_connection() -> None:
    analyzer = BehaviorAnalyzer(_config())
    analyzer.observe_flow(make_flow(source_ip="10.0.0.5", first_seen=T0))

    assessment = analyzer.assess(IPv4Address("10.0.0.5"))

    assert assessment is not None
    assert assessment.detected_patterns == ()
    assert assessment.confidence == 0.0


def test_port_scan_pattern_flags_scanning_and_destination_diversity() -> None:
    config = _config(scanning_port_threshold=5, destination_diversity_threshold=5)
    analyzer = BehaviorAnalyzer(config)

    for i in range(10):
        analyzer.observe_flow(
            make_flow(
                source_ip="203.0.113.5",
                destination_ip="10.0.0.20",
                destination_port=1000 + i,
                first_seen=T0 + timedelta(seconds=i),
                packet_count=2,
                byte_count=100,
                forward_packet_count=2,
                backward_packet_count=0,
                forward_byte_count=100,
                backward_byte_count=0,
                duration_seconds=0.01,
            )
        )

    assessment = analyzer.assess(IPv4Address("203.0.113.5"))

    assert assessment is not None
    assert BehaviorPatternType.SCANNING in assessment.detected_patterns


def test_syn_flood_like_pattern_flags_high_frequency_and_burst() -> None:
    config = _config(
        high_frequency_per_second_threshold=1.0,
        burst_window_seconds=2.0,
        burst_count_threshold=5,
    )
    analyzer = BehaviorAnalyzer(config)

    for i in range(20):
        analyzer.observe_flow(
            make_flow(
                source_ip="203.0.113.9",
                destination_ip="10.0.0.30",
                destination_port=80,
                first_seen=T0 + timedelta(milliseconds=50 * i),
                packet_count=1,
                byte_count=60,
                forward_packet_count=1,
                backward_packet_count=0,
                forward_byte_count=60,
                backward_byte_count=0,
                duration_seconds=0.0,
            )
        )

    assessment = analyzer.assess(IPv4Address("203.0.113.9"))

    assert assessment is not None
    assert BehaviorPatternType.HIGH_FREQUENCY in assessment.detected_patterns
    assert BehaviorPatternType.BURST in assessment.detected_patterns


def test_repeated_ssh_connections_flags_repeated_connections_and_failures() -> None:
    config = _config(repeated_connections_threshold=5, repeated_failures_threshold=5)
    analyzer = BehaviorAnalyzer(config)

    for i in range(10):
        analyzer.observe_flow(
            make_flow(
                source_ip="203.0.113.7",
                destination_ip="10.0.0.40",
                destination_port=22,
                first_seen=T0 + timedelta(seconds=i * 2),
                packet_count=2,
                byte_count=80,
                forward_packet_count=2,
                backward_packet_count=0,
                forward_byte_count=80,
                backward_byte_count=0,
                duration_seconds=0.1,
            )
        )

    assessment = analyzer.assess(IPv4Address("203.0.113.7"))

    assert assessment is not None
    assert BehaviorPatternType.REPEATED_CONNECTIONS in assessment.detected_patterns
    assert BehaviorPatternType.REPEATED_FAILURES in assessment.detected_patterns


def test_assess_unknown_source_returns_none() -> None:
    analyzer = BehaviorAnalyzer(_config())
    assert analyzer.assess(IPv4Address("192.0.2.1")) is None


def test_behavior_state_is_bounded_under_a_flood_of_distinct_sources() -> None:
    config = _config(max_tracked_sources=50)
    analyzer = BehaviorAnalyzer(config)

    for i in range(5000):
        analyzer.observe_flow(
            make_flow(
                source_ip=f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}",
                first_seen=T0,
            )
        )
        assert len(analyzer) <= 50

    assert len(analyzer) == 50

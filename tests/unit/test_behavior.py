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


def test_scanning_detected_from_new_connections_before_any_completion() -> None:
    """ADDENDUM_2.md B1: the volumetric signal must not need a single completed flow."""
    config = _config(scanning_port_threshold=5, destination_diversity_threshold=100)
    analyzer = BehaviorAnalyzer(config)

    for port in range(1000, 1010):
        analyzer.observe_new_connection(
            IPv4Address("203.0.113.5"), IPv4Address("10.0.0.20"), port, T0
        )

    assessment = analyzer.assess(IPv4Address("203.0.113.5"))

    assert assessment is not None
    assert BehaviorPatternType.SCANNING in assessment.detected_patterns


def test_single_new_connection_triggers_nothing() -> None:
    """The pattern threshold, not a single observation, is what may act (ADDENDUM_2.md B1/B3)."""
    config = _config(scanning_port_threshold=5)
    analyzer = BehaviorAnalyzer(config)

    analyzer.observe_new_connection(IPv4Address("203.0.113.6"), IPv4Address("10.0.0.21"), 22, T0)

    assessment = analyzer.assess(IPv4Address("203.0.113.6"))

    assert assessment is not None
    assert assessment.detected_patterns == ()


def test_observe_completion_before_any_new_connection_falls_back_to_full_observe() -> None:
    """A flow whose creation-time signal never arrived (dropped/evicted) must not lose its evidence."""
    analyzer = BehaviorAnalyzer(_config())
    assert len(analyzer) == 0

    analyzer.observe_completion(make_flow(source_ip="203.0.113.8", first_seen=T0))

    assert len(analyzer) == 1
    assessment = analyzer.assess(IPv4Address("203.0.113.8"))
    assert assessment is not None


def test_observe_completion_does_not_double_count_a_connection_already_observed() -> None:
    """The same flow's creation and completion signals must count as exactly one connection."""
    config = _config(repeated_connections_threshold=2)
    analyzer = BehaviorAnalyzer(config)

    analyzer.observe_new_connection(
        IPv4Address("203.0.113.9"), IPv4Address("10.0.0.22"), 443, T0
    )
    analyzer.observe_completion(
        make_flow(
            source_ip="203.0.113.9",
            destination_ip="10.0.0.22",
            destination_port=443,
            first_seen=T0,
            backward_packet_count=4,
        )
    )

    assessment = analyzer.assess(IPv4Address("203.0.113.9"))
    assert assessment is not None
    assert BehaviorPatternType.REPEATED_CONNECTIONS not in assessment.detected_patterns


def test_slow_rate_dos_detected_from_concurrent_slow_connection_count() -> None:
    """ADDENDUM_2.md B2: many concurrent slow connections to one destination fires the pattern."""
    config = _config(concurrent_slow_connections_threshold=8)
    analyzer = BehaviorAnalyzer(config)

    analyzer.note_slow_connections(
        IPv4Address("203.0.113.70"), IPv4Address("10.0.0.50"), 8, T0
    )

    assessment = analyzer.assess(IPv4Address("203.0.113.70"))
    assert assessment is not None
    assert BehaviorPatternType.SLOW_RATE_DOS in assessment.detected_patterns


def test_single_slow_connection_does_not_trigger_slow_rate_dos() -> None:
    """Regression for the DHCP/Slowhttptest false positive (ADDENDUM_2.md, top of file):

    one ordinary slow connection (one IoT-device-style flow) must never be
    mistaken for a slow-rate DoS pattern on its own.
    """
    config = _config(concurrent_slow_connections_threshold=8)
    analyzer = BehaviorAnalyzer(config)

    analyzer.note_slow_connections(
        IPv4Address("203.0.113.71"), IPv4Address("10.0.0.51"), 1, T0
    )

    assessment = analyzer.assess(IPv4Address("203.0.113.71"))
    assert assessment is not None
    assert BehaviorPatternType.SLOW_RATE_DOS not in assessment.detected_patterns


def test_slow_connection_count_is_a_live_snapshot_not_an_accumulator() -> None:
    """A later, lower count must be able to clear the pattern — it isn't a monotonic counter."""
    config = _config(concurrent_slow_connections_threshold=8)
    analyzer = BehaviorAnalyzer(config)

    analyzer.note_slow_connections(IPv4Address("203.0.113.72"), IPv4Address("10.0.0.52"), 10, T0)
    analyzer.note_slow_connections(
        IPv4Address("203.0.113.72"), IPv4Address("10.0.0.52"), 2, T0 + timedelta(seconds=30)
    )

    assessment = analyzer.assess(IPv4Address("203.0.113.72"))
    assert assessment is not None
    assert BehaviorPatternType.SLOW_RATE_DOS not in assessment.detected_patterns


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

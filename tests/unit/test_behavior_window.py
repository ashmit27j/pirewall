"""Time-windowed behavior state (`behavior_window_seconds`, docs/KNOWN_ISSUES.md #3).

Before this, `behavior_window_seconds` was read by nothing and every
per-source counter was lifetime state, so a device that browsed for long
enough accumulated its way past thresholds meant for a short burst and
stayed flagged forever.
"""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from pirewall.config.models import DetectionConfig
from pirewall.core.enums import BehaviorPatternType
from pirewall.core.models.flow import Flow
from pirewall.detection.behavior import BehaviorAnalyzer
from tests.helpers.flows import make_flow

T0 = datetime(2026, 1, 1, tzinfo=UTC)
SOURCE = IPv4Address("192.168.100.50")


def _config(**overrides: object) -> DetectionConfig:
    return DetectionConfig.model_validate(overrides)


def _patterns(analyzer: BehaviorAnalyzer) -> tuple[BehaviorPatternType, ...]:
    assessment = analyzer.assess(SOURCE)
    assert assessment is not None
    return assessment.detected_patterns


def _connect(analyzer: BehaviorAnalyzer, destination: str, port: int, at: datetime) -> None:
    analyzer.observe_new_connection(SOURCE, IPv4Address(destination), port, at)


def _unanswered_syn(destination: str, port: int, at: datetime) -> Flow:
    return make_flow(
        source_ip=str(SOURCE),
        destination_ip=destination,
        destination_port=port,
        first_seen=at,
        duration_seconds=1.0,
        packet_count=2,
        forward_packet_count=2,
        backward_packet_count=0,
        byte_count=80,
        forward_byte_count=80,
        backward_byte_count=0,
        tcp_flags={"syn": 2},
    )


def test_destination_diversity_decays_once_the_window_passes() -> None:
    analyzer = BehaviorAnalyzer(_config(behavior_window_seconds=60, destination_diversity_threshold=5))
    for i in range(6):
        _connect(analyzer, f"203.0.113.{i + 1}", 443, T0 + timedelta(seconds=i))
    assert BehaviorPatternType.DESTINATION_DIVERSITY in _patterns(analyzer)

    # Two minutes later the same device reaches one more host: the earlier
    # six are outside the window and must no longer count.
    _connect(analyzer, "203.0.113.99", 443, T0 + timedelta(seconds=120))
    assert BehaviorPatternType.DESTINATION_DIVERSITY not in _patterns(analyzer)


def test_long_lived_browsing_never_accumulates_past_a_burst_threshold() -> None:
    """The KNOWN_ISSUES #3 failure mode: a slow trickle over an hour, never bursty."""
    analyzer = BehaviorAnalyzer(_config(behavior_window_seconds=300, destination_diversity_threshold=15))
    for i in range(120):  # one new host every 30 s for an hour
        _connect(analyzer, f"198.51.100.{i % 250 + 1}", 443, T0 + timedelta(seconds=30 * i))
    assert BehaviorPatternType.DESTINATION_DIVERSITY not in _patterns(analyzer)


def test_repeated_failures_requires_concentration_on_one_destination() -> None:
    config = _config(behavior_window_seconds=300, repeated_failures_threshold=5)

    spread = BehaviorAnalyzer(config)
    for i in range(12):  # e.g. a device whose traffic is dropped before portal sign-in
        flow = _unanswered_syn(f"203.0.113.{i + 1}", 443, T0 + timedelta(seconds=i))
        spread.observe_flow(flow)
    assert BehaviorPatternType.REPEATED_FAILURES not in _patterns(spread)

    concentrated = BehaviorAnalyzer(config)
    for i in range(6):  # a SYN flood / filtered-port scan against one target
        flow = _unanswered_syn("192.168.100.1", 1000 + i, T0 + timedelta(seconds=i))
        concentrated.observe_flow(flow)
    assessment = concentrated.assess(SOURCE)
    assert assessment is not None
    assert BehaviorPatternType.REPEATED_FAILURES in assessment.detected_patterns


def test_failures_expire_with_the_window() -> None:
    analyzer = BehaviorAnalyzer(_config(behavior_window_seconds=60, repeated_failures_threshold=3))
    for i in range(3):
        analyzer.observe_flow(_unanswered_syn("192.168.100.1", 22, T0 + timedelta(seconds=i)))
    assert BehaviorPatternType.REPEATED_FAILURES in _patterns(analyzer)

    assessment = analyzer.assess_at(SOURCE, T0 + timedelta(seconds=200))
    assert assessment is not None
    assert BehaviorPatternType.REPEATED_FAILURES not in assessment.detected_patterns


def test_a_dissolved_slow_connection_cluster_stops_counting() -> None:
    config = _config(behavior_window_seconds=60, concurrent_slow_connections_threshold=8)
    analyzer = BehaviorAnalyzer(config)
    analyzer.note_slow_connections(SOURCE, IPv4Address("192.168.100.1"), 20, T0)
    assert BehaviorPatternType.SLOW_RATE_DOS in _patterns(analyzer)

    assessment = analyzer.assess_at(SOURCE, T0 + timedelta(seconds=120))
    assert assessment is not None
    assert BehaviorPatternType.SLOW_RATE_DOS not in assessment.detected_patterns


def test_persistence_measures_an_uninterrupted_streak_not_lifetime() -> None:
    config = _config(behavior_window_seconds=60, persistence_seconds_threshold=600)
    analyzer = BehaviorAnalyzer(config)
    _connect(analyzer, "203.0.113.1", 443, T0)
    _connect(analyzer, "203.0.113.1", 443, T0 + timedelta(seconds=30))
    # Silent for an hour, then back: a new streak, not "active for an hour".
    _connect(analyzer, "203.0.113.1", 443, T0 + timedelta(hours=1))
    _connect(analyzer, "203.0.113.1", 443, T0 + timedelta(hours=1, seconds=30))
    assert BehaviorPatternType.PERSISTENCE not in _patterns(analyzer)

    for i in range(1, 25):  # then every 30 s for 12 minutes, never a gap > window
        _connect(analyzer, "203.0.113.1", 443, T0 + timedelta(hours=1, seconds=30 + 30 * i))
    assert BehaviorPatternType.PERSISTENCE in _patterns(analyzer)


def test_window_state_stays_bounded_under_a_flood() -> None:
    config = _config(behavior_window_seconds=300, max_tracked_connections_per_source=100)
    analyzer = BehaviorAnalyzer(config)
    for i in range(10_000):
        _connect(analyzer, f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}", 80, T0)
    assessment = analyzer.assess(SOURCE)
    assert assessment is not None
    # The analyzer's own LRU/window bookkeeping keeps internal counters exact:
    # every expired event decremented exactly what it incremented.
    state = analyzer._sources[SOURCE]  # pyright: ignore[reportPrivateUsage]
    assert state.connection_count == 100
    assert sum(state.destination_counts.values()) <= 100


def test_flood_fires_on_connection_rate_to_one_destination_not_on_busy_browsing() -> None:
    config = _config(burst_window_seconds=5.0, flood_connections_per_second_threshold=100.0)
    flooder = BehaviorAnalyzer(config)
    for i in range(600):  # 600 connections to one host in ~3 s: a SYN/UDP flood's shape
        at = T0 + timedelta(milliseconds=5 * i)
        flooder.observe_new_connection(SOURCE, IPv4Address("192.168.100.1"), 80, at)
    flooded = flooder.assess(SOURCE)
    assert flooded is not None and BehaviorPatternType.FLOOD in flooded.detected_patterns

    browser = BehaviorAnalyzer(config)
    for i in range(600):  # the same rate spread over 120 different hosts
        _connect(browser, f"203.0.113.{i % 120 + 1}", 443, T0 + timedelta(milliseconds=5 * i))
    browsing = browser.assess(SOURCE)
    assert browsing is not None and BehaviorPatternType.FLOOD not in browsing.detected_patterns


def test_a_responders_flow_never_seeds_behavior_state() -> None:
    """A lone RST (or a SYN-ACK whose SYN was missed) is not a connection its sender made.

    Counting it as one rate-limited a flood's own victim for "scanning" its attacker.
    """
    analyzer = BehaviorAnalyzer(_config())
    responder_flow = make_flow(
        source_ip=str(SOURCE), tcp_flags={"rst": 1}, packet_count=1, forward_packet_count=1,
        backward_packet_count=0, byte_count=40, forward_byte_count=40, backward_byte_count=0,
    ).model_copy(update={"opened_by_initiation": False})
    analyzer.observe_completion(responder_flow)
    assert analyzer.assess(SOURCE) is None

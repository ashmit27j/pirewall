"""`pirewall.runtime.metrics` — the live half of the Netdata deliverable (spec §33, ADDENDUM.md A3).

`pirewall.integration.netdata` could always *shape* a snapshot; nothing
could *produce* one, because no running loop existed to poll capture
statistics, the flow table, and the rate limiter. These tests cover the
producer, particularly the rate arithmetic, which is where a plausible-
looking but wrong number would be easiest to ship.
"""

from datetime import UTC, datetime, timedelta

from pirewall.core.models.capture_stats import CaptureStatistics
from pirewall.runtime.metrics import MetricsCollector, RuntimeCounters

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _stats(packets_seen: int, dropped: int = 0) -> CaptureStatistics:
    return CaptureStatistics(interface="eth1", packets_seen=packets_seen, packets_dropped=dropped)


def _collect(
    collector: MetricsCollector, at: datetime, stats: CaptureStatistics
) -> "object":
    return collector.collect(
        at,
        stats,
        active_flows=3,
        rule_count=2,
        adaptive_rules_in_window=5,
        capture_health=True,
        firewall_health=True,
        api_health=True,
    )


def test_counters_are_monotonic_and_snapshot_is_a_copy() -> None:
    counters = RuntimeCounters()
    counters.add(flows_completed=2, detections=1)
    snapshot = counters.snapshot()
    counters.add(flows_completed=5)

    assert snapshot.flows_completed == 2  # the copy did not move
    assert counters.flows_completed == 7


def test_first_collection_reports_zero_rates_rather_than_inventing_them() -> None:
    """No previous reading to difference against — a fabricated rate would be worse than 0."""
    collector = MetricsCollector(RuntimeCounters(), max_adaptive_rules_per_window=20)

    snapshot = collector.collect(
        NOW,
        _stats(1000),
        active_flows=0,
        rule_count=0,
        adaptive_rules_in_window=0,
        capture_health=True,
        firewall_health=True,
        api_health=True,
    )

    assert snapshot.packet_rate_per_second == 0.0
    assert snapshot.flow_creation_rate_per_second == 0.0


def test_rates_are_derived_by_differencing_successive_readings() -> None:
    counters = RuntimeCounters()
    collector = MetricsCollector(counters, max_adaptive_rules_per_window=20)
    _collect(collector, NOW, _stats(100))

    counters.add(flows_completed=40, flows_expired=20)
    snapshot = collector.collect(
        NOW + timedelta(seconds=10),
        _stats(1100),
        active_flows=3,
        rule_count=2,
        adaptive_rules_in_window=5,
        capture_health=True,
        firewall_health=True,
        api_health=True,
    )

    assert snapshot.packet_rate_per_second == 100.0  # 1000 packets / 10 s
    assert snapshot.flow_creation_rate_per_second == 4.0
    assert snapshot.flow_expiration_rate_per_second == 2.0


def test_inference_latency_is_the_mean_over_all_inferences() -> None:
    counters = RuntimeCounters()
    counters.add(inferences=4, inference_seconds_total=0.080)
    collector = MetricsCollector(counters, max_adaptive_rules_per_window=20)

    snapshot = collector.collect(
        NOW,
        _stats(0),
        active_flows=0,
        rule_count=0,
        adaptive_rules_in_window=0,
        capture_health=True,
        firewall_health=True,
        api_health=True,
    )

    assert snapshot.inference_count == 4
    assert snapshot.inference_latency_ms == 20.0


def test_budget_fraction_tracks_the_a3_rate_cap() -> None:
    """A3's metric is meaningless without current usage against the cap."""
    collector = MetricsCollector(RuntimeCounters(), max_adaptive_rules_per_window=20)

    snapshot = collector.collect(
        NOW,
        _stats(0),
        active_flows=0,
        rule_count=0,
        adaptive_rules_in_window=15,
        capture_health=True,
        firewall_health=True,
        api_health=True,
    )

    assert snapshot.adaptive_rule_creation_rate_per_window == 15
    assert snapshot.adaptive_rule_budget_fraction == 0.75


def test_budget_fraction_is_clamped_so_the_model_never_rejects_a_snapshot() -> None:
    """`adaptive_rule_budget_fraction` is `le=1.0`; an over-budget window must not raise."""
    collector = MetricsCollector(RuntimeCounters(), max_adaptive_rules_per_window=10)

    snapshot = collector.collect(
        NOW,
        _stats(0),
        active_flows=0,
        rule_count=0,
        adaptive_rules_in_window=25,
        capture_health=True,
        firewall_health=True,
        api_health=True,
    )

    assert snapshot.adaptive_rule_budget_fraction == 1.0


def test_health_flags_are_passed_through_verbatim() -> None:
    collector = MetricsCollector(RuntimeCounters(), max_adaptive_rules_per_window=20)

    snapshot = collector.collect(
        NOW,
        _stats(0, dropped=7),
        active_flows=0,
        rule_count=0,
        adaptive_rules_in_window=0,
        capture_health=False,
        firewall_health=False,
        api_health=True,
    )

    assert snapshot.capture_health is False
    assert snapshot.firewall_health is False
    assert snapshot.api_health is True
    assert snapshot.packet_drops == 7

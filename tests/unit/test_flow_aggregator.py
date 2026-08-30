"""`FlowAggregator`: end-to-end packet -> Flow behavior (spec §8, ADDENDUM.md A5)."""

from datetime import UTC, datetime, timedelta

from pirewall.config.models import FlowConfig
from pirewall.core.enums import AddressFamily, Protocol
from pirewall.core.models.common import TcpFlags
from pirewall.core.models.flow import Flow
from pirewall.flow.aggregator import FlowAggregator, NewFlowSignal, NewFlowSink
from tests.helpers.flows import make_packet

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _aggregator(on_new_flow: NewFlowSink | None = None, **overrides: object) -> FlowAggregator:
    defaults: dict[str, object] = {
        "active_timeout_seconds": 1800,
        "inactive_timeout_seconds": 60,
        "max_flows": 100_000,
        "cleanup_interval_seconds": 30,
    }
    defaults.update(overrides)
    return FlowAggregator(FlowConfig.model_validate(defaults), on_new_flow=on_new_flow)


def test_syn_then_ack_stays_open_until_completion() -> None:
    aggregator = _aggregator()
    syn = make_packet(timestamp=T0, tcp_flags=TcpFlags(syn=True))
    emitted = aggregator.process_packet(syn)
    assert emitted == []
    assert len(aggregator) == 1


def test_fin_both_directions_emits_completed_flow() -> None:
    aggregator = _aggregator()
    aggregator.process_packet(make_packet(timestamp=T0, tcp_flags=TcpFlags(syn=True)))
    aggregator.process_packet(
        make_packet(
            source_ip="10.0.0.10",
            destination_ip="10.0.0.5",
            source_port=443,
            destination_port=51234,
            timestamp=T0 + timedelta(milliseconds=1),
            tcp_flags=TcpFlags(syn=True, ack=True),
        )
    )
    aggregator.process_packet(
        make_packet(timestamp=T0 + timedelta(seconds=1), tcp_flags=TcpFlags(fin=True, ack=True))
    )
    emitted = aggregator.process_packet(
        make_packet(
            source_ip="10.0.0.10",
            destination_ip="10.0.0.5",
            source_port=443,
            destination_port=51234,
            timestamp=T0 + timedelta(seconds=1, milliseconds=5),
            tcp_flags=TcpFlags(fin=True, ack=True),
        )
    )

    assert len(emitted) == 1
    flow = emitted[0]
    assert flow.packet_count == 4
    assert len(aggregator) == 0


def test_ipv6_packets_are_never_aggregated() -> None:
    aggregator = _aggregator()
    ipv6_packet = make_packet(
        address_family=AddressFamily.IPV6,
        source_ip="::1",
        destination_ip="::2",
    )
    emitted = aggregator.process_packet(ipv6_packet)
    assert emitted == []
    assert len(aggregator) == 0


def test_sweep_timeouts_closes_idle_flows() -> None:
    aggregator = _aggregator(active_timeout_seconds=3600, inactive_timeout_seconds=10)
    aggregator.process_packet(make_packet(timestamp=T0, tcp_flags=TcpFlags(syn=True)))
    assert len(aggregator) == 1

    emitted = aggregator.sweep_timeouts(T0 + timedelta(seconds=11))
    assert len(emitted) == 1
    assert len(aggregator) == 0


def test_sweep_timeouts_leaves_active_flows_open() -> None:
    aggregator = _aggregator(active_timeout_seconds=3600, inactive_timeout_seconds=10)
    aggregator.process_packet(make_packet(timestamp=T0, tcp_flags=TcpFlags(syn=True)))

    emitted = aggregator.sweep_timeouts(T0 + timedelta(seconds=5))
    assert emitted == []
    assert len(aggregator) == 1


def test_flush_finalizes_all_open_flows_regardless_of_timeout() -> None:
    aggregator = _aggregator(active_timeout_seconds=3600, inactive_timeout_seconds=3600)
    for port in range(50000, 50005):
        aggregator.process_packet(
            make_packet(source_port=port, timestamp=T0, tcp_flags=TcpFlags(syn=True))
        )
    assert len(aggregator) == 5

    emitted = aggregator.flush()
    assert len(emitted) == 5
    assert len(aggregator) == 0


def test_eviction_under_flood_emits_evicted_flow_and_stays_bounded() -> None:
    aggregator = _aggregator(max_flows=10, active_timeout_seconds=3600, inactive_timeout_seconds=3600)
    all_emitted: list[Flow] = []
    for port in range(50000, 51000):
        emitted = aggregator.process_packet(
            make_packet(source_port=port, timestamp=T0, tcp_flags=TcpFlags(syn=True))
        )
        all_emitted.extend(emitted)
        assert len(aggregator) <= 10

    assert len(aggregator) == 10
    assert len(all_emitted) == 990  # every flow beyond the first 10 caused one eviction


def test_on_new_flow_fires_once_per_new_flow_not_per_packet() -> None:
    """ADDENDUM_2.md B1: the creation-time hook must fire exactly once per flow."""
    signals: list[NewFlowSignal] = []
    aggregator = _aggregator(on_new_flow=signals.append)

    aggregator.process_packet(make_packet(timestamp=T0, tcp_flags=TcpFlags(syn=True)))
    aggregator.process_packet(
        make_packet(
            source_ip="10.0.0.10",
            destination_ip="10.0.0.5",
            source_port=443,
            destination_port=51234,
            timestamp=T0 + timedelta(milliseconds=1),
            tcp_flags=TcpFlags(syn=True, ack=True),
        )
    )
    aggregator.process_packet(
        make_packet(timestamp=T0 + timedelta(seconds=1), tcp_flags=TcpFlags(ack=True))
    )

    assert len(signals) == 1
    signal = signals[0]
    assert str(signal.source_ip) == "10.0.0.5"
    assert str(signal.destination_ip) == "10.0.0.10"
    assert signal.destination_port == 443
    assert signal.protocol is Protocol.TCP
    assert signal.timestamp == T0


def test_on_new_flow_fires_again_for_a_genuinely_new_flow_from_the_same_ports() -> None:
    signals: list[NewFlowSignal] = []
    aggregator = _aggregator(on_new_flow=signals.append)

    aggregator.process_packet(make_packet(source_port=51234, destination_port=443, timestamp=T0))
    aggregator.process_packet(
        make_packet(
            source_port=51235,
            destination_port=443,
            timestamp=T0 + timedelta(milliseconds=1),
        )
    )

    assert len(signals) == 2


def test_snapshot_slow_connection_clusters_finds_a_qualifying_cluster_without_closing_flows() -> None:
    """ADDENDUM_2.md B2: read-only — the connections stay open, nothing is popped from the table."""
    aggregator = _aggregator(active_timeout_seconds=3600, inactive_timeout_seconds=3600)
    for source_port in range(40000, 40008):
        aggregator.process_packet(
            make_packet(
                source_ip="203.0.113.80",
                destination_ip="10.0.0.60",
                source_port=source_port,
                destination_port=80,
                timestamp=T0,
                total_length=10,
            )
        )
    assert len(aggregator) == 8

    clusters = aggregator.snapshot_slow_connection_clusters(
        now=T0 + timedelta(seconds=20),
        min_duration_seconds=15.0,
        max_bytes_per_second=5.0,
        concurrent_threshold=8,
    )

    assert len(clusters) == 1
    cluster = clusters[0]
    assert str(cluster.source_ip) == "203.0.113.80"
    assert str(cluster.destination_ip) == "10.0.0.60"
    assert cluster.concurrent_count == 8
    # Nothing was closed — every flow is still open in the table.
    assert len(aggregator) == 8


def test_snapshot_slow_connection_clusters_ignores_a_single_slow_connection() -> None:
    aggregator = _aggregator(active_timeout_seconds=3600, inactive_timeout_seconds=3600)
    aggregator.process_packet(
        make_packet(
            source_ip="203.0.113.81",
            destination_ip="10.0.0.61",
            destination_port=80,
            timestamp=T0,
            total_length=10,
        )
    )

    clusters = aggregator.snapshot_slow_connection_clusters(
        now=T0 + timedelta(seconds=20),
        min_duration_seconds=15.0,
        max_bytes_per_second=5.0,
        concurrent_threshold=8,
    )

    assert clusters == []


def test_snapshot_slow_connection_clusters_ignores_flows_below_the_duration_floor() -> None:
    aggregator = _aggregator(active_timeout_seconds=3600, inactive_timeout_seconds=3600)
    for source_port in range(40000, 40008):
        aggregator.process_packet(
            make_packet(
                source_ip="203.0.113.82",
                destination_ip="10.0.0.62",
                source_port=source_port,
                destination_port=80,
                timestamp=T0,
                total_length=10,
            )
        )

    clusters = aggregator.snapshot_slow_connection_clusters(
        now=T0 + timedelta(seconds=5),  # below min_duration_seconds
        min_duration_seconds=15.0,
        max_bytes_per_second=5.0,
        concurrent_threshold=8,
    )

    assert clusters == []


def test_snapshot_slow_connection_clusters_ignores_flows_above_the_rate_ceiling() -> None:
    """A fast, ordinary connection held open a while must not be mistaken for a slow one."""
    aggregator = _aggregator(active_timeout_seconds=3600, inactive_timeout_seconds=3600)
    for source_port in range(40000, 40008):
        aggregator.process_packet(
            make_packet(
                source_ip="203.0.113.83",
                destination_ip="10.0.0.63",
                source_port=source_port,
                destination_port=80,
                timestamp=T0,
                total_length=10_000,  # far above the rate ceiling once divided by duration
            )
        )

    clusters = aggregator.snapshot_slow_connection_clusters(
        now=T0 + timedelta(seconds=20),
        min_duration_seconds=15.0,
        max_bytes_per_second=5.0,
        concurrent_threshold=8,
    )

    assert clusters == []


def test_udp_flow_produces_expected_protocol_on_finalization() -> None:
    aggregator = _aggregator(active_timeout_seconds=3600, inactive_timeout_seconds=10)
    aggregator.process_packet(make_packet(protocol=Protocol.UDP, tcp_flags=None, timestamp=T0))
    emitted = aggregator.sweep_timeouts(T0 + timedelta(seconds=11))
    assert len(emitted) == 1
    assert emitted[0].protocol is Protocol.UDP

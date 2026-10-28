"""`ConnectionStartTracker` (V2_CONTRACTS §11): the unit D1 counts."""

from datetime import UTC, datetime
from ipaddress import IPv4Address

from pirewall.core.enums import Protocol
from pirewall.core.models.flow import Flow
from pirewall.flow.connection_start import ConnectionStartTracker

_T = datetime(2026, 3, 1, tzinfo=UTC)


def _flow(
    sport: int = 40000,
    protocol: Protocol = Protocol.TCP,
    initiated: bool = True,
    src: str = "192.168.100.5",
    dport: int = 80,
) -> Flow:
    return Flow.model_validate(
        {
            "flow_id": "f",
            "source_ip": IPv4Address(src),
            "destination_ip": IPv4Address("203.0.113.7"),
            "source_port": sport,
            "destination_port": dport,
            "protocol": protocol,
            "first_seen": _T,
            "last_seen": _T,
            "packet_count": 1,
            "byte_count": 60,
            "forward_packet_count": 1,
            "backward_packet_count": 0,
            "forward_byte_count": 60,
            "backward_byte_count": 0,
            "tcp_flags": {"syn": 1, "ack": 0, "fin": 0, "rst": 0, "psh": 0, "urg": 0},
            "packet_size_stats": {"min_bytes": 60, "max_bytes": 60, "mean_bytes": 60.0, "std_bytes": 0.0},
            "inter_arrival_stats": {
                "min_seconds": 0.0,
                "max_seconds": 0.0,
                "mean_seconds": 0.0,
                "std_seconds": 0.0,
            },
            "opened_by_initiation": initiated,
        }
    )


def test_a_syn_opened_tcp_record_seen_first_is_a_start() -> None:
    tracker = ConnectionStartTracker(max_tracked=10)
    assert tracker.observe(_flow()) is True
    assert len(tracker) == 1


def test_a_connection_split_by_the_active_timeout_counts_once() -> None:
    tracker = ConnectionStartTracker(max_tracked=10)
    assert tracker.observe(_flow(initiated=True)) is True
    # The continuation record opens mid-stream (no SYN) ...
    assert tracker.observe(_flow(initiated=False)) is False
    # ... and even a retransmitted SYN on the same 5-tuple is not a new start.
    assert tracker.observe(_flow(initiated=True)) is False


def test_responder_opened_records_are_never_starts_but_are_remembered() -> None:
    tracker = ConnectionStartTracker(max_tracked=10)
    assert tracker.observe(_flow(initiated=False)) is False
    assert tracker.observe(_flow(initiated=True)) is False


def test_udp_and_icmp_records_are_never_starts_and_never_tracked() -> None:
    tracker = ConnectionStartTracker(max_tracked=10)
    assert tracker.observe(_flow(protocol=Protocol.UDP)) is False
    assert tracker.observe(_flow(protocol=Protocol.ICMP, sport=0, dport=0)) is False
    assert len(tracker) == 0
    # A UDP record never shadows the TCP record with the same ports.
    assert tracker.observe(_flow()) is True


def test_distinct_tuples_are_distinct_starts() -> None:
    tracker = ConnectionStartTracker(max_tracked=10)
    assert [tracker.observe(_flow(sport=port)) for port in (1, 2, 3)] == [True, True, True]
    assert tracker.observe(_flow(src="192.168.100.6")) is True


def test_the_bound_evicts_least_recently_seen_and_over_counts_visibly() -> None:
    tracker = ConnectionStartTracker(max_tracked=2)
    tracker.observe(_flow(sport=1))
    tracker.observe(_flow(sport=2))
    tracker.observe(_flow(sport=1))  # 1 is now the most recently seen
    assert tracker.observe(_flow(sport=3)) is True  # evicts 2
    assert (len(tracker), tracker.evictions) == (2, 1)
    assert tracker.observe(_flow(sport=1)) is False  # still remembered
    assert tracker.observe(_flow(sport=2)) is True  # forgotten: counted again
    assert tracker.evictions == 2

"""`FlowState`: packet accumulation, forward/backward attribution, `RunningStats`."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from pirewall.core.enums import Protocol
from pirewall.core.models.common import TcpFlags
from pirewall.core.models.packet import PacketMetadata
from pirewall.flow.key import compute_flow_key
from pirewall.flow.state import FlowState, RunningStats
from tests.helpers.flows import make_packet

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def test_running_stats_mean_min_max_std() -> None:
    stats = RunningStats()
    for value in (10.0, 20.0, 30.0):
        stats.add(value)

    assert stats.count == 3
    assert stats.mean == 20.0
    assert stats.min == 10.0
    assert stats.max == 30.0
    assert round(stats.std, 4) == round((200 / 3) ** 0.5, 4)


def test_running_stats_empty_defaults_to_zero() -> None:
    stats = RunningStats()
    assert stats.mean == 0.0
    assert stats.std == 0.0
    assert stats.min == 0.0
    assert stats.max == 0.0


def _open_flow(first_packet: PacketMetadata) -> FlowState:
    assert isinstance(first_packet.source_ip, IPv4Address)
    assert isinstance(first_packet.destination_ip, IPv4Address)
    key = compute_flow_key(
        first_packet.source_ip,
        first_packet.destination_ip,
        first_packet.source_port,
        first_packet.destination_port,
        first_packet.protocol,
    )
    return FlowState.opening(key, first_packet)


def test_opening_and_observing_attributes_forward_and_backward_correctly() -> None:
    syn = make_packet(
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        source_port=51234,
        destination_port=443,
        timestamp=T0,
        total_length=60,
        tcp_flags=TcpFlags(syn=True),
    )
    state = _open_flow(syn)

    syn_ack = make_packet(
        source_ip="10.0.0.10",
        destination_ip="10.0.0.5",
        source_port=443,
        destination_port=51234,
        timestamp=T0 + timedelta(milliseconds=10),
        total_length=60,
        tcp_flags=TcpFlags(syn=True, ack=True),
    )
    state.observe(syn_ack)

    ack = make_packet(
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        source_port=51234,
        destination_port=443,
        timestamp=T0 + timedelta(milliseconds=20),
        total_length=52,
        tcp_flags=TcpFlags(ack=True),
    )
    state.observe(ack)

    assert state.packet_count == 3
    assert state.forward_packet_count == 2
    assert state.backward_packet_count == 1
    assert state.forward_byte_count == 60 + 52
    assert state.backward_byte_count == 60
    assert state.syn_count == 2
    assert state.ack_count == 2

    flow = state.to_flow("flow-1")
    assert flow.source_ip.compressed == "10.0.0.5"
    assert flow.destination_ip.compressed == "10.0.0.10"
    assert flow.packet_count == 3
    assert flow.tcp_flags.syn == 2
    assert flow.duration_seconds == 0.02


def test_fin_from_both_directions_marks_completion_flags() -> None:
    syn = make_packet(timestamp=T0, tcp_flags=TcpFlags(syn=True))
    state = _open_flow(syn)

    fin_forward = make_packet(
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        source_port=51234,
        destination_port=443,
        timestamp=T0 + timedelta(seconds=1),
        tcp_flags=TcpFlags(fin=True, ack=True),
    )
    state.observe(fin_forward)
    assert state.saw_fin_forward is True
    assert state.saw_fin_backward is False

    fin_backward = make_packet(
        source_ip="10.0.0.10",
        destination_ip="10.0.0.5",
        source_port=443,
        destination_port=51234,
        timestamp=T0 + timedelta(seconds=1, milliseconds=5),
        tcp_flags=TcpFlags(fin=True, ack=True),
    )
    state.observe(fin_backward)
    assert state.saw_fin_backward is True


def test_rst_sets_saw_rst() -> None:
    syn = make_packet(timestamp=T0, tcp_flags=TcpFlags(syn=True))
    state = _open_flow(syn)
    rst = make_packet(
        source_ip="10.0.0.10",
        destination_ip="10.0.0.5",
        source_port=443,
        destination_port=51234,
        timestamp=T0 + timedelta(seconds=1),
        tcp_flags=TcpFlags(rst=True),
    )
    state.observe(rst)
    assert state.saw_rst is True


def test_last_seen_never_moves_backward_on_out_of_order_packet() -> None:
    first = make_packet(timestamp=T0 + timedelta(seconds=5))
    state = _open_flow(first)
    late_but_older = make_packet(
        source_ip="10.0.0.10",
        destination_ip="10.0.0.5",
        source_port=443,
        destination_port=51234,
        timestamp=T0,
    )
    state.observe(late_but_older)
    assert state.last_seen == T0 + timedelta(seconds=5)


def test_icmp_packet_has_no_ports_and_no_tcp_flags() -> None:
    ping = make_packet(
        protocol=Protocol.ICMP,
        source_port=None,
        destination_port=None,
        tcp_flags=None,
    )
    state = _open_flow(ping)
    flow = state.to_flow("flow-icmp")
    assert flow.source_port is None
    assert flow.destination_port is None
    assert flow.tcp_flags.syn == 0

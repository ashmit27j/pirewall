"""Flow closure decisions: active/inactive timeout and TCP completion (spec §8)."""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from pirewall.core.enums import Protocol
from pirewall.core.models.common import TcpFlags
from pirewall.core.models.packet import PacketMetadata
from pirewall.flow.key import compute_flow_key
from pirewall.flow.state import FlowState
from pirewall.flow.timeout import FlowCloseReason, check_closure, is_tcp_completed
from tests.helpers.flows import make_packet

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _open(packet: PacketMetadata) -> FlowState:
    assert isinstance(packet.source_ip, IPv4Address)
    assert isinstance(packet.destination_ip, IPv4Address)
    key = compute_flow_key(
        packet.source_ip, packet.destination_ip, packet.source_port, packet.destination_port, packet.protocol
    )
    return FlowState.opening(key, packet)


def test_no_closure_when_within_all_timeouts() -> None:
    state = _open(make_packet(timestamp=T0))
    reason = check_closure(
        state, T0 + timedelta(seconds=1), active_timeout_seconds=30, inactive_timeout_seconds=10
    )
    assert reason is None


def test_active_timeout_fires() -> None:
    state = _open(make_packet(timestamp=T0))
    now = T0 + timedelta(seconds=31)
    reason = check_closure(state, now, active_timeout_seconds=30, inactive_timeout_seconds=10)
    assert reason is FlowCloseReason.ACTIVE_TIMEOUT


def test_inactive_timeout_fires() -> None:
    state = _open(make_packet(timestamp=T0))
    now = T0 + timedelta(seconds=11)
    reason = check_closure(state, now, active_timeout_seconds=3600, inactive_timeout_seconds=10)
    assert reason is FlowCloseReason.INACTIVE_TIMEOUT


def test_tcp_completion_takes_priority_over_timeouts() -> None:
    state = _open(make_packet(timestamp=T0, tcp_flags=TcpFlags(syn=True)))
    state.observe(
        make_packet(
            source_ip="10.0.0.10",
            destination_ip="10.0.0.5",
            source_port=443,
            destination_port=51234,
            timestamp=T0,
            tcp_flags=TcpFlags(fin=True, ack=True),
        )
    )
    state.observe(
        make_packet(
            source_ip="10.0.0.5",
            destination_ip="10.0.0.10",
            source_port=51234,
            destination_port=443,
            timestamp=T0,
            tcp_flags=TcpFlags(fin=True, ack=True),
        )
    )
    assert is_tcp_completed(state) is True

    reason = check_closure(state, T0, active_timeout_seconds=3600, inactive_timeout_seconds=3600)
    assert reason is FlowCloseReason.TCP_COMPLETED


def test_udp_flow_never_reports_tcp_completed() -> None:
    state = _open(make_packet(protocol=Protocol.UDP, tcp_flags=None, timestamp=T0))
    assert is_tcp_completed(state) is False

"""`FlowTable`: bounded size and LRU eviction (spec §8)."""

from datetime import UTC, datetime
from ipaddress import IPv4Address

from pirewall.core.enums import Protocol
from pirewall.flow.key import FlowKey, compute_flow_key
from pirewall.flow.state import FlowState, FlowTable
from tests.helpers.flows import make_packet

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _state_for_port(port: int) -> tuple[FlowKey, FlowState]:
    packet = make_packet(source_port=port, destination_port=443, timestamp=T0)
    assert isinstance(packet.source_ip, IPv4Address)
    assert isinstance(packet.destination_ip, IPv4Address)
    key = compute_flow_key(
        packet.source_ip, packet.destination_ip, packet.source_port, packet.destination_port, Protocol.TCP
    )
    return key, FlowState.opening(key, packet)


def test_table_never_exceeds_max_flows() -> None:
    table = FlowTable(max_flows=3)
    for port in range(50000, 50010):
        key, state = _state_for_port(port)
        table.insert(key, state)
        assert len(table) <= 3


def test_insert_beyond_capacity_evicts_least_recently_used() -> None:
    table = FlowTable(max_flows=2)
    key_a, state_a = _state_for_port(1)
    key_b, state_b = _state_for_port(2)
    key_c, state_c = _state_for_port(3)

    table.insert(key_a, state_a)
    table.insert(key_b, state_b)
    evicted = table.insert(key_c, state_c)

    assert evicted is state_a
    assert table.get(key_a) is None
    assert table.get(key_b) is state_b
    assert table.get(key_c) is state_c


def test_get_refreshes_lru_order() -> None:
    table = FlowTable(max_flows=2)
    key_a, state_a = _state_for_port(1)
    key_b, state_b = _state_for_port(2)
    key_c, state_c = _state_for_port(3)

    table.insert(key_a, state_a)
    table.insert(key_b, state_b)
    table.get(key_a)  # touch A so B becomes the least-recently-used
    evicted = table.insert(key_c, state_c)

    assert evicted is state_b
    assert table.get(key_a) is state_a


def test_pop_removes_and_returns_state() -> None:
    table = FlowTable(max_flows=5)
    key, state = _state_for_port(1)
    table.insert(key, state)

    assert table.pop(key) is state
    assert table.pop(key) is None
    assert len(table) == 0


def test_flood_of_distinct_flows_stays_bounded() -> None:
    table = FlowTable(max_flows=100)
    for port in range(50000, 55000):
        key, state = _state_for_port(port)
        table.insert(key, state)
        assert len(table) <= 100
    assert len(table) == 100

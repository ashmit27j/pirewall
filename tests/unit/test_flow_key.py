"""Flow-key normalization: A->B and B->A packets land in the same flow (spec §8)."""

from ipaddress import IPv4Address

from pirewall.core.enums import Protocol
from pirewall.flow.key import compute_flow_key


def test_forward_and_backward_packets_produce_the_same_key() -> None:
    forward = compute_flow_key(
        IPv4Address("10.0.0.5"), IPv4Address("10.0.0.10"), 51234, 443, Protocol.TCP
    )
    backward = compute_flow_key(
        IPv4Address("10.0.0.10"), IPv4Address("10.0.0.5"), 443, 51234, Protocol.TCP
    )
    assert forward == backward
    assert hash(forward) == hash(backward)


def test_different_protocol_produces_a_different_key() -> None:
    tcp_key = compute_flow_key(
        IPv4Address("10.0.0.5"), IPv4Address("10.0.0.10"), 51234, 443, Protocol.TCP
    )
    udp_key = compute_flow_key(
        IPv4Address("10.0.0.5"), IPv4Address("10.0.0.10"), 51234, 443, Protocol.UDP
    )
    assert tcp_key != udp_key


def test_different_endpoint_produces_a_different_key() -> None:
    key_a = compute_flow_key(
        IPv4Address("10.0.0.5"), IPv4Address("10.0.0.10"), 51234, 443, Protocol.TCP
    )
    key_b = compute_flow_key(
        IPv4Address("10.0.0.6"), IPv4Address("10.0.0.10"), 51234, 443, Protocol.TCP
    )
    assert key_a != key_b


def test_none_ports_handled_consistently() -> None:
    forward = compute_flow_key(
        IPv4Address("10.0.0.5"), IPv4Address("10.0.0.10"), None, None, Protocol.ICMP
    )
    backward = compute_flow_key(
        IPv4Address("10.0.0.10"), IPv4Address("10.0.0.5"), None, None, Protocol.ICMP
    )
    assert forward == backward

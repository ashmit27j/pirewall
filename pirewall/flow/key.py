"""Flow-key construction with bidirectional normalization (spec §8).

A flow's identity is (source IP, destination IP, source port, destination
port, protocol), but A->B and B->A packets must land in the *same* flow.
`FlowKey` is the direction-independent (undirected) identity used for flow
table lookups; which side is "forward" is tracked separately, per-flow, in
`pirewall.flow.state.FlowState` (set by whichever packet opened the flow).
"""

from dataclasses import dataclass
from ipaddress import IPv4Address

from pirewall.core.enums import Protocol

_Endpoint = tuple[IPv4Address, int | None]


@dataclass(frozen=True, slots=True)
class FlowKey:
    """A hashable, direction-independent flow identity."""

    protocol: Protocol
    endpoint_a: _Endpoint
    endpoint_b: _Endpoint


def _sort_value(endpoint: _Endpoint) -> tuple[int, int]:
    ip, port = endpoint
    return (int(ip), port if port is not None else -1)


def compute_flow_key(
    source_ip: IPv4Address,
    destination_ip: IPv4Address,
    source_port: int | None,
    destination_port: int | None,
    protocol: Protocol,
) -> FlowKey:
    """Build the undirected `FlowKey` for one packet's (src, dst) pair.

    Sorting the two endpoints into a canonical order is what makes this the
    same key regardless of which direction the packet travels in.
    """
    forward: _Endpoint = (source_ip, source_port)
    backward: _Endpoint = (destination_ip, destination_port)
    endpoint_a, endpoint_b = sorted((forward, backward), key=_sort_value)
    return FlowKey(protocol=protocol, endpoint_a=endpoint_a, endpoint_b=endpoint_b)

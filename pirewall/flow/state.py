"""Per-flow accumulated state and the bounded flow table (spec §8).

`FlowState` is the mutable accumulator a flow uses while it's still open;
`FlowTable` is the bounded, LRU-evicting container the aggregator keeps
open flows in. Neither is a Pydantic domain model — `FlowState.to_flow()`
is what produces the frozen, validated `pirewall.core.models.Flow` once a
flow closes.
"""

import math
from collections import OrderedDict
from collections.abc import ItemsView, ValuesView
from datetime import datetime
from ipaddress import IPv4Address

from pirewall.core.enums import Protocol
from pirewall.core.models.common import InterArrivalStats, PacketSizeStats, TcpFlagCounts
from pirewall.core.models.flow import Flow
from pirewall.core.models.packet import PacketMetadata
from pirewall.flow.key import FlowKey


class RunningStats:
    """Online min/max/mean/std accumulator (Welford's algorithm).

    Keeps per-flow memory bounded regardless of how many packets a flow
    sees — spec §8's "the flow table must never grow without bounds" applies
    just as much to a single very long-lived flow as to the table itself.
    """

    __slots__ = ("_m2", "_max", "_mean", "_min", "count")

    def __init__(self) -> None:
        self.count = 0
        self._mean = 0.0
        self._m2 = 0.0
        self._min = math.inf
        self._max = -math.inf

    def add(self, value: float) -> None:
        self.count += 1
        delta = value - self._mean
        self._mean += delta / self.count
        self._m2 += delta * (value - self._mean)
        self._min = min(self._min, value)
        self._max = max(self._max, value)

    @property
    def mean(self) -> float:
        return self._mean if self.count else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self._m2 / self.count) if self.count else 0.0

    @property
    def min(self) -> float:
        return self._min if self.count else 0.0

    @property
    def max(self) -> float:
        return self._max if self.count else 0.0


class FlowState:
    """Mutable, in-progress accumulation for one flow.

    `forward_*` fields fix the orientation established by the packet that
    opened this flow — every later packet is classified forward/backward by
    comparing its (source IP, source port) against these, independent of
    `FlowKey`'s own undirected, sorted representation.
    """

    __slots__ = (
        "_last_packet_time",
        "ack_count",
        "backward_byte_count",
        "backward_packet_count",
        "byte_count",
        "fin_count",
        "first_seen",
        "forward_byte_count",
        "forward_destination_ip",
        "forward_destination_port",
        "forward_packet_count",
        "forward_source_ip",
        "forward_source_port",
        "inter_arrival_stats",
        "key",
        "last_seen",
        "packet_count",
        "packet_size_stats",
        "protocol",
        "psh_count",
        "rst_count",
        "saw_fin_backward",
        "saw_fin_forward",
        "saw_rst",
        "syn_count",
        "urg_count",
    )

    def __init__(
        self,
        key: FlowKey,
        protocol: Protocol,
        forward_source_ip: IPv4Address,
        forward_source_port: int | None,
        forward_destination_ip: IPv4Address,
        forward_destination_port: int | None,
        first_seen: datetime,
    ) -> None:
        self.key = key
        self.protocol = protocol
        self.forward_source_ip = forward_source_ip
        self.forward_source_port = forward_source_port
        self.forward_destination_ip = forward_destination_ip
        self.forward_destination_port = forward_destination_port
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.packet_count = 0
        self.byte_count = 0
        self.forward_packet_count = 0
        self.backward_packet_count = 0
        self.forward_byte_count = 0
        self.backward_byte_count = 0
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.urg_count = 0
        self.saw_fin_forward = False
        self.saw_fin_backward = False
        self.saw_rst = False
        self.packet_size_stats = RunningStats()
        self.inter_arrival_stats = RunningStats()
        self._last_packet_time: datetime | None = None

    @classmethod
    def opening(cls, key: FlowKey, packet: PacketMetadata) -> "FlowState":
        """Create a new flow state from the packet that opens the flow, and observe it."""
        assert isinstance(packet.source_ip, IPv4Address)
        assert isinstance(packet.destination_ip, IPv4Address)
        state = cls(
            key=key,
            protocol=packet.protocol,
            forward_source_ip=packet.source_ip,
            forward_source_port=packet.source_port,
            forward_destination_ip=packet.destination_ip,
            forward_destination_port=packet.destination_port,
            first_seen=packet.timestamp,
        )
        state.observe(packet)
        return state

    def observe(self, packet: PacketMetadata) -> None:
        """Fold one more packet belonging to this flow into the accumulated state."""
        is_forward = (
            packet.source_ip == self.forward_source_ip
            and packet.source_port == self.forward_source_port
        )

        if packet.timestamp > self.last_seen:
            self.last_seen = packet.timestamp

        self.packet_count += 1
        self.byte_count += packet.total_length
        if is_forward:
            self.forward_packet_count += 1
            self.forward_byte_count += packet.total_length
        else:
            self.backward_packet_count += 1
            self.backward_byte_count += packet.total_length

        if packet.tcp_flags is not None:
            flags = packet.tcp_flags
            self.syn_count += flags.syn
            self.ack_count += flags.ack
            self.fin_count += flags.fin
            self.rst_count += flags.rst
            self.psh_count += flags.psh
            self.urg_count += flags.urg
            if flags.fin:
                if is_forward:
                    self.saw_fin_forward = True
                else:
                    self.saw_fin_backward = True
            if flags.rst:
                self.saw_rst = True

        self.packet_size_stats.add(float(packet.total_length))
        if self._last_packet_time is not None:
            delta = (packet.timestamp - self._last_packet_time).total_seconds()
            if delta >= 0:
                self.inter_arrival_stats.add(delta)
        self._last_packet_time = packet.timestamp

    def to_flow(self, flow_id: str) -> Flow:
        """Finalize this accumulator into an immutable, validated `Flow`."""
        return Flow(
            flow_id=flow_id,
            source_ip=self.forward_source_ip,
            destination_ip=self.forward_destination_ip,
            source_port=self.forward_source_port,
            destination_port=self.forward_destination_port,
            protocol=self.protocol,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            forward_packet_count=self.forward_packet_count,
            backward_packet_count=self.backward_packet_count,
            forward_byte_count=self.forward_byte_count,
            backward_byte_count=self.backward_byte_count,
            tcp_flags=TcpFlagCounts(
                syn=self.syn_count,
                ack=self.ack_count,
                fin=self.fin_count,
                rst=self.rst_count,
                psh=self.psh_count,
                urg=self.urg_count,
            ),
            packet_size_stats=PacketSizeStats(
                min_bytes=round(self.packet_size_stats.min),
                max_bytes=round(self.packet_size_stats.max),
                mean_bytes=self.packet_size_stats.mean,
                std_bytes=self.packet_size_stats.std,
            ),
            inter_arrival_stats=InterArrivalStats(
                min_seconds=self.inter_arrival_stats.min,
                max_seconds=self.inter_arrival_stats.max,
                mean_seconds=self.inter_arrival_stats.mean,
                std_seconds=self.inter_arrival_stats.std,
            ),
        )


class FlowTable:
    """A bounded, LRU-evicting table of open `FlowState`s (spec §8)."""

    def __init__(self, max_flows: int) -> None:
        self._max_flows = max_flows
        self._flows: OrderedDict[FlowKey, FlowState] = OrderedDict()

    def __len__(self) -> int:
        return len(self._flows)

    def get(self, key: FlowKey) -> FlowState | None:
        """Look up a flow, marking it most-recently-used if found."""
        state = self._flows.get(key)
        if state is not None:
            self._flows.move_to_end(key)
        return state

    def insert(self, key: FlowKey, state: FlowState) -> FlowState | None:
        """Insert a brand-new flow, evicting the least-recently-used one if at capacity.

        Returns the evicted `FlowState`, if an eviction occurred, so the
        caller can finalize and emit it rather than silently dropping it.
        """
        evicted: FlowState | None = None
        if len(self._flows) >= self._max_flows:
            _, evicted = self._flows.popitem(last=False)
        self._flows[key] = state
        return evicted

    def pop(self, key: FlowKey) -> FlowState | None:
        return self._flows.pop(key, None)

    def items(self) -> ItemsView[FlowKey, FlowState]:
        return self._flows.items()

    def values(self) -> ValuesView[FlowState]:
        return self._flows.values()

    def clear(self) -> None:
        self._flows.clear()

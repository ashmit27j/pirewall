"""`FlowAggregator`: turns a stream of `PacketMetadata` into `Flow` objects (spec §8).

IPv4-only (ADDENDUM.md A5): a packet whose `address_family` is IPV6 is
never turned into a flow here — it simply isn't routed into the flow table
at all, so IPv6 traffic never reaches feature extraction or ML. It can
still be counted upstream in capture statistics (Phase 2); this module just
never emits an IPv6 `Flow` because `pirewall.core.models.Flow` structurally
cannot represent one.

**`on_new_flow` (ADDENDUM_2.md B1).** Fires once per flow, at creation —
the only point volumetric behavioral signals (scanning, destination
diversity, burst rate) actually need, since they're derived from connection
metadata that's fully known from the first packet. This is a plain
`Callable`, not an import of anything from `pirewall.detection`: the flow
layer must not depend on the detection layer (`CLAUDE.md`'s "dependencies
flow one direction"). Whatever wires the two together at runtime
(`pirewall.runtime.core.CoreDaemon`) supplies the callback.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address
from uuid import uuid4

from pirewall.config.models import FlowConfig
from pirewall.core.enums import Protocol
from pirewall.core.models.flow import Flow
from pirewall.core.models.packet import PacketMetadata
from pirewall.flow.key import compute_flow_key
from pirewall.flow.state import FlowState, FlowTable
from pirewall.flow.timeout import check_closure


@dataclass(frozen=True, slots=True)
class SlowConnectionCluster:
    """A (source, destination) pair currently running many concurrent slow connections.

    Produced by `FlowAggregator.snapshot_slow_connection_clusters`
    (ADDENDUM_2.md B2) — a source-level aggregate observation, not a
    per-flow one. `representative_flow` is a point-in-time snapshot of one
    qualifying *still-open* flow's accumulated stats so far (the
    connection itself is left running, untouched, in the table) — it
    exists only to carry (source, destination, port, protocol) identity
    through the normal detection/decision/enforcement pipeline the same
    way a genuinely completed flow does, reusing that machinery rather than
    building a parallel one.
    """

    source_ip: IPv4Address
    destination_ip: IPv4Address
    concurrent_count: int
    representative_flow: Flow


@dataclass(frozen=True, slots=True)
class NewFlowSignal:
    """Everything knowable about a flow the instant its first packet arrives.

    Deliberately not a Pydantic domain model (spec §9 lists `Flow`/
    `PacketMetadata` as the domain objects that cross a subsystem boundary;
    this is internal plumbing between the flow and detection layers, same
    category as `pirewall.capture.interfaces.CapturedPacket`).
    """

    source_ip: IPv4Address
    destination_ip: IPv4Address
    destination_port: int | None
    protocol: Protocol
    timestamp: datetime


type NewFlowSink = Callable[[NewFlowSignal], None]


class FlowAggregator:
    """Routes packets into a bounded flow table and emits completed/expired flows."""

    def __init__(
        self,
        config: FlowConfig,
        on_new_flow: NewFlowSink | None = None,
    ) -> None:
        self._table = FlowTable(max_flows=config.max_flows)
        self._active_timeout_seconds = float(config.active_timeout_seconds)
        self._inactive_timeout_seconds = float(config.inactive_timeout_seconds)
        self._on_new_flow = on_new_flow

    def __len__(self) -> int:
        """Number of flows currently open in the table."""
        return len(self._table)

    def process_packet(self, packet: PacketMetadata) -> list[Flow]:
        """Fold one packet into the flow table.

        Returns zero or more finalized `Flow` objects emitted as a side
        effect of processing this packet: an evicted flow (table was at
        capacity), a flow this packet just completed (TCP FIN/RST), or both.
        IPv6 packets are silently ignored (ADDENDUM.md A5, see module
        docstring) and always return an empty list.
        """
        if not isinstance(packet.source_ip, IPv4Address) or not isinstance(
            packet.destination_ip, IPv4Address
        ):
            return []

        key = compute_flow_key(
            packet.source_ip,
            packet.destination_ip,
            packet.source_port,
            packet.destination_port,
            packet.protocol,
        )
        emitted: list[Flow] = []

        state = self._table.get(key)
        if state is None:
            state = FlowState.opening(key, packet)
            if self._on_new_flow is not None:
                self._on_new_flow(
                    NewFlowSignal(
                        source_ip=packet.source_ip,
                        destination_ip=packet.destination_ip,
                        destination_port=packet.destination_port,
                        protocol=packet.protocol,
                        timestamp=packet.timestamp,
                    )
                )
            evicted = self._table.insert(key, state)
            if evicted is not None:
                emitted.append(self._finalize(evicted))
        else:
            state.observe(packet)

        reason = check_closure(
            state, packet.timestamp, self._active_timeout_seconds, self._inactive_timeout_seconds
        )
        if reason is not None:
            self._table.pop(key)
            emitted.append(self._finalize(state))

        return emitted

    def sweep_timeouts(self, now: datetime) -> list[Flow]:
        """Close every flow that has timed out as of `now`.

        Meant to be called periodically by whatever owns the wall clock
        (Phase 8's main loop) — packet processing alone can't detect a flow
        that simply stopped sending packets forever.
        """
        emitted: list[Flow] = []
        for key, state in list(self._table.items()):
            reason = check_closure(
                state, now, self._active_timeout_seconds, self._inactive_timeout_seconds
            )
            if reason is not None:
                self._table.pop(key)
                emitted.append(self._finalize(state))
        return emitted

    def snapshot_slow_connection_clusters(
        self,
        now: datetime,
        min_duration_seconds: float,
        max_bytes_per_second: float,
        concurrent_threshold: int,
    ) -> list[SlowConnectionCluster]:
        """Group currently-open flows by (source, destination) and report any qualifying cluster.

        A flow qualifies as a "slow connection" candidate once it has been
        open at least `min_duration_seconds` while averaging at most
        `max_bytes_per_second`. A (source, destination) pair is only
        reported once at least `concurrent_threshold` of its currently-open
        flows qualify simultaneously — a single slow connection never
        qualifies on its own, by construction (ADDENDUM_2.md B2).

        Read-only: this never closes, pops, or otherwise mutates a flow —
        every connection keeps running exactly as it was. Meant to be
        called periodically, alongside `sweep_timeouts`, by whatever owns
        the wall clock (`pirewall.runtime.core.CoreDaemon`'s sweep loop).
        """
        by_pair: dict[tuple[IPv4Address, IPv4Address], list[FlowState]] = {}
        for state in self._table.values():
            duration = (now - state.first_seen).total_seconds()
            if duration < min_duration_seconds:
                continue
            rate = state.byte_count / duration
            if rate > max_bytes_per_second:
                continue
            key = (state.forward_source_ip, state.forward_destination_ip)
            by_pair.setdefault(key, []).append(state)

        clusters: list[SlowConnectionCluster] = []
        for (source_ip, destination_ip), states in by_pair.items():
            if len(states) < concurrent_threshold:
                continue
            # Deterministic, arbitrary-but-stable choice of which single
            # connection carries the evidence forward: the longest-held one.
            representative = min(states, key=lambda candidate: candidate.first_seen)
            clusters.append(
                SlowConnectionCluster(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    concurrent_count=len(states),
                    representative_flow=representative.to_flow(flow_id=str(uuid4())),
                )
            )
        return clusters

    def flush(self) -> list[Flow]:
        """Finalize every remaining open flow, regardless of timeout status.

        For graceful shutdown (spec §43): in-progress flows are not
        silently discarded when pirewall stops.
        """
        emitted = [self._finalize(state) for state in self._table.values()]
        self._table.clear()
        return emitted

    @staticmethod
    def _finalize(state: FlowState) -> Flow:
        return state.to_flow(flow_id=str(uuid4()))

"""`FlowAggregator`: turns a stream of `PacketMetadata` into `Flow` objects (spec §8).

IPv4-only (ADDENDUM.md A5): a packet whose `address_family` is IPV6 is
never turned into a flow here — it simply isn't routed into the flow table
at all, so IPv6 traffic never reaches feature extraction or ML. It can
still be counted upstream in capture statistics (Phase 2); this module just
never emits an IPv6 `Flow` because `pirewall.core.models.Flow` structurally
cannot represent one.

**Non-unicast addresses never become flows.** DHCP (`0.0.0.0` ->
`255.255.255.255`), mDNS/SSDP (`224.0.0.0/4`), APIPA (`169.254.0.0/16`) and
loopback traffic are ordinary link-level infrastructure, not connections
between hosts, and the adaptive pipeline has no meaningful way to reason
about them: they have no single owner to attribute behavior to and no
address a firewall rule could sensibly target. Left in, every device
joining the AP contributed a burst of `0.0.0.0` DHCP flows that the
behavior analyser scored as one very busy "source" — the origin of the
`slow_rate_dos` / `repeated_connections` findings reported against
`0.0.0.0`. They are filtered here, at the single entry point to the
pipeline, for the same reason IPv6 is (A5): a shape the rest of the
pipeline should never have to special-case. `pirewall.firewall.validator`
rejects them again independently, because safety validation may not depend
on an upstream layer having already been careful.

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
from ipaddress import IPv4Address, IPv4Network
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
    # The opening frame's Ethernet addresses (ADDENDUM_4.md D3), normalised
    # lowercase `aa:bb:cc:dd:ee:ff`; None when the packet had no frame.
    source_mac: str | None = None
    destination_mac: str | None = None


type NewFlowSink = Callable[[NewFlowSignal], None]


def _is_slow_connection_candidate(
    state: FlowState,
    now: datetime,
    min_duration_seconds: float,
    max_bytes_per_second: float,
    max_idle_seconds: float,
) -> bool:
    """Whether one open flow has the shape of a held-open, trickling connection.

    The single definition of a "slow connection" candidate (ADDENDUM_2.md
    B2). `native/src/flow.rs`'s `slow_clusters` mirrors it condition for
    condition; the parity tests compare the two on the same flow table, so
    any change here has to be made there in the same commit.

    See `FlowAggregator.snapshot_slow_connection_clusters` for why each
    condition is here and which false positive it removes.
    """
    # Slowloris-class attacks hold a server's connection slots open. Only
    # TCP has a slot to hold.
    if state.protocol is not Protocol.TCP:
        return False
    # Unanswered attempts are a scan's shape, not a held connection's.
    if state.backward_packet_count < 1:
        return False
    # Already closing: it occupies the table, not the server.
    if state.saw_fin_forward or state.saw_fin_backward or state.saw_rst:
        return False

    duration = (now - state.first_seen).total_seconds()
    if duration < min_duration_seconds:
        return False
    # A connection that has gone quiet is not trickling, and its
    # bytes-over-elapsed rate only falls further into the band the longer it
    # stays quiet. Checked before the rate so the reason is unambiguous.
    if (now - state.last_seen).total_seconds() > max_idle_seconds:
        return False

    return state.byte_count / duration <= max_bytes_per_second


def is_routable_unicast(address: IPv4Address, protected_network: IPv4Network | None = None) -> bool:
    """True if `address` is a host address a flow (and therefore a rule) could sensibly name.

    False for the unspecified address (`0.0.0.0`), the limited broadcast
    address (`255.255.255.255`), multicast (`224.0.0.0/4`), loopback
    (`127.0.0.0/8`), link-local/APIPA (`169.254.0.0/16`) and the reserved
    `240.0.0.0/4` block. When `protected_network` is given, its own
    subnet-directed broadcast address (e.g. `192.168.100.255` for a /24) is
    excluded too — intrinsically it looks like an ordinary host address, so
    only the local prefix can identify it.

    Deliberately *not* a "is this a public address" check: RFC 1918 space is
    exactly what the protected LAN uses, and blocking a misbehaving LAN
    client is a core use case.
    """
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
        or address == _LIMITED_BROADCAST
    ):
        return False
    return not (
        protected_network is not None
        and protected_network.prefixlen < 31
        and address == protected_network.broadcast_address
    )


_LIMITED_BROADCAST = IPv4Address("255.255.255.255")


class FlowAggregator:
    """Routes packets into a bounded flow table and emits completed/expired flows."""

    def __init__(
        self,
        config: FlowConfig,
        on_new_flow: NewFlowSink | None = None,
        protected_network: IPv4Network | None = None,
    ) -> None:
        self._table = FlowTable(max_flows=config.max_flows)
        self._active_timeout_seconds = float(config.active_timeout_seconds)
        self._inactive_timeout_seconds = float(config.inactive_timeout_seconds)
        self._on_new_flow = on_new_flow
        self._protected_network = protected_network

    def __len__(self) -> int:
        """Number of flows currently open in the table."""
        return len(self._table)

    def process_packet(self, packet: PacketMetadata) -> list[Flow]:
        """Fold one packet into the flow table.

        Returns zero or more finalized `Flow` objects emitted as a side
        effect of processing this packet: an evicted flow (table was at
        capacity), a flow this packet just completed (TCP FIN/RST), or both.
        IPv6 packets are silently ignored (ADDENDUM.md A5, see module
        docstring) and always return an empty list, as is any packet whose
        source or destination is not a routable unicast address (see
        `is_routable_unicast` and the module docstring).
        """
        if not isinstance(packet.source_ip, IPv4Address) or not isinstance(
            packet.destination_ip, IPv4Address
        ):
            return []

        if not is_routable_unicast(
            packet.source_ip, self._protected_network
        ) or not is_routable_unicast(packet.destination_ip, self._protected_network):
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
            # Only a connection *initiation* is a new connection for behavior
            # analysis; a flow first seen mid-conversation is attributed to its
            # responder and must not count against it (see Flow.opened_by_initiation).
            if self._on_new_flow is not None and state.initiated:
                self._on_new_flow(
                    NewFlowSignal(
                        source_ip=packet.source_ip,
                        destination_ip=packet.destination_ip,
                        destination_port=packet.destination_port,
                        protocol=packet.protocol,
                        timestamp=packet.timestamp,
                        source_mac=packet.source_mac,
                        destination_mac=packet.destination_mac,
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
        max_idle_seconds: float,
    ) -> list[SlowConnectionCluster]:
        """Group currently-open flows by (source, destination) and report any qualifying cluster.

        A flow qualifies as a "slow connection" candidate once it has been
        open at least `min_duration_seconds` while averaging at most
        `max_bytes_per_second`. A (source, destination) pair is only
        reported once at least
        `concurrent_threshold` of its currently-open flows qualify
        simultaneously — a single slow connection never qualifies on its
        own, by construction (ADDENDUM_2.md B2).

        Four further conditions narrow "slow connection" to the shape a
        slow-rate attack actually has. Each exists because the broader test
        matched ordinary client traffic: on the first real LAN client
        (`pi-live`, 2026-10-30) every one of 45 shadow decisions was this
        pattern firing on a phone's normal browsing.

        * **TCP only.** Slowloris-class attacks work by holding a server's
          connection slots open; UDP and ICMP have no such slot to hold, so
          a DNS lookup or a QUIC probe can never be one.
        * **Established.** The peer must have answered at least once. A
          lone unanswered SYN is a scan or a dead host, and is already
          `REPEATED_FAILURES`/`SCANNING`'s business.
        * **Not being torn down.** A connection that has seen FIN or RST is
          closing, not being held open; it lingers in the table only until
          eviction.
        * **Still trickling** (`max_idle_seconds`). This is the decisive
          one. The rate test divides bytes by *elapsed* time, so a flow
          that goes quiet drifts into the band as its idle time grows: a
          500-byte exchange that finished in two seconds reads as 8 B/s
          after a minute and 4 B/s after two, so every idle keepalive on
          the network eventually qualified. A real slowloris cannot go quiet —
          the server would reap it — so requiring recent activity costs no
          detection and removes the whole benign population.

        Read-only: this never closes, pops, or otherwise mutates a flow —
        every connection keeps running exactly as it was. Meant to be
        called periodically, alongside `sweep_timeouts`, by whatever owns
        the wall clock (`pirewall.runtime.core.CoreDaemon`'s sweep loop).
        """
        by_pair: dict[tuple[IPv4Address, IPv4Address], list[FlowState]] = {}
        for state in self._table.values():
            if not _is_slow_connection_candidate(
                state, now, min_duration_seconds, max_bytes_per_second, max_idle_seconds
            ):
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

    def snapshot_open_flow_from(self, source_ip: IPv4Address) -> Flow | None:
        """A point-in-time `Flow` snapshot of `source_ip`'s most recently active open flow.

        Read-only, like `snapshot_slow_connection_clusters`: the connection
        keeps running untouched in the table. `None` if the source has no
        open flow. A linear scan — callers rate-limit it (the source-level
        fast path asks at most once per source per cooldown, and only for a
        source whose behavior already scores MEDIUM or above).
        """
        newest: FlowState | None = None
        for state in self._table.values():
            if state.forward_source_ip != source_ip:
                continue
            if newest is None or state.last_seen > newest.last_seen:
                newest = state
        return None if newest is None else newest.to_flow(flow_id=str(uuid4()))

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

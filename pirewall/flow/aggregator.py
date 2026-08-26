"""`FlowAggregator`: turns a stream of `PacketMetadata` into `Flow` objects (spec §8).

IPv4-only (ADDENDUM.md A5): a packet whose `address_family` is IPV6 is
never turned into a flow here — it simply isn't routed into the flow table
at all, so IPv6 traffic never reaches feature extraction or ML. It can
still be counted upstream in capture statistics (Phase 2); this module just
never emits an IPv6 `Flow` because `pirewall.core.models.Flow` structurally
cannot represent one.
"""

from datetime import datetime
from ipaddress import IPv4Address
from uuid import uuid4

from pirewall.config.models import FlowConfig
from pirewall.core.models.flow import Flow
from pirewall.core.models.packet import PacketMetadata
from pirewall.flow.key import compute_flow_key
from pirewall.flow.state import FlowState, FlowTable
from pirewall.flow.timeout import check_closure


class FlowAggregator:
    """Routes packets into a bounded flow table and emits completed/expired flows."""

    def __init__(self, config: FlowConfig) -> None:
        self._table = FlowTable(max_flows=config.max_flows)
        self._active_timeout_seconds = float(config.active_timeout_seconds)
        self._inactive_timeout_seconds = float(config.inactive_timeout_seconds)

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

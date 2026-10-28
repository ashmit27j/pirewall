"""The canonical `Flow` domain model (spec §8, §9)."""

from ipaddress import IPv4Address

from pydantic import AwareDatetime, Field, NonNegativeInt, model_validator

from pirewall.core.enums import Protocol
from pirewall.core.models.common import (
    InterArrivalStats,
    MacAddress,
    PacketSizeStats,
    PayloadStats,
    PirewallModel,
    TcpFlagCounts,
)


class Flow(PirewallModel):
    """A canonical, bidirectional network flow aggregated from captured packets.

    Flow identity is (source IP, destination IP, source port, destination
    port, protocol); bidirectional traffic is normalized into forward/
    backward counters relative to the flow's initiating packet. IPv4-only
    for v1 (ADDENDUM.md A5) — the address fields are typed `IPv4Address`,
    so an IPv6 flow cannot be constructed at all.
    """

    flow_id: str = Field(min_length=1)
    source_ip: IPv4Address
    destination_ip: IPv4Address
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Protocol

    first_seen: AwareDatetime
    last_seen: AwareDatetime

    packet_count: NonNegativeInt
    byte_count: NonNegativeInt
    forward_packet_count: NonNegativeInt
    backward_packet_count: NonNegativeInt
    forward_byte_count: NonNegativeInt
    backward_byte_count: NonNegativeInt

    tcp_flags: TcpFlagCounts = Field(default_factory=TcpFlagCounts)
    packet_size_stats: PacketSizeStats
    inter_arrival_stats: InterArrivalStats
    # Feature schema 2.0.0 reads only these, never the IP-level byte fields
    # above (see `PayloadStats`). Optional so that non-ML callers (tests,
    # IPC round-trips of older state) can still build a `Flow`; feature
    # extraction refuses a flow without it rather than inventing zeros.
    payload_stats: PayloadStats | None = None
    # Whether the packet that opened this flow *initiated* a connection
    # (a TCP SYN without ACK/RST, or any non-TCP packet). False for a flow
    # first seen mid-conversation — a lone RST, a SYN-ACK whose SYN was
    # dropped, a stray ACK — whose "source" is really the responder. Behavior
    # analysis must not count those as connections the responder made: it
    # once rate-limited a flood's own victim (LIVE_AB.md).
    opened_by_initiation: bool = True
    # Ethernet addresses of the frame that opened the flow (ADDENDUM_4.md
    # D3): the initiator's MAC, even when its IP source was spoofed. For
    # keying and spoof detection only. MAC is never a model feature: the
    # feature extractor does not read these, and a test pins that. None
    # where there was no frame (the CICIDS/UNSW dataset adapters). Not
    # `UnicastMacAddress`: an observed frame field may be anything a sender
    # put on the wire; whatever *identifies a device* re-validates it.
    source_mac: MacAddress | None = None
    destination_mac: MacAddress | None = None

    @model_validator(mode="after")
    def _check_consistency(self) -> "Flow":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        if self.payload_stats is not None and self.payload_stats.total_bytes > self.byte_count:
            raise ValueError("payload bytes cannot exceed total (IP-level) bytes")
        if self.forward_packet_count + self.backward_packet_count != self.packet_count:
            raise ValueError("forward_packet_count + backward_packet_count must equal packet_count")
        if self.forward_byte_count + self.backward_byte_count != self.byte_count:
            raise ValueError("forward_byte_count + backward_byte_count must equal byte_count")
        return self

    @property
    def duration_seconds(self) -> float:
        """Elapsed time between the first and last packet observed in this flow."""
        return (self.last_seen - self.first_seen).total_seconds()

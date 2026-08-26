"""The `PacketMetadata` domain model (spec §7).

This is the output of `pirewall.capture.parser` — L3/L4 header fields only,
never application payload (spec §7 "do not perform application-payload
inspection as part of the core detection pipeline").
"""

from ipaddress import IPv4Address, IPv6Address

from pydantic import AwareDatetime, Field, NonNegativeInt

from pirewall.core.enums import AddressFamily, Protocol
from pirewall.core.models.common import PirewallModel, TcpFlags


class PacketMetadata(PirewallModel):
    """Parsed L3/L4 header fields for one captured packet.

    `address_family` tags whether `source_ip`/`destination_ip` are IPv4 or
    IPv6 — both are parsed (spec §7), but only IPV4 packets are aggregated
    into adaptive-pipeline flows in v1 (ADDENDUM.md A5); Phase 3 filters on
    this field.
    """

    timestamp: AwareDatetime
    address_family: AddressFamily
    source_ip: IPv4Address | IPv6Address
    destination_ip: IPv4Address | IPv6Address
    protocol: Protocol

    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    tcp_flags: TcpFlags | None = None

    total_length: NonNegativeInt
    payload_length: NonNegativeInt

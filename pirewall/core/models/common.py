"""Shared value objects reused by several domain models."""

import re
from typing import Annotated

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, NonNegativeInt

# Six octets, one separator style throughout: `aa:bb:cc:dd:ee:ff` or
# `aa-bb-cc-dd-ee-ff`, any case. Dotted Cisco form and bare 12-digit hex are
# refused on purpose: a MAC arrives here from config, the lease file, nft JSON
# and the native engine, and none of those emit them, so accepting them would
# only widen what a malformed input can be mistaken for.
_MAC_PATTERN = re.compile(r"^[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}$")


def _normalise_mac(value: object) -> str:
    if not isinstance(value, str) or _MAC_PATTERN.fullmatch(value) is None:
        raise ValueError("a MAC address must be six hex octets separated by ':' or '-'")
    return value.lower().replace("-", ":")


def _require_unicast_identity(value: str) -> str:
    first_octet = int(value[:2], 16)
    if first_octet & 0x01:
        # The I/G bit: group (multicast) addresses, broadcast included. No
        # single device owns one, so binding, blocking or allowlisting by
        # one would act on every listener at once (ADDENDUM_4.md D3).
        raise ValueError("a multicast or broadcast MAC cannot identify a device")
    if value == "00:00:00:00:00:00":
        raise ValueError("the all-zero MAC cannot identify a device")
    return value


MacAddress = Annotated[str, BeforeValidator(_normalise_mac)]
"""Any EUI-48, normalised to lowercase `aa:bb:cc:dd:ee:ff` (ADDENDUM_4.md D3).

Use for observed frame fields (`Flow.destination_mac` may legitimately be
broadcast). Anything that *identifies a device* uses `UnicastMacAddress`.
"""

UnicastMacAddress = Annotated[MacAddress, AfterValidator(_require_unicast_identity)]
"""A `MacAddress` that can name one device: not multicast, broadcast or all-zero.

Locally administered addresses are accepted: phones randomise their MAC per
network, and those randomised addresses are exactly what pirewall sees.
"""


class PirewallModel(BaseModel):
    """Base config shared by every domain model: no stray fields, no silent mutation.

    Deliberately *not* `strict=True`: these models sit at the boundary of
    TOML/JSON data (config files, the API, dataset rows) where the wire
    representation of an `IPv4Address`, an `Enum`, or a tuple is always a
    plain string/list. Pydantic's default ("lax") mode still enforces the
    annotated type and every constraint below — it just also accepts the
    standard string/list encodings of those types rather than rejecting
    them outright, which is what boundary parsing requires.
    """

    model_config = ConfigDict(extra="forbid", frozen=False)


class PacketSizeStats(PirewallModel):
    """Packet-size distribution statistics over a flow or window (spec §8)."""

    min_bytes: NonNegativeInt
    max_bytes: NonNegativeInt
    mean_bytes: float = Field(ge=0.0)
    std_bytes: float = Field(ge=0.0)


class PayloadStats(PirewallModel):
    """Transport-layer *payload* byte statistics over a flow (feature schema 2.0.0).

    Payload means the bytes after the TCP/UDP/ICMP header — never IP or L4
    header bytes. This is the definition CICFlowMeter (and therefore the
    CICIDS2017 training data) uses for every packet-length column, so it is
    the only definition under which training-time and runtime features
    agree. `Flow.byte_count`/`packet_size_stats` stay IP-level (total
    length) for everything that is not ML: dashboards, the slow-rate
    bytes/second check, rule evidence. See `docs/FEATURE_SCHEMA.md`.
    """

    forward_bytes: NonNegativeInt
    backward_bytes: NonNegativeInt
    min_bytes: NonNegativeInt
    max_bytes: NonNegativeInt
    mean_bytes: float = Field(ge=0.0)
    std_bytes: float = Field(ge=0.0)

    @property
    def total_bytes(self) -> int:
        """Payload bytes in both directions."""
        return self.forward_bytes + self.backward_bytes


class InterArrivalStats(PirewallModel):
    """Inter-arrival-time statistics, in seconds, over a flow or window (spec §8)."""

    min_seconds: float = Field(ge=0.0)
    max_seconds: float = Field(ge=0.0)
    mean_seconds: float = Field(ge=0.0)
    std_seconds: float = Field(ge=0.0)


class TcpFlags(PirewallModel):
    """The control flags set on a single TCP packet (spec §7)."""

    syn: bool = False
    ack: bool = False
    fin: bool = False
    rst: bool = False
    psh: bool = False
    urg: bool = False


class TcpFlagCounts(PirewallModel):
    """Counts of each TCP control flag observed in a flow (spec §8)."""

    syn: NonNegativeInt = 0
    ack: NonNegativeInt = 0
    fin: NonNegativeInt = 0
    rst: NonNegativeInt = 0
    psh: NonNegativeInt = 0
    urg: NonNegativeInt = 0
    ece: NonNegativeInt = 0
    cwr: NonNegativeInt = 0

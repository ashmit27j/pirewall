"""Shared value objects reused by several domain models."""

from pydantic import BaseModel, ConfigDict, Field, NonNegativeInt


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

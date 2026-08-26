"""The `CaptureStatistics` domain model (spec §6).

Surfaced later through the control panel's "network statistics" section
(spec §30) — kept as a real domain model rather than an ad hoc dict so that
boundary stays typed.
"""

from pydantic import Field, NonNegativeInt

from pirewall.core.models.common import PirewallModel


class CaptureStatistics(PirewallModel):
    """A point-in-time snapshot of a `PacketCapture` implementation's counters."""

    interface: str = Field(min_length=1)
    packets_seen: NonNegativeInt = 0
    packets_dropped: NonNegativeInt = 0
    packets_malformed: NonNegativeInt = 0

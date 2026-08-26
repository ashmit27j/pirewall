"""The `BehaviorAssessment` domain model (spec §17).

Behavior analysis is deterministic and never uses an LLM at runtime — this
model captures the *output* of that deterministic analysis, not how it was
computed.
"""

from ipaddress import IPv4Address

from pydantic import AwareDatetime, Field, model_validator

from pirewall.core.enums import BehaviorPatternType
from pirewall.core.models.common import PirewallModel


class BehaviorAssessment(PirewallModel):
    """Deterministic behavioral-pattern findings for a source over a time window."""

    source_ip: IPv4Address
    detected_patterns: tuple[BehaviorPatternType, ...] = Field(default_factory=tuple)
    confidence: float = Field(ge=0.0, le=1.0)
    description: str = Field(min_length=1)
    window_start: AwareDatetime
    window_end: AwareDatetime

    @model_validator(mode="after")
    def _check_window(self) -> "BehaviorAssessment":
        if self.window_end < self.window_start:
            raise ValueError("window_end must not precede window_start")
        return self

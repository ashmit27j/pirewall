"""The `FirewallDecision` domain model (spec §19)."""

from pydantic import AwareDatetime, Field

from pirewall.core.enums import FirewallAction, ThreatLevel
from pirewall.core.models.common import PirewallModel


class FirewallDecision(PirewallModel):
    """An explicit, auditable decision derived from a `ThreatAssessment`.

    This is the boundary between the detection/scoring layers and the
    firewall subsystem (CLAUDE.md "Detection -> Decision -> Enforcement are
    separate layers") — nothing upstream of this model may call the firewall
    backend directly.
    """

    id: str = Field(min_length=1)
    threat_assessment_id: str = Field(min_length=1)
    flow_id: str | None = None

    action: FirewallAction
    threat_score: float = Field(ge=0.0, le=100.0)
    threat_level: ThreatLevel
    reason: str = Field(min_length=1)
    evidence: tuple[str, ...] = Field(default_factory=tuple)

    decided_at: AwareDatetime

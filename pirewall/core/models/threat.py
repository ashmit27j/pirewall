"""The `ThreatAssessment` domain model (spec §18)."""

from ipaddress import IPv4Address

from pydantic import AwareDatetime, Field

from pirewall.core.enums import ThreatLevel
from pirewall.core.models.behavior import BehaviorAssessment
from pirewall.core.models.common import PirewallModel
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence


class ThreatAssessment(PirewallModel):
    """Combined known-attack, anomaly, and behavioral evidence for one flow.

    This is the single object the decision engine (spec §19) consumes to
    produce a `FirewallDecision` — it never sees the raw evidence models
    directly, keeping detection and decision-making as separate layers.
    """

    id: str = Field(min_length=1)
    flow_id: str = Field(min_length=1)
    source_ip: IPv4Address
    destination_ip: IPv4Address

    threat_score: float = Field(ge=0.0, le=100.0)
    threat_level: ThreatLevel
    confidence: float = Field(ge=0.0, le=1.0)

    known_evidence: KnownEvidence | None = None
    anomaly_evidence: AnomalyEvidence | None = None
    behavior_assessment: BehaviorAssessment | None = None

    explanation: str = Field(min_length=1)
    contributing_evidence: tuple[str, ...] = Field(default_factory=tuple)

    assessed_at: AwareDatetime

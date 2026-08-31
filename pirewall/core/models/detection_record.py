"""The `DetectionRecord` domain model — raw detection-layer output for the API's `/detections`.

Distinct from `ThreatAssessment` (`/threats`): this is the pre-scoring
evidence for one flow (spec's Detection -> Engine/Threat layering, spec
§14/§18), before `pirewall.engine.scoring` combines it into a score.
"""

from pydantic import AwareDatetime, Field

from pirewall.core.models.common import PirewallModel
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence, ProtocolSignatureEvidence


class DetectionRecord(PirewallModel):
    """One flow's raw known-attack/anomaly/protocol-signature evidence, paired for display."""

    flow_id: str = Field(min_length=1)
    known_evidence: KnownEvidence | None = None
    anomaly_evidence: AnomalyEvidence | None = None
    protocol_signature_evidence: ProtocolSignatureEvidence | None = None
    recorded_at: AwareDatetime

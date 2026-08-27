"""`ThreatAssessment -> FirewallDecision` (spec §19).

Keeps detection/scoring and decision-making as separate layers (CLAUDE.md):
this module only picks an action from a `ThreatAssessment`'s already-final
`threat_level` — it does not re-score or re-interpret evidence itself.

Action ladder (a deliberate, documented design choice, not derived from
data): each `ThreatLevel` maps to exactly one `FirewallAction`, the
mildest action that's still a meaningful response at that severity —
`LOW` never generates any adaptive rule (see
`pirewall.firewall.generator`, which returns `None` for `ALLOW`).
"""

from datetime import datetime
from uuid import uuid4

from pirewall.core.enums import FirewallAction, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.threat import ThreatAssessment

_ACTION_BY_LEVEL: dict[ThreatLevel, FirewallAction] = {
    ThreatLevel.LOW: FirewallAction.ALLOW,
    ThreatLevel.MEDIUM: FirewallAction.MONITOR,
    ThreatLevel.HIGH: FirewallAction.RATE_LIMIT,
    ThreatLevel.CRITICAL: FirewallAction.BLOCK,
}


def decide(assessment: ThreatAssessment, decided_at: datetime) -> FirewallDecision:
    """Turn one `ThreatAssessment` into an explicit, auditable `FirewallDecision`."""
    return FirewallDecision(
        id=str(uuid4()),
        threat_assessment_id=assessment.id,
        flow_id=assessment.flow_id,
        action=_ACTION_BY_LEVEL[assessment.threat_level],
        threat_score=assessment.threat_score,
        threat_level=assessment.threat_level,
        reason=assessment.explanation,
        evidence=assessment.contributing_evidence,
        decided_at=decided_at,
    )

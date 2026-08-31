"""`ThreatAssessment -> FirewallDecision` (spec §19).

Keeps detection/scoring and decision-making as separate layers (CLAUDE.md):
this module only picks an action from a `ThreatAssessment`'s already-final
`threat_level` — it does not re-score or re-interpret evidence itself.

Action ladder (a deliberate, documented design choice, not derived from
data): each `ThreatLevel` maps to exactly one `FirewallAction`, the
mildest action that's still a meaningful response at that severity —
`LOW` never generates any adaptive rule (see
`pirewall.firewall.generator`, which returns `None` for `ALLOW`).

**Evidence-maturity gate (ADDENDUM_2.md B3).** A real, named, testable
invariant, not left as an emergent property of today's tuned
weights/thresholds: no single, low-evidence observation may ever directly
produce a `BLOCK` or `RATE_LIMIT` decision. "Sufficient evidence" is
exactly one of:

(a) a fully completed flow's known-attack classification
    (`ThreatAssessment.known_evidence is not None`) — this is already
    single-flow-conclusive by what it *is*, not by any threshold — or a
    positive protocol-structure match (`protocol_signature_evidence is not
    None`, ADDENDUM_2.md B4/B5: a Heartbleed length mismatch or a JA3
    fingerprint hit) — a deterministic pattern match, not a raw score,
    same category of conclusiveness as a classification;
(b) a behavioral signal that already requires multiple independent
    observations by construction — every current
    `BehaviorPatternType` does (see `pirewall.detection.behavior`'s module
    docstring), so any non-empty `detected_patterns` qualifies; or
(c) the same elevated reading from the same source, observed consistently
    across `ThreatConfig.evidence_maturity_consistency_windows` consecutive
    independent assessment windows (`EvidenceMaturityTracker`) — the path
    for evidence that never qualifies under (a) or (b) on its own, e.g.
    anomaly evidence alone.

Anything reaching `BLOCK`/`RATE_LIMIT` without meeting one of these is
downgraded to `MONITOR`. This is a safety net, not a new bottleneck on
detection already trusted: under the current scoring weights
(`known_attack_weight=60, anomaly_weight=15, behavior_weight=25,
protocol_signature_weight=75`), `anomaly_weight` alone cannot even reach
`low_threshold` (25) — so today, real scoring output can only ever reach
`high_threshold`/`critical_threshold` (75/90) by already having
`known_evidence`, a behavioral pattern, or `protocol_signature_evidence`
contributing, i.e. (a) or (b) already holds whenever this gate would
apply. Path (c) is therefore not reachable from today's real scoring
output at all — it exists purely as a forward-looking safety net for a
future weight/threshold change, verified by construction rather than
assumed (see `docs/ADDENDUM_2.md` B3 for the full arithmetic).
"""

from collections import OrderedDict
from datetime import datetime
from ipaddress import IPv4Address
from uuid import uuid4

from pirewall.config.models import ThreatConfig
from pirewall.core.enums import FirewallAction, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.threat import ThreatAssessment

_ACTION_BY_LEVEL: dict[ThreatLevel, FirewallAction] = {
    ThreatLevel.LOW: FirewallAction.ALLOW,
    ThreatLevel.MEDIUM: FirewallAction.MONITOR,
    ThreatLevel.HIGH: FirewallAction.RATE_LIMIT,
    ThreatLevel.CRITICAL: FirewallAction.BLOCK,
}

# The two actions the evidence-maturity gate (ADDENDUM_2.md B3) applies to.
# MONITOR and below are already the mildest possible response and need no
# gating; this is exactly the "restrictive" action set spec §24 already
# names for the validator's allowlist/safety stages.
_MATURITY_GATED_ACTIONS = frozenset({FirewallAction.RATE_LIMIT, FirewallAction.BLOCK})


class EvidenceMaturityTracker:
    """Bounded per-source history for the evidence-maturity gate's path (c) (ADDENDUM_2.md B3).

    Tracks, per source, whether its last few assessment windows were
    "elevated but not otherwise mature" (path (a)/(b) both failed, yet the
    threat level was above LOW) — only ever consulted/updated for a window
    that doesn't already qualify under (a) or (b), since those already
    settle maturity on their own. LRU-bounded by `max_tracked_sources`,
    same shape as `pirewall.detection.behavior.BehaviorAnalyzer`, so this
    can never be used to exhaust memory.
    """

    def __init__(self, consistency_windows: int, max_tracked_sources: int) -> None:
        self._consistency_windows = consistency_windows
        self._max_tracked_sources = max_tracked_sources
        self._sources: OrderedDict[IPv4Address, int] = OrderedDict()

    def __len__(self) -> int:
        return len(self._sources)

    def observe(self, source_ip: IPv4Address) -> bool:
        """Record one more weak-but-elevated window for `source_ip`; return whether it is now consistent.

        Only ever called for a window that was already elevated enough to
        attempt `BLOCK`/`RATE_LIMIT` but failed paths (a)/(b) — so every
        call is a genuine additional observation, never a mixed signal;
        reaching `consistency_windows` such calls (they need not be
        wall-clock-consecutive, only consecutive *calls* to this method for
        this source) is what "consistent" means. The count saturates rather
        than growing unboundedly for a long-lived attacker.
        """
        count = min(self._sources.get(source_ip, 0) + 1, self._consistency_windows)
        if source_ip not in self._sources and len(self._sources) >= self._max_tracked_sources:
            self._sources.popitem(last=False)
        self._sources[source_ip] = count
        self._sources.move_to_end(source_ip)
        return count >= self._consistency_windows

    @classmethod
    def from_config(cls, config: ThreatConfig) -> "EvidenceMaturityTracker":
        return cls(config.evidence_maturity_consistency_windows, config.max_tracked_maturity_sources)


def decide(
    assessment: ThreatAssessment,
    decided_at: datetime,
    maturity_tracker: EvidenceMaturityTracker | None = None,
) -> FirewallDecision:
    """Turn one `ThreatAssessment` into an explicit, auditable `FirewallDecision`.

    `maturity_tracker` is optional so this stays trivially callable in tests
    that don't care about path (c) above — omitting it simply means a
    `BLOCK`/`RATE_LIMIT` decision lacking (a) or (b) always downgrades to
    `MONITOR`, which is the conservative default, never the permissive one.
    """
    action = _ACTION_BY_LEVEL[assessment.threat_level]
    if action in _MATURITY_GATED_ACTIONS and not _has_mature_evidence(assessment, maturity_tracker):
        action = FirewallAction.MONITOR
    return FirewallDecision(
        id=str(uuid4()),
        threat_assessment_id=assessment.id,
        flow_id=assessment.flow_id,
        action=action,
        threat_score=assessment.threat_score,
        threat_level=assessment.threat_level,
        reason=assessment.explanation,
        evidence=assessment.contributing_evidence,
        decided_at=decided_at,
    )


def _has_mature_evidence(assessment: ThreatAssessment, tracker: EvidenceMaturityTracker | None) -> bool:
    """Paths (a)/(b)/(c) from the module docstring, in order."""
    if assessment.known_evidence is not None:
        return True
    if assessment.protocol_signature_evidence is not None:
        return True
    if assessment.behavior_assessment is not None and assessment.behavior_assessment.detected_patterns:
        return True
    if tracker is None:
        return False
    return tracker.observe(assessment.source_ip)

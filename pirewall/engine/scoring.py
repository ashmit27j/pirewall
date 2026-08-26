"""Combines evidence into a numeric 0-100 threat score (spec §18).

Every weight/threshold used here comes from `config.threat`
(`pirewall.config.models.ThreatConfig`) — no magic constants inline
(CLAUDE.md). The formula is deliberately simple and explainable rather
than empirically tuned: it hasn't been validated against real attack
traffic (see `docs/PROGRESS.md` — that's Environment-dependent, spec §34).

Formula, per evidence type, each contributing independently up to its
configured weight:

* **Known-attack** (`known_attack_weight`): `weight * confidence` if the
  predicted class is an attack label (`pirewall.ml.labels.is_attack_label`),
  else 0 — a confidently-benign classification contributes nothing.
* **Anomaly** (`anomaly_weight`): the full weight if `is_anomaly`, else 0 —
  a flat contribution, not scaled by the raw (unbounded, model-specific)
  anomaly score.
* **Behavior** (`behavior_weight`): `weight * (patterns detected / total
  possible pattern types)` — more corroborating behavioral signals scale
  the contribution up linearly.

The three contributions are summed and clamped to `[0, 100]`.
"""

from dataclasses import dataclass

from pirewall.config.models import ThreatConfig
from pirewall.core.enums import BehaviorPatternType
from pirewall.core.models.behavior import BehaviorAssessment
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence
from pirewall.ml.labels import is_attack_label

_TOTAL_PATTERN_TYPES = len(BehaviorPatternType)


@dataclass(frozen=True, slots=True)
class ScoreBreakdown:
    """The overall score plus each evidence type's individual contribution (for explainability)."""

    total: float
    known_attack_contribution: float
    anomaly_contribution: float
    behavior_contribution: float


def score_evidence(
    config: ThreatConfig,
    known_evidence: KnownEvidence | None,
    anomaly_evidence: AnomalyEvidence | None,
    behavior_assessment: BehaviorAssessment | None,
) -> ScoreBreakdown:
    """Combine whichever evidence is present into a `ScoreBreakdown`.

    Any subset of evidence may be `None` (e.g. no model loaded, or no
    tracked behavior yet for this source) — missing evidence simply
    contributes 0, it never fails scoring.
    """
    known_attack_contribution = 0.0
    if known_evidence is not None and is_attack_label(known_evidence.predicted_class):
        known_attack_contribution = config.known_attack_weight * known_evidence.confidence

    anomaly_contribution = 0.0
    if anomaly_evidence is not None and anomaly_evidence.is_anomaly:
        anomaly_contribution = config.anomaly_weight

    behavior_contribution = 0.0
    if behavior_assessment is not None and behavior_assessment.detected_patterns:
        behavior_contribution = config.behavior_weight * (
            len(behavior_assessment.detected_patterns) / _TOTAL_PATTERN_TYPES
        )

    total = min(100.0, known_attack_contribution + anomaly_contribution + behavior_contribution)
    return ScoreBreakdown(
        total=total,
        known_attack_contribution=known_attack_contribution,
        anomaly_contribution=anomaly_contribution,
        behavior_contribution=behavior_contribution,
    )

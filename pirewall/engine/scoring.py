"""Combines evidence into a numeric 0-100 threat score (spec §18).

Every weight/threshold used here comes from `config.threat`
(`pirewall.config.models.ThreatConfig`) — no magic constants inline
(CLAUDE.md). The formula stays deliberately simple and explainable
(spec §18); what changed as of model v0.4.0 is that the **weights** are now
set from measured per-detector reliability rather than an even split:

    known-attack (LightGBM)     precision 0.9927, FPR 0.0018  -> weight 60
    anomaly (Isolation Forest)  precision 0.5300, FPR 0.0987  -> weight 15
    behavior (deterministic)    no labelled ground truth      -> weight 25

The anomaly detector is correct roughly half the times it fires, at ~55x
the classifier's false-positive rate; at 15 it cannot reach
`low_threshold` (25) alone, only contribute in combination. See
`docs/ML_PIPELINE.md` for where those numbers come from.

**Deliberately not done: per-class weighting.** Per-class precision on this
dataset ranges from 0.357 (Web Attack - XSS) to 0.9997 (DDoS), so scaling
the known-attack contribution by the predicted class's precision is
tempting. It is rejected because it would bake dataset-specific constants
into the engine, go stale silently on the next retrain, and make a score
impossible to explain without a lookup table — all three against spec §18.
Per-class precision is recorded in the model metadata for anything that
wants it.

Still Environment-dependent: none of this is validated against *live*
traffic on the Pi (spec §34).

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

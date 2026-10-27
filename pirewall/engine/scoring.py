"""Combines evidence into a numeric 0-100 threat score (spec §18).

Every weight/threshold used here comes from `config.threat`
(`pirewall.config.models.ThreatConfig`) — no magic constants inline
(CLAUDE.md). The formula stays deliberately simple and explainable
(spec §18); what changed as of model v0.4.0 is that the **weights** are now
set from measured per-detector reliability rather than an even split:

    known-attack (LightGBM)     precision 0.9927, FPR 0.0018  -> weight 60
    anomaly (Isolation Forest)  precision 0.5300, FPR 0.0987  -> weight 15
    behavior (deterministic)    per-pattern points, capped    -> cap 80

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
* **Behavior** (`behavior_weight`, `behavior_pattern_points`): the sum of
  each detected pattern's own points, capped at `behavior_weight`. Replaced
  `weight * patterns / 9`, which treated "loaded a busy web page" and "port
  scan" as equally diagnostic and capped every behavior-only score far
  below anything actionable (docs/KNOWN_ISSUES.md #20). The cap sits below
  `critical_threshold`, so behavior alone can reach RATE_LIMIT but never
  BLOCK.
* **Protocol signature** (`protocol_signature_weight`, ADDENDUM_2.md
  B4/B5): `weight * confidence` — same shape as known-attack, but the
  evidence comes from a deterministic TLS structural match
  (`pirewall.detection.tls_heartbeat`/`tls_fingerprint`) rather than an ML
  classification. Weighted above `known_attack_weight` because a Heartbleed
  length mismatch (confidence 1.0) is a near-certain protocol violation,
  not a probabilistic score; a JA3 tool-fingerprint match sets a lower
  `confidence`, reflecting that it's an honestly weaker, evadable signal.

The four contributions are summed and clamped to `[0, 100]`.
"""

from dataclasses import dataclass

from pirewall.config.models import ThreatConfig
from pirewall.core.models.behavior import BehaviorAssessment
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence, ProtocolSignatureEvidence
from pirewall.ml.labels import is_attack_label


@dataclass(frozen=True, slots=True)
class ScoreBreakdown:
    """The overall score plus each evidence type's individual contribution (for explainability)."""

    total: float
    known_attack_contribution: float
    anomaly_contribution: float
    behavior_contribution: float
    protocol_signature_contribution: float = 0.0


def score_evidence(
    config: ThreatConfig,
    known_evidence: KnownEvidence | None,
    anomaly_evidence: AnomalyEvidence | None,
    behavior_assessment: BehaviorAssessment | None,
    protocol_signature_evidence: ProtocolSignatureEvidence | None = None,
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
        behavior_contribution = min(
            config.behavior_weight,
            sum(config.behavior_pattern_points[pattern] for pattern in behavior_assessment.detected_patterns),
        )

    protocol_signature_contribution = 0.0
    if protocol_signature_evidence is not None:
        protocol_signature_contribution = (
            config.protocol_signature_weight * protocol_signature_evidence.confidence
        )

    total = min(
        100.0,
        known_attack_contribution
        + anomaly_contribution
        + behavior_contribution
        + protocol_signature_contribution,
    )
    return ScoreBreakdown(
        total=total,
        known_attack_contribution=known_attack_contribution,
        anomaly_contribution=anomaly_contribution,
        behavior_contribution=behavior_contribution,
        protocol_signature_contribution=protocol_signature_contribution,
    )

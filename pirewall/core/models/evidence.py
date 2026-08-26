"""ML-produced evidence models (spec §14, §18).

These are evidence, never commands: nothing downstream may treat a
`KnownEvidence`/`AnomalyEvidence` instance as authorization to touch the
firewall directly (CLAUDE.md "ML produces evidence, never commands").
"""

from pydantic import AwareDatetime, Field

from pirewall.core.models.common import PirewallModel


class KnownEvidence(PirewallModel):
    """LightGBM known-attack classification output for one flow (spec §14)."""

    flow_id: str = Field(min_length=1)
    predicted_class: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    class_probabilities: dict[str, float] = Field(default_factory=dict)
    model_version: str = Field(min_length=1)
    feature_schema_version: str = Field(min_length=1)
    generated_at: AwareDatetime


class AnomalyEvidence(PirewallModel):
    """Isolation Forest anomaly-detection output for one flow (spec §14).

    An anomaly is evidence, not automatically malicious — `is_anomaly` is a
    thresholded convenience derived from `anomaly_score` vs `threshold`, it
    does not by itself imply any firewall action.
    """

    flow_id: str = Field(min_length=1)
    anomaly_score: float
    threshold: float
    is_anomaly: bool
    model_version: str = Field(min_length=1)
    feature_schema_version: str = Field(min_length=1)
    generated_at: AwareDatetime

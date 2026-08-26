"""The canonical `FeatureVector` domain model (spec §11, §15).

The actual feature names/ordering/schema version are frozen in Phase 3
(`pirewall.features.schema`); this model only fixes the *shape* every
producer (dataset preprocessing, training, runtime inference) must agree on.
"""

from pydantic import AwareDatetime, Field, model_validator

from pirewall.core.models.common import PirewallModel


class FeatureVector(PirewallModel):
    """A named, ordered, schema-versioned set of numeric features for one flow.

    `feature_names` and `values` must be the same length and are
    positionally aligned — this is what lets a model trained against one
    schema version detect a mismatch against a different runtime schema
    version (spec §15) before ever running inference.
    """

    flow_id: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    feature_names: tuple[str, ...] = Field(min_length=1)
    values: tuple[float, ...]
    computed_at: AwareDatetime

    @model_validator(mode="after")
    def _check_shape(self) -> "FeatureVector":
        if len(self.feature_names) != len(self.values):
            raise ValueError("feature_names and values must have the same length")
        if len(set(self.feature_names)) != len(self.feature_names):
            raise ValueError("feature_names must not contain duplicates")
        return self

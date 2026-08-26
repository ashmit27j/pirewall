"""The `ModelMetadata` domain model (spec §15, §16).

`is_placeholder`/`notes` are not in the original spec's field list but are
required by `CLAUDE.md`'s labeling-honesty rule: a model trained on
synthetic fixture data (e.g. because Phase 4 ran without real dataset files)
must be unmistakably marked as such everywhere its metadata is shown,
never presented as a real detection-performance result.
"""

from pydantic import AwareDatetime, Field

from pirewall.core.enums import ModelType
from pirewall.core.models.common import PirewallModel


class ModelMetadata(PirewallModel):
    """Everything needed to identify a model artifact and check compatibility at runtime.

    Runtime inference must refuse to run if its feature schema version does
    not exactly match `feature_schema_version` here (spec §15).
    """

    model_type: ModelType
    model_version: str = Field(min_length=1)
    training_dataset: str = Field(min_length=1)
    feature_schema_version: str = Field(min_length=1)
    feature_ordering: tuple[str, ...] = Field(min_length=1)
    training_timestamp: AwareDatetime
    class_mapping: dict[str, int] = Field(default_factory=dict)
    preprocessing_version: str = Field(min_length=1)
    evaluation_metrics: dict[str, float] = Field(default_factory=dict)

    is_placeholder: bool = False
    notes: str | None = None

"""Wires the three detection sources into one `DetectionRecord` (spec §14, §17).

The detection layer's single entry point for a completed flow. It owns the
loaded ML artifacts and the `BehaviorAnalyzer`, and answers exactly one
question: *what evidence exists about this flow?*

**It deliberately stops there.** No `ThreatAssessment`, no
`FirewallDecision`, no candidate rule, no backend call — those belong to
`pirewall.engine` and `pirewall.firewall`, which sit downstream of this
module in the dependency order `CLAUDE.md` fixes
(`detection -> engine -> firewall`). Importing `pirewall.engine` from here
would invert that. `pirewall.runtime.pipeline` is what carries this
module's output onward into the engine.

**Graceful degradation is the point of `ModelRegistry`.** ML artifacts are
gitignored and trained separately (spec §12/§35), so a freshly provisioned
Pi legitimately has no model files at all. Missing, unreadable, or
schema-incompatible artifacts must therefore degrade this layer to
behavior-only detection with a loud warning, never prevent pirewall-core
from starting: behavioral detection and the whole enforcement path stay
fully functional without either model.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pirewall.config.models import DetectionConfig, MLConfig
from pirewall.core.enums import EventSeverity, ModelType, SecurityEventType
from pirewall.core.exceptions import ModelInferenceError, ModelLoadError
from pirewall.core.models.behavior import BehaviorAssessment
from pirewall.core.models.detection_record import DetectionRecord
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence, ProtocolSignatureEvidence
from pirewall.core.models.feature_vector import FeatureVector
from pirewall.core.models.flow import Flow
from pirewall.detection.anomaly import detect as detect_anomaly
from pirewall.detection.behavior import BehaviorAnalyzer
from pirewall.detection.known_attack import classify as classify_known_attack
from pirewall.ml.inference.loader import (
    LoadedIsolationForestModel,
    LoadedLightGBMModel,
    load_isolation_forest_model,
    load_lightgbm_model,
)

_logger = logging.getLogger(__name__)
_SUBSYSTEM = "detection.coordinator"

EventSink = Callable[[SecurityEvent], None]

# A model that fails inference for one flow usually fails for every flow.
# Emitting a `SecurityEvent` per failure would flood the audit trail (and
# any Wazuh forwarder attached to it) at flow rate, so only the first and
# then every Nth failure per model produce an event. The failure *count* is
# always accurate — see `DetectionCoordinator.inference_failures`.
_INFERENCE_FAILURE_EVENT_INTERVAL = 100


@dataclass(frozen=True, slots=True)
class ModelRegistry:
    """The ML artifacts pirewall-core actually managed to load at startup.

    Either field being `None` is a supported operating state, not an error —
    see this module's docstring. `load_errors` carries one human-readable
    line per artifact that failed, so the caller can log precisely what is
    missing instead of a generic "ML unavailable".
    """

    lightgbm: LoadedLightGBMModel | None = None
    isolation_forest: LoadedIsolationForestModel | None = None
    load_errors: tuple[str, ...] = ()

    @property
    def any_loaded(self) -> bool:
        return self.lightgbm is not None or self.isolation_forest is not None


def load_models(config: MLConfig) -> ModelRegistry:
    """Load both ML artifacts, degrading to `None` for whichever one is unusable.

    Never raises. A missing file, an unreadable artifact, a missing metadata
    sidecar, and a feature-schema mismatch (spec §15) are all treated the
    same way: warn, record the reason in `load_errors`, and continue without
    that model.
    """
    errors: list[str] = []

    lightgbm: LoadedLightGBMModel | None = None
    try:
        lightgbm = load_lightgbm_model(Path(config.lightgbm_model_path))
    except (ModelLoadError, ModelInferenceError) as exc:
        errors.append(f"lightgbm: {exc}")
        _logger.warning(
            "LightGBM model unavailable, known-attack classification disabled: %s", exc
        )

    isolation_forest: LoadedIsolationForestModel | None = None
    try:
        isolation_forest = load_isolation_forest_model(Path(config.isolation_forest_model_path))
    except (ModelLoadError, ModelInferenceError) as exc:
        errors.append(f"isolation_forest: {exc}")
        _logger.warning("Isolation Forest model unavailable, anomaly detection disabled: %s", exc)

    if lightgbm is not None:
        _logger.info(
            "loaded LightGBM model version=%s schema=%s placeholder=%s",
            lightgbm.metadata.model_version,
            lightgbm.metadata.feature_schema_version,
            lightgbm.metadata.is_placeholder,
        )
    if isolation_forest is not None:
        _logger.info(
            "loaded Isolation Forest model version=%s schema=%s placeholder=%s",
            isolation_forest.metadata.model_version,
            isolation_forest.metadata.feature_schema_version,
            isolation_forest.metadata.is_placeholder,
        )
    return ModelRegistry(
        lightgbm=lightgbm, isolation_forest=isolation_forest, load_errors=tuple(errors)
    )


@dataclass(frozen=True, slots=True)
class DetectionOutcome:
    """Everything the detection layer knows about one completed flow.

    `record` is the ML half (either or both pieces of evidence may be
    `None`); `behavior` is the deterministic half, `None` only if the
    analyzer has no state for this flow's source — which cannot happen when
    `DetectionCoordinator.analyze` produced it, since it observes the flow
    first.
    """

    record: DetectionRecord
    behavior: BehaviorAssessment | None


def with_anomaly_evidence(
    outcome: DetectionOutcome, anomaly_evidence: AnomalyEvidence | None
) -> DetectionOutcome:
    """Attach anomaly evidence to an outcome produced by `DetectionCoordinator.analyze_except_anomaly`.

    Pure data combination, no coordinator state needed — a caller that
    scored anomaly evidence separately (batched, ADDENDUM_2 follow-up pass
    section 3) uses this to fold the result back in before the outcome
    continues through `pirewall.engine.threat.assess_threat`.
    """
    return DetectionOutcome(
        record=outcome.record.model_copy(update={"anomaly_evidence": anomaly_evidence}),
        behavior=outcome.behavior,
    )


class DetectionCoordinator:
    """Runs every available detector over one flow and pairs up the results."""

    def __init__(
        self,
        detection_config: DetectionConfig,
        models: ModelRegistry,
        on_event: EventSink | None = None,
        behavior_analyzer: BehaviorAnalyzer | None = None,
    ) -> None:
        self._config = detection_config
        self._models = models
        self._on_event = on_event
        self._behavior = behavior_analyzer or BehaviorAnalyzer(detection_config)
        self._inference_failures: dict[ModelType, int] = {
            ModelType.LIGHTGBM: 0,
            ModelType.ISOLATION_FOREST: 0,
        }

    @property
    def models(self) -> ModelRegistry:
        return self._models

    @property
    def behavior_analyzer(self) -> BehaviorAnalyzer:
        """Exposed so the runtime can report how many sources are being tracked."""
        return self._behavior

    @property
    def inference_failures(self) -> dict[ModelType, int]:
        """Total per-model inference failures since startup (not just the ones that emitted events)."""
        return dict(self._inference_failures)

    def analyze(
        self,
        flow: Flow,
        features: FeatureVector,
        now: datetime,
        protocol_signature: ProtocolSignatureEvidence | None = None,
    ) -> DetectionOutcome:
        """Observe `flow`, run every available detector, and return the combined evidence.

        Never raises for a detector-level failure: an inference error
        degrades that one evidence field to `None` (and emits a
        `MODEL_ERROR` event) rather than losing the flow entirely. Behavior
        analysis is deterministic and has no external dependency, so it
        always contributes.

        Only folds in this flow's *completion* signal (ADDENDUM_2.md B1) —
        the *creation*-time volumetric signals were already folded in when
        this flow was opened, via `pirewall.runtime.core.CoreDaemon` calling
        `behavior_analyzer.observe_new_connection` directly from the capture
        path. Calling `observe_flow` here instead would double-count every
        real flow's connection.

        `protocol_signature` (ADDENDUM_2.md B4/B5) is computed upstream, not
        here — `pirewall.runtime.core.CoreDaemon` inspects raw TCP payload
        bytes for this flow's key while the connection is still open (this
        module never sees payload bytes, only already-aggregated `Flow`/
        `FeatureVector` data) and hands the result in at completion time.
        This module's only job for it is to embed it in the combined
        `DetectionRecord`, the same passthrough role it already plays for
        `known`/`anomaly` evidence computed by other modules.

        Scores anomaly evidence inline, synchronously, one flow at a time —
        use `analyze_except_anomaly` instead when the caller batches
        Isolation Forest scoring across many flows (ADDENDUM_2 follow-up
        pass, section 3; `pirewall.runtime.core.CoreDaemon`'s dedicated
        anomaly-inference thread).
        """
        outcome = self.analyze_except_anomaly(flow, features, now, protocol_signature)
        anomaly = self._detect_anomaly(features, now)
        return with_anomaly_evidence(outcome, anomaly)

    def analyze_except_anomaly(
        self,
        flow: Flow,
        features: FeatureVector,
        now: datetime,
        protocol_signature: ProtocolSignatureEvidence | None = None,
    ) -> DetectionOutcome:
        """Everything `analyze` does except Isolation Forest scoring — `anomaly_evidence` is
        always `None` on the returned outcome's record.

        For callers that batch anomaly scoring across many flows instead of
        scoring inline per flow (ADDENDUM_2 follow-up pass, section 3):
        attach the real evidence afterward with `with_anomaly_evidence`.
        Folds in this flow's completion signal into `BehaviorAnalyzer`
        exactly once either way — `analyze` calling this and doing nothing
        else with `BehaviorAnalyzer` is what keeps that guarantee true
        regardless of which entry point a caller uses.
        """
        self._behavior.observe_completion(flow)
        known = self._classify_known(features, now)
        record = DetectionRecord(
            flow_id=flow.flow_id,
            known_evidence=known,
            anomaly_evidence=None,
            protocol_signature_evidence=protocol_signature,
            recorded_at=now,
        )
        return DetectionOutcome(record=record, behavior=self._behavior.assess(flow.source_ip))

    def _classify_known(self, features: FeatureVector, now: datetime) -> KnownEvidence | None:
        model = self._models.lightgbm
        if model is None:
            return None
        try:
            return classify_known_attack(model, features, now)
        except (ModelInferenceError, ValueError) as exc:
            self._report_inference_failure(ModelType.LIGHTGBM, features.flow_id, now, exc)
            return None

    def _detect_anomaly(self, features: FeatureVector, now: datetime) -> AnomalyEvidence | None:
        model = self._models.isolation_forest
        if model is None:
            return None
        try:
            return detect_anomaly(model, features, self._config.anomaly_score_threshold, now)
        except (ModelInferenceError, ValueError) as exc:
            self._report_inference_failure(ModelType.ISOLATION_FOREST, features.flow_id, now, exc)
            return None

    def _report_inference_failure(
        self, model_type: ModelType, flow_id: str, now: datetime, exc: Exception
    ) -> None:
        count = self._inference_failures[model_type] + 1
        self._inference_failures[model_type] = count
        _logger.warning("%s inference failed for flow %s: %s", model_type.value, flow_id, exc)
        if self._on_event is None:
            return
        if count != 1 and count % _INFERENCE_FAILURE_EVENT_INTERVAL != 0:
            return
        self._on_event(
            SecurityEvent(
                timestamp=now,
                severity=EventSeverity.ERROR,
                event_type=SecurityEventType.MODEL_ERROR,
                subsystem=_SUBSYSTEM,
                flow_id=flow_id,
                reason=f"{model_type.value} inference failed ({count} total): {exc}",
            )
        )

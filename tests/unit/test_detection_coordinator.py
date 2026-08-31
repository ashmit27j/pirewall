"""`pirewall.detection.coordinator` — graceful ML degradation and evidence pairing (spec §14, §15).

ML artifacts are gitignored and trained separately, so a freshly
provisioned Pi legitimately has no model files. The load path must degrade
to behaviour-only detection with a warning, never prevent pirewall-core
from starting — and the analyze path must survive an inference failure
mid-run without losing the flow.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from pirewall.config.models import MLConfig
from pirewall.core.enums import ModelType, SecurityEventType
from pirewall.core.exceptions import ModelInferenceError
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.evidence import AnomalyEvidence
from pirewall.core.models.feature_vector import FeatureVector
from pirewall.detection.coordinator import (
    DetectionCoordinator,
    ModelRegistry,
    load_models,
    with_anomaly_evidence,
)
from pirewall.features.extractor import extract_features
from pirewall.ml.inference.loader import load_isolation_forest_model
from pirewall.ml.preprocessing.common import LabeledFlow
from pirewall.ml.training.isolation_forest_trainer import (
    save_isolation_forest_artifact,
    train_isolation_forest,
)
from tests.helpers.config import make_config
from tests.helpers.flows import make_flow

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_missing_model_files_degrade_instead_of_raising() -> None:
    """A Pi with no trained artifacts must still start (CLAUDE.md honesty: no fabricated scores)."""
    registry = load_models(
        MLConfig(
            lightgbm_model_path="/nonexistent/lightgbm_model.txt",
            isolation_forest_model_path="/nonexistent/isolation_forest.joblib",
        )
    )
    assert registry.lightgbm is None
    assert registry.isolation_forest is None
    assert registry.any_loaded is False
    assert len(registry.load_errors) == 2
    # The reason has to be actionable, not just "ML unavailable".
    assert any("lightgbm" in error for error in registry.load_errors)
    assert any("isolation_forest" in error for error in registry.load_errors)


def test_analysis_without_models_still_produces_behaviour_evidence() -> None:
    config = make_config()
    coordinator = DetectionCoordinator(config.detection, ModelRegistry())
    flow = make_flow()

    outcome = coordinator.analyze(flow, extract_features(flow), NOW)

    assert outcome.record.flow_id == flow.flow_id
    assert outcome.record.known_evidence is None
    assert outcome.record.anomaly_evidence is None
    # Behaviour analysis is deterministic and has no external dependency,
    # so it contributes even with both models absent.
    assert outcome.behavior is not None
    assert outcome.behavior.source_ip == flow.source_ip


def test_the_flow_is_observed_by_the_behaviour_analyzer() -> None:
    config = make_config()
    coordinator = DetectionCoordinator(config.detection, ModelRegistry())
    assert len(coordinator.behavior_analyzer) == 0

    flow = make_flow()
    coordinator.analyze(flow, extract_features(flow), NOW)

    assert len(coordinator.behavior_analyzer) == 1


class _ExplodingModel:
    """Stands in for a loaded model whose inference call fails at runtime."""

    metadata: Any = None


def test_inference_failure_degrades_that_evidence_and_reports_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One model blowing up must cost that evidence field, not the whole flow."""

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise ModelInferenceError("feature schema drifted")

    monkeypatch.setattr("pirewall.detection.coordinator.classify_known_attack", _boom)
    events: list[SecurityEvent] = []
    config = make_config()
    coordinator = DetectionCoordinator(
        config.detection,
        # `_ExplodingModel` only has to be non-None: the patched classifier
        # raises before anything reads it.
        ModelRegistry(lightgbm=_ExplodingModel()),  # pyright: ignore[reportArgumentType]
        on_event=events.append,
    )
    flow = make_flow()

    outcome = coordinator.analyze(flow, extract_features(flow), NOW)

    assert outcome.record.known_evidence is None
    assert outcome.behavior is not None  # the flow was NOT lost
    assert coordinator.inference_failures[ModelType.LIGHTGBM] == 1
    assert [event.event_type for event in events] == [SecurityEventType.MODEL_ERROR]
    assert "feature schema drifted" in (events[0].reason or "")


def test_repeated_inference_failures_are_counted_but_not_flooded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken model fails for every flow; one event per flow would evict the audit trail."""

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise ModelInferenceError("still broken")

    monkeypatch.setattr("pirewall.detection.coordinator.classify_known_attack", _boom)
    events: list[SecurityEvent] = []
    config = make_config()
    coordinator = DetectionCoordinator(
        config.detection,
        ModelRegistry(lightgbm=_ExplodingModel()),  # pyright: ignore[reportArgumentType]
        on_event=events.append,
    )

    features: FeatureVector = extract_features(make_flow())
    for _ in range(20):
        coordinator.analyze(make_flow(), features, NOW)

    assert coordinator.inference_failures[ModelType.LIGHTGBM] == 20
    assert len(events) == 1  # first failure only, until the 100th


def test_analyze_except_anomaly_never_scores_anomaly_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ADDENDUM_2 follow-up pass, section 3: this is the entry point batched callers use
    instead of `analyze` — it must never touch the anomaly detector at all, regardless of
    whether an Isolation Forest model is loaded, so a caller batching scores elsewhere never
    pays for (or races) a second, inline score for the same flow.
    """

    def _must_not_be_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("analyze_except_anomaly must never score anomaly evidence")

    monkeypatch.setattr("pirewall.detection.coordinator.detect_anomaly", _must_not_be_called)
    config = make_config()
    coordinator = DetectionCoordinator(
        config.detection,
        ModelRegistry(isolation_forest=_ExplodingModel()),  # pyright: ignore[reportArgumentType]
    )
    flow = make_flow()

    outcome = coordinator.analyze_except_anomaly(flow, extract_features(flow), NOW)

    assert outcome.record.anomaly_evidence is None


def test_with_anomaly_evidence_attaches_evidence_without_changing_anything_else() -> None:
    config = make_config()
    coordinator = DetectionCoordinator(config.detection, ModelRegistry())
    flow = make_flow()
    outcome = coordinator.analyze_except_anomaly(flow, extract_features(flow), NOW)
    evidence = AnomalyEvidence(
        flow_id=flow.flow_id,
        anomaly_score=-0.5,
        threshold=0.0,
        is_anomaly=True,
        model_version="1.0.0",
        feature_schema_version="1.0.0",
        generated_at=NOW,
    )

    combined = with_anomaly_evidence(outcome, evidence)

    assert combined.record.anomaly_evidence == evidence
    assert combined.record.known_evidence == outcome.record.known_evidence
    assert combined.record.flow_id == outcome.record.flow_id
    assert combined.behavior == outcome.behavior


def test_analyze_equals_analyze_except_anomaly_plus_with_anomaly_evidence(tmp_path: Path) -> None:
    """The split introduced for batched scoring (ADDENDUM_2 follow-up pass, section 3) must be
    behavior-preserving. `analyze` is defined in terms of these two pieces internally, but this
    pins the equivalence directly against a real trained model rather than trusting it by
    inspection.
    """
    flows = [LabeledFlow(flow=make_flow(flow_id=f"benign-{i}"), label="BENIGN") for i in range(20)]
    result = train_isolation_forest(
        flows,
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
    )
    model_path = save_isolation_forest_artifact(result, tmp_path)
    isolation_forest = load_isolation_forest_model(model_path)
    config = make_config()
    flow = make_flow(flow_id="target")
    features = extract_features(flow)

    combined_coordinator = DetectionCoordinator(
        config.detection, ModelRegistry(isolation_forest=isolation_forest)
    )
    combined_outcome = combined_coordinator.analyze(flow, features, NOW)

    # A fresh coordinator (fresh BehaviorAnalyzer state) so the split path's own
    # `observe_completion` call doesn't double-count this flow against the combined run above.
    split_coordinator = DetectionCoordinator(
        config.detection, ModelRegistry(isolation_forest=isolation_forest)
    )
    partial = split_coordinator.analyze_except_anomaly(flow, features, NOW)
    anomaly = split_coordinator._detect_anomaly(features, NOW)  # pyright: ignore[reportPrivateUsage]
    split_outcome = with_anomaly_evidence(partial, anomaly)

    assert combined_outcome.record == split_outcome.record
    assert combined_outcome.behavior == split_outcome.behavior

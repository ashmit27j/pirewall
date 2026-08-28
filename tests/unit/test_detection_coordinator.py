"""`pirewall.detection.coordinator` — graceful ML degradation and evidence pairing (spec §14, §15).

ML artifacts are gitignored and trained separately, so a freshly
provisioned Pi legitimately has no model files. The load path must degrade
to behaviour-only detection with a warning, never prevent pirewall-core
from starting — and the analyze path must survive an inference failure
mid-run without losing the flow.
"""

from datetime import UTC, datetime
from typing import Any

import pytest

from pirewall.config.models import MLConfig
from pirewall.core.enums import ModelType, SecurityEventType
from pirewall.core.exceptions import ModelInferenceError
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.feature_vector import FeatureVector
from pirewall.detection.coordinator import DetectionCoordinator, ModelRegistry, load_models
from pirewall.features.extractor import extract_features
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

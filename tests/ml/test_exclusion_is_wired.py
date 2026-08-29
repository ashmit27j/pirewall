"""The rare-class exclusion policy is actually *applied*, not merely defined.

This file exists because of a real regression: `is_excluded_from_supervised
_training` was implemented, unit-tested and documented as "the single shared
function both training and evaluation call" — while having **zero**
production callers. Model v0.3.0 was trained with 7 Heartbleed, 15 SQL
Injection and 26 Infiltration rows in its training set as a result.

Unit-testing the predicate cannot catch that. These tests drive the real
trainer end to end and assert on what actually reached the booster.
"""

from datetime import UTC, datetime

import pytest

from pirewall.ml.labels import is_excluded_from_supervised_training
from pirewall.ml.preprocessing.common import LabeledFlow
from pirewall.ml.training.lightgbm_trainer import train_lightgbm
from tests.helpers.flows import make_flow

NOW = datetime(2026, 1, 1, tzinfo=UTC)
RARE = "Heartbleed"  # 11 real examples in CICIDS2017 — below the threshold


def _corpus(rare_count: int = 4) -> list[LabeledFlow]:
    """A corpus with two well-populated classes and one ultra-rare one."""
    flows: list[LabeledFlow] = []
    for i in range(120):
        flows.append(LabeledFlow(flow=make_flow(flow_id=f"b-{i}"), label="BENIGN"))
    for i in range(120):
        flows.append(
            LabeledFlow(
                flow=make_flow(
                    flow_id=f"a-{i}",
                    packet_count=2000,
                    byte_count=200_000,
                    forward_packet_count=1900,
                    backward_packet_count=100,
                    forward_byte_count=190_000,
                    backward_byte_count=10_000,
                    duration_seconds=1.0,
                ),
                label="DDoS",
            )
        )
    for i in range(rare_count):
        flows.append(
            LabeledFlow(
                flow=make_flow(
                    flow_id=f"r-{i}",
                    packet_count=7,
                    byte_count=900,
                    forward_packet_count=4,
                    backward_packet_count=3,
                    forward_byte_count=500,
                    backward_byte_count=400,
                    duration_seconds=0.4,
                ),
                label=RARE,
            )
        )
    return flows


def _train(**kwargs: object):
    return train_lightgbm(
        _corpus(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes="NOT trained on real data",
        **kwargs,  # pyright: ignore[reportArgumentType]
    )


def test_the_fixture_class_is_actually_covered_by_the_policy() -> None:
    """Guard the guard: if the policy stopped covering it, the rest is vacuous."""
    assert is_excluded_from_supervised_training(RARE) is True


def test_excluded_class_never_becomes_a_predictable_output() -> None:
    """The booster must not be able to emit a class it was never trained on."""
    result = _train()

    assert RARE not in result.class_mapping
    assert result.excluded_labels == (RARE,)
    assert set(result.class_mapping) == {"BENIGN", "DDoS"}


def test_excluded_class_still_appears_in_the_evaluation_report() -> None:
    """Withheld from training is not the same as deleted from evaluation."""
    result = _train()

    assert RARE in result.per_class
    assert RARE in result.confusion_matrix
    # It is in the test split, so it has real support there.
    assert sum(result.confusion_matrix[RARE].values()) > 0


def test_excluded_class_is_left_out_of_macro_f1() -> None:
    """macro-F1 averages the trained classes only, not a class never taught."""
    result = _train()

    trained_f1 = [result.per_class[label]["f1"] for label in result.class_mapping]
    assert result.macro_f1 == pytest.approx(sum(trained_f1) / len(trained_f1))


def test_disabling_the_policy_puts_the_rare_class_back_in_training() -> None:
    """The opposite branch, so a no-op implementation cannot pass this file.

    Without this, an `exclude_rare_classes` flag that silently did nothing
    would still satisfy every assertion above if the fixture happened to
    place the rare rows outside the training split.
    """
    included = _train(exclude_rare_classes=False)

    assert RARE in included.class_mapping
    assert included.excluded_labels == ()


def test_exclusion_changes_the_trained_class_count() -> None:
    """End-to-end proof the flag reaches the booster, not just the result object."""
    excluded = _train()
    included = _train(exclude_rare_classes=False)

    assert len(included.class_mapping) == len(excluded.class_mapping) + 1
    assert excluded.booster.num_model_per_iteration() < included.booster.num_model_per_iteration()

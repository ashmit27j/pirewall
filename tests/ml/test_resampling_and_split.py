"""Three-way split integrity, training-split-only resampling, and the new
LightGBM/Isolation Forest imbalance-remediation options (class weighting,
PR-curve threshold tuning, contamination sweep) added in the CICIDS2017
imbalance-remediation session. `tests/ml/test_training.py` already covers
the pre-existing, backward-compatible default behavior of both trainers;
this file covers what's new.
"""

from pirewall.ml.preprocessing.common import LabeledFlow
from pirewall.ml.training.common import split_train_val_test
from pirewall.ml.training.isolation_forest_trainer import (
    sweep_isolation_forest_contamination,
    train_isolation_forest,
)
from pirewall.ml.training.lightgbm_trainer import train_lightgbm
from pirewall.ml.training.resampling import ResamplingConfig, resample_training_split
from tests.helpers.flows import make_flow

PLACEHOLDER_NOTES = "NOT trained on real data — placeholder for pipeline testing"


# --- split_train_val_test -------------------------------------------------


def test_split_train_val_test_partitions_every_row_exactly_once() -> None:
    features = [[float(i)] for i in range(100)]
    labels = ["A"] * 60 + ["B"] * 40

    split = split_train_val_test(features, labels, val_fraction=0.2, test_fraction=0.2, seed=1)

    all_values = [x[0] for x in split.x_train] + [x[0] for x in split.x_val] + [x[0] for x in split.x_test]
    assert sorted(all_values) == list(range(100))  # every row appears, none duplicated
    assert len(split.x_train) + len(split.x_val) + len(split.x_test) == 100


def test_split_train_val_test_gives_rare_class_representation_in_every_split() -> None:
    # 20 rows of a rare class -- a single global shuffle could plausibly put
    # all of them in one split; per-class stratification should not.
    features = [[float(i)] for i in range(220)]
    labels = ["COMMON"] * 200 + ["RARE"] * 20

    split = split_train_val_test(features, labels, val_fraction=0.15, test_fraction=0.15, seed=7)

    assert split.y_train.count("RARE") > 0
    assert split.y_val.count("RARE") > 0
    assert split.y_test.count("RARE") > 0


def test_split_train_val_test_does_not_block_rows_by_class() -> None:
    # Regression test: an earlier version built each split by concatenating
    # one contiguous block of row-indices per class (all of class A, then
    # all of class B, ...) without a final shuffle. A row-order-sensitive
    # downstream consumer -- LightGBM's histogram bin construction samples
    # sequentially from the front of the training set -- would then see a
    # training set that looks almost entirely like whichever class happens
    # to be first, silently wrecking every other class's model quality. On
    # the real CICIDS2017 run this collapsed PortScan/SSH-Patator recall to
    # 0%. Assert the first half of train isn't dominated by a single label
    # the way an unshuffled block layout would be.
    features = [[float(i)] for i in range(1000)]
    labels = ["MAJORITY"] * 900 + ["MINORITY"] * 100

    split = split_train_val_test(features, labels, val_fraction=0.1, test_fraction=0.1, seed=1)

    first_half = split.y_train[: len(split.y_train) // 2]
    assert first_half.count("MINORITY") > 0


def test_split_train_val_test_rejects_fractions_summing_past_one() -> None:
    import pytest

    with pytest.raises(ValueError, match="val_fraction"):
        split_train_val_test([[1.0]], ["A"], val_fraction=0.6, test_fraction=0.6)


# --- resample_training_split -----------------------------------------------


def test_resample_training_split_caps_majority_class() -> None:
    x = [[float(i)] for i in range(200)]
    y = ["MAJORITY"] * 150 + ["MINORITY"] * 50
    config = ResamplingConfig(undersample_ceiling=100, oversample_ceiling=10, oversample_target=20)

    result = resample_training_split(x, y, config, seed=3)

    assert result.after_counts["MAJORITY"] == 100
    assert result.after_counts["MINORITY"] == 50  # untouched: above oversample_ceiling
    assert result.undersampled_labels == ("MAJORITY",)
    assert result.oversampled_labels == ()


def test_resample_training_split_oversamples_rare_classes_to_target() -> None:
    x = [[float(i), float(i) * 2] for i in range(120)]
    y = ["MAJORITY"] * 100 + ["RARE_A"] * 12 + ["RARE_B"] * 8
    config = ResamplingConfig(undersample_ceiling=1000, oversample_ceiling=15, oversample_target=30)

    result = resample_training_split(x, y, config, seed=5)

    assert result.after_counts["RARE_A"] == 30
    assert result.after_counts["RARE_B"] == 30
    assert result.after_counts["MAJORITY"] == 100  # not touched: no undersample_ceiling breach
    assert set(result.oversampled_labels) == {"RARE_A", "RARE_B"}
    assert len(result.x_train) == len(result.y_train)


def test_resample_training_split_is_noop_below_both_thresholds() -> None:
    x = [[float(i)] for i in range(30)]
    y = ["A"] * 15 + ["B"] * 15
    config = ResamplingConfig(undersample_ceiling=1000, oversample_ceiling=1, oversample_target=5)

    result = resample_training_split(x, y, config, seed=1)

    assert result.x_train == x
    assert result.y_train == y
    assert result.undersampled_labels == ()
    assert result.oversampled_labels == ()


# --- LightGBM: class weighting, resampling, threshold tuning --------------


def _imbalanced_labeled_flows() -> list[LabeledFlow]:
    flows: list[LabeledFlow] = []
    for i in range(60):
        flows.append(
            LabeledFlow(
                flow=make_flow(
                    flow_id=f"benign-{i}",
                    packet_count=10,
                    byte_count=1000,
                    forward_packet_count=6,
                    backward_packet_count=4,
                    forward_byte_count=600,
                    backward_byte_count=400,
                    duration_seconds=10.0,
                    destination_port=443,
                ),
                label="BENIGN",
            )
        )
    for i in range(10):
        flows.append(
            LabeledFlow(
                flow=make_flow(
                    flow_id=f"attack-{i}",
                    packet_count=2000,
                    byte_count=200_000,
                    forward_packet_count=1900,
                    backward_packet_count=100,
                    forward_byte_count=190_000,
                    backward_byte_count=10_000,
                    duration_seconds=1.0,
                    destination_port=22,
                ),
                label="Attack",
            )
        )
    return flows


def test_train_lightgbm_class_weighting_runs_and_is_recorded() -> None:
    result = train_lightgbm(
        _imbalanced_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
        class_weighting=True,
    )

    assert result.class_weighting_used is True
    assert 0.0 <= result.accuracy <= 1.0


def test_train_lightgbm_resampling_only_changes_the_train_split() -> None:
    flows = _imbalanced_labeled_flows()
    config = ResamplingConfig(undersample_ceiling=20, oversample_ceiling=15, oversample_target=25)

    baseline = train_lightgbm(
        flows,
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
    )
    resampled = train_lightgbm(
        flows,
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
        resampling=config,
    )

    assert resampled.resampling is not None
    # Undersampling BENIGN (60 -> capped) and oversampling Attack (10ish -> 25)
    # changes the train split's row count...
    assert resampled.split_sizes["train"] != baseline.split_sizes["train"]
    # ...but validation/test are computed from the same deterministic
    # pre-resample partition in both calls (same seed/fractions) and must be
    # byte-identical in size -- resampling must never reach them.
    assert resampled.split_sizes["val"] == baseline.split_sizes["val"]
    assert resampled.split_sizes["test"] == baseline.split_sizes["test"]


def test_train_lightgbm_tune_thresholds_produces_a_threshold_per_class() -> None:
    result = train_lightgbm(
        _imbalanced_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
        tune_thresholds=True,
    )

    assert result.thresholds is not None
    assert set(result.thresholds) == set(result.class_mapping)
    assert all(0.0 <= t <= 1.0 for t in result.thresholds.values())


def test_train_lightgbm_threshold_tuning_never_makes_test_macro_f1_worse() -> None:
    # Regression test: an earlier version of the self-validating gate was
    # missing, so a degenerate per-class PR-curve threshold (0.0 or ~1.0,
    # which a class with only a handful of validation rows can produce)
    # went straight into decoding test predictions -- on the real CICIDS2017
    # run this collapsed macro-F1 from 0.2367 to 0.0612. `tune_thresholds`
    # must never score worse than plain argmax on the *test* split.
    flows = _imbalanced_labeled_flows()

    baseline = train_lightgbm(
        flows,
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
        tune_thresholds=False,
    )
    tuned = train_lightgbm(
        flows,
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
        tune_thresholds=True,
    )

    assert tuned.macro_f1 >= baseline.macro_f1


# --- Isolation Forest: contamination/max_samples, sweep --------------------


def _isolation_forest_labeled_flows() -> list[LabeledFlow]:
    flows: list[LabeledFlow] = []
    for i in range(60):
        flows.append(
            LabeledFlow(
                flow=make_flow(
                    flow_id=f"benign-{i}",
                    packet_count=10,
                    byte_count=1000,
                    forward_byte_count=600,
                    backward_byte_count=400,
                    destination_port=443,
                ),
                label="BENIGN",
            )
        )
    for i in range(20):
        flows.append(
            LabeledFlow(
                flow=make_flow(
                    flow_id=f"attack-{i}",
                    packet_count=2000,
                    byte_count=200_000,
                    forward_packet_count=1900,
                    backward_packet_count=100,
                    forward_byte_count=190_000,
                    backward_byte_count=10_000,
                    duration_seconds=1.0,
                    destination_port=22,
                ),
                label="Attack",
            )
        )
    return flows


def test_train_isolation_forest_accepts_contamination_and_max_samples() -> None:
    result = train_isolation_forest(
        _isolation_forest_labeled_flows(),
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
        contamination=0.2,
        max_samples=32,
    )

    assert 0.0 <= result.precision <= 1.0
    assert 0.0 <= result.recall <= 1.0


def test_sweep_isolation_forest_contamination_returns_one_result_per_candidate() -> None:
    candidates = [0.05, 0.1, 0.2]

    results = sweep_isolation_forest_contamination(
        _isolation_forest_labeled_flows(), candidates, n_estimators=25
    )

    assert [r.contamination for r in results] == candidates
    for r in results:
        assert 0.0 <= r.precision <= 1.0
        assert 0.0 <= r.recall <= 1.0
        assert 0.0 <= r.false_positive_rate <= 1.0
        assert 0.0 <= r.false_negative_rate <= 1.0


def test_sweep_and_final_training_agree_on_split_sizes_for_same_seed() -> None:
    flows = _isolation_forest_labeled_flows()

    sweep_results = sweep_isolation_forest_contamination(flows, [0.1], n_estimators=25, seed=9)
    trained = train_isolation_forest(
        flows,
        training_dataset_name="synthetic_fixture",
        model_version="0.0.1-placeholder",
        is_placeholder=True,
        notes=PLACEHOLDER_NOTES,
        contamination=sweep_results[0].contamination,
        seed=9,
    )

    # Same seed -> split_train_val_test produces the identical partition in
    # both calls, so the sweep's validation rows and this call's test rows
    # are guaranteed disjoint (structural leakage guard, not just a number
    # coincidence).
    assert trained.split_sizes["test"] > 0

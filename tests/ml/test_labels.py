"""`pirewall.ml.labels` — attack interpretation and the rare-class exclusion policy."""

import pytest

from pirewall.ml.labels import (
    MIN_SUPERVISED_TRAINING_EXAMPLES,
    is_attack_label,
    is_excluded_from_supervised_training,
    normalize_label,
)

# Real CICIDS2017 totals across all 8 files (docs/ML_DATA_AUDIT.md §C).
# The distribution's break is between 36 and 652.
REAL_COUNTS = {
    "Heartbleed": 11,
    "Web Attack � Sql Injection": 21,
    "Infiltration": 36,
    "Web Attack � XSS": 652,
    "Web Attack � Brute Force": 1_507,
    "Bot": 1_966,
    "DoS Slowhttptest": 5_499,
    "DoS slowloris": 5_796,
    "SSH-Patator": 5_897,
    "FTP-Patator": 7_938,
    "DoS GoldenEye": 10_293,
    "DDoS": 128_027,
    "PortScan": 158_930,
    "DoS Hulk": 231_073,
    "BENIGN": 2_272_982,
}


@pytest.mark.parametrize("label", ["BENIGN", "benign", "  Normal  ", "NORMAL"])
def test_benign_labels_are_not_attacks(label: str) -> None:
    assert is_attack_label(label) is False


@pytest.mark.parametrize("label", ["DDoS", "Heartbleed", "Bot", "PortScan"])
def test_everything_else_is_an_attack(label: str) -> None:
    assert is_attack_label(label) is True


class TestExclusionPolicy:
    @pytest.mark.parametrize(
        "label", ["Heartbleed", "Web Attack � Sql Injection", "Infiltration"]
    )
    def test_the_three_ultra_rare_classes_are_excluded(self, label: str) -> None:
        assert is_excluded_from_supervised_training(label) is True

    @pytest.mark.parametrize(
        "label",
        ["BENIGN", "DDoS", "PortScan", "DoS Hulk", "Bot",
         "Web Attack � XSS", "Web Attack � Brute Force", "SSH-Patator"],
    )
    def test_everything_with_enough_examples_is_kept(self, label: str) -> None:
        assert is_excluded_from_supervised_training(label) is False

    def test_policy_matches_the_real_counts_at_the_threshold(self) -> None:
        """The excluded set is exactly the classes below the threshold."""
        for label, count in REAL_COUNTS.items():
            expected = count < MIN_SUPERVISED_TRAINING_EXAMPLES
            assert is_excluded_from_supervised_training(label) is expected, label

    def test_boundary_just_below_and_just_above_the_break(self) -> None:
        """Infiltration (36) is out; Web Attack XSS (652) is the next one up and stays in."""
        assert REAL_COUNTS["Infiltration"] < MIN_SUPERVISED_TRAINING_EXAMPLES
        assert REAL_COUNTS["Web Attack � XSS"] > MIN_SUPERVISED_TRAINING_EXAMPLES
        assert is_excluded_from_supervised_training("Infiltration") is True
        assert is_excluded_from_supervised_training("Web Attack � XSS") is False

    def test_threshold_sits_inside_the_gap_so_the_choice_is_robust(self) -> None:
        """Any cutoff between 37 and 652 selects the same three classes.

        This is what makes the threshold a reading of the distribution
        rather than an arbitrary constant.
        """
        below = max(c for c in REAL_COUNTS.values() if c < MIN_SUPERVISED_TRAINING_EXAMPLES)
        above = min(c for c in REAL_COUNTS.values() if c > MIN_SUPERVISED_TRAINING_EXAMPLES)
        assert below == 36
        assert above == 652
        assert below < MIN_SUPERVISED_TRAINING_EXAMPLES < above

    @pytest.mark.parametrize(
        "variant",
        [
            "Web Attack � Sql Injection",  # as published (U+FFFD)
            "Web Attack - Sql Injection",  # hyphen
            "Web Attack – Sql Injection",  # noqa: RUF001 - en dash is the point
            "web attack sql injection",  # already normalised
            "  Web Attack � Sql Injection  ",  # padded
        ],
    )
    def test_exclusion_survives_the_label_encoding_variants(self, variant: str) -> None:
        """An encoding difference must not silently re-admit an excluded class."""
        assert is_excluded_from_supervised_training(variant) is True

    def test_excluded_classes_are_still_attacks(self) -> None:
        """Excluding from training must never be confused with relabelling benign."""
        for label in ("Heartbleed", "Infiltration", "Web Attack � Sql Injection"):
            assert is_attack_label(label) is True


def test_normalize_label_collapses_punctuation_and_case() -> None:
    assert normalize_label("Web Attack � XSS") == "web attack xss"
    assert normalize_label("  DoS   slowloris ") == "dos slowloris"
    assert normalize_label("FTP-Patator") == "ftp patator"

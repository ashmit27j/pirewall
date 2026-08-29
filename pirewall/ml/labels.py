"""Dataset-agnostic interpretation of a classifier's predicted-class label.

A dataset adapter's label strings are dataset-specific ("BENIGN" for
CICIDS2017, "Normal" for UNSW-NB15) — this is the single place that maps
any of them to "is this actually an attack?", shared by training-time
evaluation (`pirewall.ml.training.metrics`) and runtime detection
(`pirewall.detection.known_attack`) so the two can never disagree.

It is also the single home for the **rare-class exclusion policy**: which
attack classes carry too few real examples to be a supervised training
target at all. Both the trainer and every evaluation path must call
`is_excluded_from_supervised_training` rather than keeping their own copy
of the list (see `docs/ML_DATA_AUDIT.md` for the measured counts).
"""

import re

_BENIGN_LABELS = frozenset({"benign", "normal"})


def is_attack_label(label: str) -> bool:
    """True unless `label` is a known benign/normal label (case-insensitive)."""
    return label.strip().lower() not in _BENIGN_LABELS


# --- Rare-class exclusion policy (docs/ML_DATA_AUDIT.md §C) ---------------
#
# Minimum total examples (train+val+test combined) a class needs before it
# is worth training a supervised classifier to predict it.
#
# This number is read off the real CICIDS2017 distribution rather than
# picked a priori. Measured totals across all 8 files, ascending:
#
#     Heartbleed                    11
#     Web Attack - Sql Injection    21
#     Infiltration                  36
#     ---------------------------------  <-- 18x gap
#     Web Attack - XSS             652
#     Web Attack - Brute Force   1,507
#     Bot                        1,966
#     DoS Slowhttptest           5,499
#     ... (everything else larger)
#
# The distribution breaks hard between 36 and 652 — an 18x jump. Any
# threshold in that range selects exactly the same three classes, so this
# cutoff is robust rather than knife-edge. 100 is chosen inside the gap
# because it is also where the split stops being meaningful: with the
# project's 70/15/15 split, 100 total examples still leaves ~70 training
# and ~15 test rows, and below that a per-class recall figure has no
# resolution worth reporting (Heartbleed lands 2 rows in test).
#
# Excluded classes are NOT benign and are NOT deleted from the dataset.
# They are withheld from the supervised *training target* only, and still
# appear in held-out evaluation (reported separately by
# `pirewall.ml.training.report`). Detecting them is the job of the
# Isolation Forest and `pirewall.detection.behavior`.
MIN_SUPERVISED_TRAINING_EXAMPLES = 100

_EXCLUDED_LABELS = frozenset(
    {
        "heartbleed",
        "web attack sql injection",
        "infiltration",
    }
)


def normalize_label(label: str) -> str:
    """Collapse a dataset label to a stable comparison key.

    CICIDS2017's three `Web Attack` labels contain U+FFFD in the published
    files (the corruption is upstream, not introduced by this project — see
    `docs/ML_DATA_AUDIT.md` §A3). Normalising every run of non-alphanumeric
    characters to a single space makes the key identical whether the label
    arrives with the replacement character, a plain hyphen, or an en dash
    between "Web Attack" and the variant name, so the policy cannot be
    silently bypassed by an encoding difference.
    """
    return re.sub(r"[^a-z0-9]+", " ", label.strip().lower()).strip()


def is_excluded_from_supervised_training(original_label: str) -> bool:
    """True if `original_label` has too few real examples to be a training target.

    Callers must use this to filter which rows contribute to the
    train/validation split. Rows of an excluded class must never be used as
    a training example — and must never be relabelled benign, because they
    are not benign — but must still be kept in held-out evaluation.
    """
    return normalize_label(original_label) in _EXCLUDED_LABELS

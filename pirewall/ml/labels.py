"""Dataset-agnostic interpretation of a classifier's predicted-class label.

A dataset adapter's label strings are dataset-specific ("BENIGN" for
CICIDS2017, "Normal" for UNSW-NB15) — this is the single place that maps
any of them to "is this actually an attack?", shared by training-time
evaluation (`pirewall.ml.training.metrics`) and runtime detection
(`pirewall.detection.known_attack`) so the two can never disagree.
"""

_BENIGN_LABELS = frozenset({"benign", "normal"})


def is_attack_label(label: str) -> bool:
    """True unless `label` is a known benign/normal label (case-insensitive)."""
    return label.strip().lower() not in _BENIGN_LABELS

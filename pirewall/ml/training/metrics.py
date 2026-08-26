"""Pure-Python evaluation metrics (spec §16).

Deliberately not `sklearn.metrics` — scikit-learn ships no inline type
information, and these are simple enough to implement directly, fully
typed, without an untyped-library boundary.
"""

from collections.abc import Sequence


def _safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator > 0 else 0.0


def accuracy(y_true: Sequence[str], y_pred: Sequence[str]) -> float:
    if not y_true:
        return 0.0
    correct = sum(1 for actual, predicted in zip(y_true, y_pred, strict=True) if actual == predicted)
    return correct / len(y_true)


def confusion_matrix(
    y_true: Sequence[str], y_pred: Sequence[str], labels: Sequence[str]
) -> dict[str, dict[str, int]]:
    """`matrix[actual][predicted] = count`, over every label in `labels`."""
    matrix: dict[str, dict[str, int]] = {actual: dict.fromkeys(labels, 0) for actual in labels}
    for actual, predicted in zip(y_true, y_pred, strict=True):
        matrix[actual][predicted] += 1
    return matrix


def per_class_metrics(
    y_true: Sequence[str], y_pred: Sequence[str], labels: Sequence[str]
) -> dict[str, dict[str, float]]:
    """Per-class precision/recall/F1, one-vs-rest for each label in `labels`."""
    result: dict[str, dict[str, float]] = {}
    for label in labels:
        true_positive = sum(1 for a, p in zip(y_true, y_pred, strict=True) if a == label and p == label)
        false_positive = sum(1 for a, p in zip(y_true, y_pred, strict=True) if a != label and p == label)
        false_negative = sum(1 for a, p in zip(y_true, y_pred, strict=True) if a == label and p != label)

        precision = _safe_ratio(true_positive, true_positive + false_positive)
        recall = _safe_ratio(true_positive, true_positive + false_negative)
        f1 = _safe_ratio(2 * precision * recall, precision + recall)
        result[label] = {"precision": precision, "recall": recall, "f1": f1}
    return result


def macro_f1(per_class: dict[str, dict[str, float]]) -> float:
    if not per_class:
        return 0.0
    return sum(metrics["f1"] for metrics in per_class.values()) / len(per_class)


def is_attack_label(label: str) -> bool:
    """Collapse a multiclass dataset label into a binary attack/normal ground truth."""
    return label.strip().lower() not in {"benign", "normal"}


def binary_confusion_counts(
    y_true_is_attack: Sequence[bool], y_pred_is_attack: Sequence[bool]
) -> tuple[int, int, int, int]:
    """Returns (true_positive, false_positive, false_negative, true_negative)."""
    pairs = list(zip(y_true_is_attack, y_pred_is_attack, strict=True))
    true_positive = sum(1 for t, p in pairs if t and p)
    false_positive = sum(1 for t, p in pairs if not t and p)
    false_negative = sum(1 for t, p in pairs if t and not p)
    true_negative = sum(1 for t, p in pairs if not t and not p)
    return true_positive, false_positive, false_negative, true_negative


def binary_rates(
    true_positive: int, false_positive: int, false_negative: int, true_negative: int
) -> dict[str, float]:
    """Precision/recall/false-positive-rate/false-negative-rate from a binary confusion count."""
    precision = _safe_ratio(true_positive, true_positive + false_positive)
    recall = _safe_ratio(true_positive, true_positive + false_negative)
    fpr = _safe_ratio(false_positive, false_positive + true_negative)
    fnr = _safe_ratio(false_negative, false_negative + true_positive)
    return {
        "precision": precision,
        "recall": recall,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
    }

"""The standard per-class evaluation report for pirewall ML models (spec §16).

Every LightGBM evaluation in this project renders through
`format_evaluation_report` so that results from different sessions,
architectures, and datasets are directly comparable instead of each run
inventing its own table. It reports, in one place:

* multiclass macro-F1 over the *trained* label set,
* binary any-attack-vs-benign precision/recall/F1 (what the firewall
  actually acts on),
* the full per-class recall table (class, test n, count caught, recall%),
* and, listed separately, any class excluded from supervised training by
  `pirewall.ml.labels.is_excluded_from_supervised_training` — shown for
  transparency, never folded into macro-F1, because the model was never
  trained to predict them (see `docs/ML_PIPELINE.md`).

Rendering is pure text and returns a `str`; callers are responsible for
writing it with an explicit `encoding="utf-8"`. Attack-class labels in
CICIDS2017 carry non-ASCII characters, so writing this report with the
platform default encoding can raise `UnicodeEncodeError` on Windows —
`write_report` exists to make the correct call the easy one.
"""

from collections.abc import Sequence
from pathlib import Path

from pirewall.ml.labels import is_attack_label
from pirewall.ml.training.metrics import (
    accuracy,
    binary_confusion_counts,
    binary_rates,
    macro_f1,
    per_class_metrics,
)

_CLASS_COLUMN_WIDTH = 34


def _per_class_rows(
    y_true: Sequence[str],
    y_pred: Sequence[str],
    labels: Sequence[str],
) -> list[tuple[str, int, int, float, float, float]]:
    """(label, test n, count caught, recall, precision, f1) for each label."""
    per_class = per_class_metrics(y_true, y_pred, labels)
    rows: list[tuple[str, int, int, float, float, float]] = []
    for label in labels:
        support = sum(1 for actual in y_true if actual == label)
        caught = sum(
            1 for actual, predicted in zip(y_true, y_pred, strict=True)
            if actual == label and predicted == label
        )
        metrics = per_class[label]
        rows.append((label, support, caught, metrics["recall"], metrics["precision"], metrics["f1"]))
    return rows


def _format_row(row: tuple[str, int, int, float, float, float]) -> str:
    """One per-class table line: class, support, caught, recall%, precision%, F1."""
    label, support, caught, recall, precision, f1 = row
    return (
        f"{label:{_CLASS_COLUMN_WIDTH}s} {support:9d} {caught:9d}"
        f" {100 * recall:8.2f}% {100 * precision:8.2f}% {f1:8.4f}"
    )


def format_evaluation_report(
    y_true: Sequence[str],
    y_pred: Sequence[str],
    *,
    trained_labels: Sequence[str],
    excluded_labels: Sequence[str] = (),
    title: str,
    notes: Sequence[str] = (),
) -> str:
    """Render the standard pirewall evaluation report.

    `trained_labels` are the classes the model was actually trained on —
    macro-F1 is computed over exactly these. `excluded_labels` are classes
    present in the held-out data but deliberately kept out of the training
    target; they are reported separately and never affect macro-F1.
    """
    header = (
        f"{'class':{_CLASS_COLUMN_WIDTH}s} {'test n':>9s} {'caught':>9s}"
        f" {'recall':>9s} {'prec':>9s} {'f1':>8s}"
    )
    lines: list[str] = [title, "=" * len(header), ""]
    for note in notes:
        lines.append(note)
    if notes:
        lines.append("")

    trained_rows = _per_class_rows(y_true, y_pred, trained_labels)
    macro = macro_f1(per_class_metrics(y_true, y_pred, trained_labels))

    true_is_attack = [is_attack_label(label) for label in y_true]
    pred_is_attack = [is_attack_label(label) for label in y_pred]
    true_positive, false_positive, false_negative, true_negative = binary_confusion_counts(
        true_is_attack, pred_is_attack
    )
    rates = binary_rates(true_positive, false_positive, false_negative, true_negative)
    binary_f1 = (
        2 * rates["precision"] * rates["recall"] / (rates["precision"] + rates["recall"])
        if rates["precision"] + rates["recall"] > 0
        else 0.0
    )

    lines.append(f"overall accuracy          {accuracy(y_true, y_pred):.6f}")
    lines.append(f"multiclass macro-F1       {macro:.6f}   (over {len(trained_labels)} trained classes)")
    lines.append("")
    lines.append("binary (any-attack vs benign):")
    lines.append(f"  precision               {rates['precision']:.6f}")
    lines.append(f"  recall                  {rates['recall']:.6f}")
    lines.append(f"  f1                      {binary_f1:.6f}")
    lines.append(f"  false positive rate     {rates['false_positive_rate']:.6f}")
    lines.append(f"  false negative rate     {rates['false_negative_rate']:.6f}")
    lines.append(f"  tp={true_positive} fp={false_positive} fn={false_negative} tn={true_negative}")
    lines.append("")
    lines.append("per-class (trained classes — these determine macro-F1):")
    lines.append(header)
    lines.append("-" * len(header))
    for row in trained_rows:
        lines.append(_format_row(row))

    if excluded_labels:
        lines.append("")
        lines.append("excluded from supervised training — insufficient examples;")
        lines.append("relying on Isolation Forest / behavior analysis instead.")
        lines.append("Shown for transparency only; NOT included in macro-F1 above.")
        lines.append(header)
        lines.append("-" * len(header))
        for row in _per_class_rows(y_true, y_pred, excluded_labels):
            lines.append(_format_row(row))
    return "\n".join(lines) + "\n"


def write_report(path: Path, report: str) -> None:
    """Write `report` as UTF-8, whatever the platform default encoding is.

    CICIDS2017's attack labels contain non-ASCII characters; writing them
    with the Windows default (cp1252) raises `UnicodeEncodeError` and
    truncates the report.
    """
    path.write_text(report, encoding="utf-8")

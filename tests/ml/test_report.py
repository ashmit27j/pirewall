"""`pirewall.ml.training.report` — the standard evaluation report format."""

from pathlib import Path

from pirewall.ml.training.report import format_evaluation_report, write_report

TRAINED = ("BENIGN", "DDoS", "PortScan")


def _report(y_true: list[str], y_pred: list[str], **kwargs: object) -> str:
    return format_evaluation_report(
        y_true, y_pred, trained_labels=TRAINED, title="test report", **kwargs  # pyright: ignore[reportArgumentType]
    )


def test_perfect_predictions_give_macro_f1_one() -> None:
    y = ["BENIGN", "DDoS", "PortScan", "BENIGN"]
    report = _report(y, list(y))

    assert "multiclass macro-F1       1.000000" in report
    assert "overall accuracy          1.000000" in report


def test_per_class_row_reports_support_caught_and_recall() -> None:
    y_true = ["DDoS", "DDoS", "DDoS", "DDoS", "BENIGN"]
    y_pred = ["DDoS", "DDoS", "DDoS", "BENIGN", "BENIGN"]

    report = _report(y_true, y_pred)

    # DDoS: 4 in test, 3 caught -> 75.00%
    ddos = next(line for line in report.splitlines() if line.startswith("DDoS"))
    assert "        4" in ddos
    assert "        3" in ddos
    assert "75.00%" in ddos


def test_binary_metrics_collapse_attack_classes() -> None:
    # Two attacks, both detected as *some* attack: binary recall is 1.0 even
    # though the multiclass prediction for one of them is the wrong attack.
    y_true = ["DDoS", "PortScan", "BENIGN"]
    y_pred = ["PortScan", "PortScan", "BENIGN"]

    report = _report(y_true, y_pred)

    assert "  recall                  1.000000" in report
    assert "  false positive rate     0.000000" in report


def test_excluded_classes_get_their_own_section_out_of_macro_f1() -> None:
    """Excluded classes are reported, but never counted as a trained class."""
    y_true = ["BENIGN", "DDoS", "PortScan", "Heartbleed"]
    y_pred = ["BENIGN", "DDoS", "PortScan", "BENIGN"]

    with_excluded = _report(y_true, y_pred, excluded_labels=("Heartbleed",))
    without = _report(y_true, y_pred)

    assert "excluded from supervised training" in with_excluded
    assert "Heartbleed" in with_excluded
    assert "Heartbleed" not in without
    # Heartbleed never appears as its own F1 term either way: macro-F1 is
    # taken over the three trained classes only.
    assert "(over 3 trained classes)" in with_excluded
    assert "(over 3 trained classes)" in without


def test_excluded_rows_still_cost_the_trained_class_that_absorbs_them() -> None:
    """An excluded-class flow does not vanish at inference — it lands somewhere.

    Here the single Heartbleed row is predicted BENIGN. It is not scored as
    a Heartbleed miss (Heartbleed is not a trained class), but it *is* a
    false positive against BENIGN, dropping BENIGN precision to 0.5 and
    macro-F1 below 1.0. Excluding a class from the training target does not
    make its traffic disappear from the evaluation, and this report format
    deliberately does not hide that cost.
    """
    y_true = ["BENIGN", "DDoS", "PortScan", "Heartbleed"]
    y_pred = ["BENIGN", "DDoS", "PortScan", "BENIGN"]

    report = _report(y_true, y_pred, excluded_labels=("Heartbleed",))

    benign = next(line for line in report.splitlines() if line.startswith("BENIGN"))
    assert "50.00%" in benign  # precision, not recall
    assert "multiclass macro-F1       1.000000" not in report


def test_write_report_uses_utf8_regardless_of_platform_default(tmp_path: Path) -> None:
    """CICIDS2017 labels are non-ASCII; the platform default can't be trusted."""
    path = tmp_path / "r.txt"
    report = _report(["BENIGN"], ["BENIGN"]) + "Web Attack – Brute Force\n"

    write_report(path, report)

    assert path.read_text(encoding="utf-8") == report
    assert "–".encode() in path.read_bytes()

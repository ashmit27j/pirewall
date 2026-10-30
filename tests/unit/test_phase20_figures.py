"""Phase-20 paper tooling (`lab/paper/make_figures.py`): refusals, watermark and purity."""

import json
from pathlib import Path

from lab.paper.make_figures import (
    WATERMARK_FORMAT,
    build_figures,
    figure_entries,
    render,
)
from lab.paper.make_figures import (
    main as make_figures_main,
)
from lab.paper.make_tables import load_phase19_metrics

ENV_TAG = "mock"


def _write_report(directory: Path, env_tag: str) -> Path:
    """A phase-19-shaped report directory for the figure tests."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "metrics.json").write_text(
        json.dumps(
            {
                "env_tags": [env_tag],
                "reportable_as_model_quality": False,
                "feature_schema_version": "3.0.0",
                "dataset_id": "7991e00196cfc02747a162a62bbf97c5e1fa2aad1295148cc6d4f3b91a8af742",
                "d2": {
                    "benign_scores": {
                        "rows": 822,
                        "mean": 0.03,
                        "std": 0.06,
                        "minimum": -0.25,
                        "p50": 0.04,
                        "p90": 0.09,
                        "p99": 0.09,
                        "maximum": 0.09,
                    },
                    "attack_scores": {
                        "rows": 18781,
                        "mean": 0.02,
                        "std": 0.09,
                        "minimum": -0.12,
                        "p50": 0.09,
                        "p90": 0.09,
                        "p99": 0.09,
                        "maximum": 0.09,
                    },
                },
                "d3": {
                    "benign_scores": {
                        "rows": 822,
                        "mean": 0.39,
                        "std": 0.47,
                        "minimum": 0.0,
                        "p50": 0.96,
                        "p90": 0.96,
                        "p99": 0.96,
                        "maximum": 0.96,
                    },
                    "attack_scores": {
                        "rows": 18781,
                        "mean": 0.96,
                        "std": 0.05,
                        "minimum": 0.0,
                        "p50": 0.96,
                        "p90": 1.0,
                        "p99": 1.0,
                        "maximum": 1.0,
                    },
                    "reliability": [
                        {
                            "lower": 0.0,
                            "upper": 0.1,
                            "rows": 517,
                            "positives": 40,
                            "mean_score": 0.0,
                            "observed_rate": 0.07,
                        },
                    ],
                },
                "psi": {"forward_payload_byte_count": {"psi": 0.015, "major_shift": False}},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return directory


def test_figure_entries_group_the_phase19_numbers_by_figure(tmp_path: Path) -> None:
    metrics = load_phase19_metrics(_write_report(tmp_path / "phase19", ENV_TAG) / "metrics.json")
    entries = figure_entries(metrics)
    figures = build_figures(metrics, ENV_TAG)
    assert len(figures) == 3
    assert [figure.number for figure in figures] == ["3", "4", "5"]
    assert {str(entry["figure"]) for entry in entries} == {"3", "4", "5"}


def test_make_figures_refuses_a_mock_report_without_regression(tmp_path: Path) -> None:
    report = _write_report(tmp_path / "phase19", ENV_TAG)
    out = tmp_path / "out"
    assert make_figures_main([str(report), "--out", str(out)]) == 2
    assert not out.exists()


def test_make_figures_writes_a_regression_watermarked_figure_set(tmp_path: Path) -> None:
    report = _write_report(tmp_path / "phase19", ENV_TAG)
    out = tmp_path / "out"
    assert make_figures_main([str(report), "--out", str(out), "--regression"]) == 0
    document: dict[str, object] = json.loads((out / "paper_figures.json").read_text(encoding="utf-8"))
    figures = document["figures"]
    assert isinstance(figures, list) and len(figures) == 3
    for figure in figures:
        assert isinstance(figure, dict)
        assert figure["watermark"] == WATERMARK_FORMAT.format(env_tag=ENV_TAG)
    assert (out / "paper_figures.csv").is_file()


def test_make_figures_output_is_pure_and_hash_stable(tmp_path: Path) -> None:
    report = _write_report(tmp_path / "phase19", ENV_TAG)
    first_out, second_out = tmp_path / "out1", tmp_path / "out2"
    assert make_figures_main([str(report), "--out", str(first_out), "--regression"]) == 0
    assert make_figures_main([str(report), "--out", str(second_out), "--regression"]) == 0
    for name in ("paper_figures.json", "paper_figures.csv"):
        assert (first_out / name).read_bytes() == (second_out / name).read_bytes()


def test_make_figures_rejects_a_report_with_no_env_tag(tmp_path: Path) -> None:
    report = _write_report(tmp_path / "phase19", ENV_TAG)
    (report / "metrics.json").write_text(json.dumps({"d2": {}}), encoding="utf-8")
    assert make_figures_main([str(report), "--out", str(tmp_path / "out")]) == 2


def test_render_applies_the_watermark_only_when_requested() -> None:
    figures = build_figures({"env_tags": [ENV_TAG], "d2": {}, "d3": {}, "psi": {}}, ENV_TAG)
    assert all(figure.watermark is None for figure in render(figures, regression=False, env_tag=ENV_TAG))
    assert all(figure.watermark is not None for figure in render(figures, regression=True, env_tag=ENV_TAG))
    assert render(figures, regression=True, env_tag=ENV_TAG)[0].watermark == (
        WATERMARK_FORMAT.format(env_tag=ENV_TAG)
    )

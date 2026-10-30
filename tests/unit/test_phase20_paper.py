"""Phase-20 paper tooling (`lab/paper/make_tables.py`): refusals, watermark and purity."""

import json
from pathlib import Path

import pytest

from lab.manifest import Json
from lab.paper import make_tables
from lab.paper.make_tables import (
    NOT_YET_RUN,
    TABLE_TITLES,
    WATERMARK_FORMAT,
    ReportError,
    build_tables,
    load_phase19_metrics,
    table_v_entries,
    write_outputs,
)
from lab.paper.make_tables import (
    main as make_tables_main,
)

ENV_TAG = "mock"


def _metrics(env_tag: str, *, reportable: bool = False) -> dict[str, Json]:
    """A phase-19-shaped metrics document for the tests."""
    return {
        "env_tags": [env_tag],
        "reportable_as_model_quality": reportable,
        "feature_schema_version": "3.0.0",
        "dataset_id": "7991e00196cfc02747a162a62bbf97c5e1fa2aad1295148cc6d4f3b91a8af742",
        "dataset_manifest_sha256": "0" * 64,
        "benign_flows_per_day": 225226.9,
        "d2": {
            "operating_threshold": -0.25,
            "benign_false_positive_rate": 0.0,
            "attack_recall": 0.0,
            "average_precision": 0.92,
            "roc_auc": 0.53,
            "expected_alerts_per_day": 0.0,
            "benign_flows_per_day": 225226.9,
            "recall_at_fpr": {
                "0.001": {
                    "target_fpr": 0.001,
                    "achieved_fpr": 0.0,
                    "resolution": 0.002,
                    "resolvable": False,
                    "recall": 0.0,
                },
                "0.0001": {
                    "target_fpr": 0.0001,
                    "achieved_fpr": 0.0,
                    "resolution": 0.002,
                    "resolvable": False,
                    "recall": 0.0,
                },
            },
        },
        "d3": {
            "operating_threshold": 0.96,
            "benign_false_positive_rate": 0.0,
            "attack_recall": 0.28,
            "average_precision": 0.98,
            "roc_auc": 0.83,
            "expected_alerts_per_day": 0.0,
            "benign_flows_per_day": 225226.9,
            "recall_at_fpr": {
                "0.001": {
                    "target_fpr": 0.001,
                    "achieved_fpr": 0.0,
                    "resolution": 0.002,
                    "resolvable": False,
                    "recall": 0.28,
                },
                "0.0001": {
                    "target_fpr": 0.0001,
                    "achieved_fpr": 0.0,
                    "resolution": 0.002,
                    "resolvable": False,
                    "recall": 0.28,
                },
            },
        },
    }


def _write_phase19_report(directory: Path, env_tag: str, *, reportable: bool = False) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "metrics.json").write_text(
        json.dumps(_metrics(env_tag, reportable=reportable), indent=2) + "\n", encoding="utf-8"
    )
    (directory / "table_v.csv").write_text(
        "model,threshold,benign_fpr,attack_recall,average_precision,roc_auc,"
        "recall_at_fpr_1e-3,recall_at_fpr_1e-4,expected_alerts_per_day,env_tag\n",
        encoding="utf-8",
    )
    return directory


def _write_aggregate(path: Path, env_tag: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"env_tag": env_tag, "phase": "dev", "verified": True, "rows": []}, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def test_load_phase19_metrics_reads_a_single_env_tag(tmp_path: Path) -> None:
    report = _write_phase19_report(tmp_path / "phase19", ENV_TAG, reportable=True)
    metrics = load_phase19_metrics(report / "metrics.json")
    assert metrics["env_tags"] == [ENV_TAG]
    assert metrics["reportable_as_model_quality"] is True


def test_load_phase19_metrics_refuses_missing_or_mixed_tags(tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "metrics.json").write_text(json.dumps({"env_tags": [ENV_TAG, "sandbox"]}), encoding="utf-8")
    with pytest.raises(ReportError, match="mixed"):
        load_phase19_metrics(bad / "metrics.json")
    (bad / "metrics.json").write_text(json.dumps({}), encoding="utf-8")
    with pytest.raises(ReportError, match="env_tags"):
        load_phase19_metrics(bad / "metrics.json")


def test_table_v_entries_cover_each_model_and_operating_fpr() -> None:
    entries = table_v_entries(_metrics(ENV_TAG), ENV_TAG)
    assert len(entries) == 6  # D2 base + 2 recalls, D3 base + 2 recalls
    assert [str(entry["model"]) for entry in entries] == ["D2", "D2", "D2", "D3", "D3", "D3"]


def test_build_tables_renders_every_paper_table_in_order() -> None:
    """Tables I-VII (critique_ml.md §10), each with its source and env tag."""
    tables = build_tables(_metrics(ENV_TAG), {"env_tag": ENV_TAG})
    assert [table.number for table in tables] == ["I", "II", "III", "IV", "V", "VI", "VII"]
    assert all(table.source for table in tables)
    assert all(table.env_tag == ENV_TAG for table in tables)
    assert all(table.watermark is None for table in tables)
    table_v = next(table for table in tables if table.number == "V")
    assert table_v.title == "ML"


def test_tables_without_their_campaign_say_so_rather_than_showing_a_zero() -> None:
    """An input that has not been produced yet gives `not yet run`, never a number."""
    tables = {table.number: table for table in build_tables(_metrics(ENV_TAG), {"env_tag": ENV_TAG})}
    ablation_arms = tables["VI"].entries
    assert [str(entry["arm"]) for entry in ablation_arms] == ["kernel only", "+D1", "+D2", "+D3"]
    assert all(entry["attacks_detected"] == NOT_YET_RUN for entry in ablation_arms)
    assert tables["IV"].entries[0]["action"] == NOT_YET_RUN
    assert tables["VII"].entries[0]["pps"] == NOT_YET_RUN
    assert tables["II"].entries[0]["detector"] == NOT_YET_RUN


def test_make_tables_refuses_a_mock_report_without_regression(tmp_path: Path) -> None:
    report = _write_phase19_report(tmp_path / "phase19", ENV_TAG)
    aggregate = _write_aggregate(tmp_path / "agg" / "aggregate-mock-dev.json", ENV_TAG)
    out = tmp_path / "out"
    assert make_tables_main([str(report), "--aggregate", str(aggregate), "--out", str(out)]) == 2
    assert not out.exists()


def test_make_tables_writes_a_regression_watermarked_table(tmp_path: Path) -> None:
    report = _write_phase19_report(tmp_path / "phase19", ENV_TAG)
    aggregate = _write_aggregate(tmp_path / "agg" / "aggregate-mock-dev.json", ENV_TAG)
    out = tmp_path / "out"
    assert (
        make_tables_main([str(report), "--aggregate", str(aggregate), "--out", str(out), "--regression"]) == 0
    )
    document: dict[str, Json] = json.loads((out / "paper_tables.json").read_text(encoding="utf-8"))
    assert document["regression"] is True
    assert document["watermark"] == WATERMARK_FORMAT.format(env_tag=ENV_TAG)
    tables = document["tables"]
    assert isinstance(tables, list) and len(tables) == len(TABLE_TITLES)
    assert [table["number"] for table in tables if isinstance(table, dict)] == list(TABLE_TITLES)
    for table in tables:
        assert isinstance(table, dict)
        # The watermark is on *every* table, not just the first (phase-20 prompt).
        assert table["watermark"] == WATERMARK_FORMAT.format(env_tag=ENV_TAG)
        entries = table["entries"]
        assert isinstance(entries, list) and len(entries) > 0
    assert (out / "paper_tables.csv").is_file()


def test_make_tables_refuses_an_aggregate_with_a_different_env_tag(tmp_path: Path) -> None:
    report = _write_phase19_report(tmp_path / "phase19", ENV_TAG)
    aggregate = _write_aggregate(tmp_path / "agg" / "aggregate-mock-dev.json", "pi-live")
    assert make_tables_main([str(report), "--aggregate", str(aggregate), "--out", str(tmp_path / "out")]) == 2


def test_make_tables_output_is_pure_and_hash_stable(tmp_path: Path) -> None:
    report = _write_phase19_report(tmp_path / "phase19", ENV_TAG)
    aggregate = _write_aggregate(tmp_path / "agg" / "aggregate-mock-dev.json", ENV_TAG)
    first_out, second_out = tmp_path / "out1", tmp_path / "out2"
    assert (
        make_tables_main(
            [str(report), "--aggregate", str(aggregate), "--out", str(first_out), "--regression"]
        )
        == 0
    )
    assert (
        make_tables_main(
            [str(report), "--aggregate", str(aggregate), "--out", str(second_out), "--regression"]
        )
        == 0
    )
    for name in ("paper_tables.json", "paper_tables.csv"):
        assert (first_out / name).read_bytes() == (second_out / name).read_bytes()


def test_write_outputs_renders_a_pi_tagged_table(tmp_path: Path) -> None:
    table = make_tables.PaperTable(
        number="V",
        title="ML",
        source="phase-19 metrics.json + table_v.csv; lab/aggregate.py output",
        entries=({"table": "V", "model": "D2"},),
        env_tag="pi-live",
    )
    json_path, csv_path = write_outputs(tmp_path / "out", [table], env_tag="pi-live", regression=False)
    assert json_path.is_file() and csv_path.is_file()
    assert json_path.parent == tmp_path / "out"

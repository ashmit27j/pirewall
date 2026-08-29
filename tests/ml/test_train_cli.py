"""`scripts/train/*` CLI entry points: clear failure on a missing dataset, success on a fixture."""

from collections.abc import Callable
from pathlib import Path

import pytest
from scripts.train.train_isolation_forest import main as isolation_forest_main
from scripts.train.train_lightgbm import main as lightgbm_main

_CICIDS_HEADER = (
    " Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets,"
    "Total Length of Fwd Packets, Total Length of Bwd Packets,"
    " Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean,"
    " Fwd Packet Length Std, Bwd Packet Length Max, Bwd Packet Length Min,"
    " Bwd Packet Length Mean, Bwd Packet Length Std, Flow IAT Mean,"
    " Flow IAT Std, Flow IAT Max, Flow IAT Min, SYN Flag Count,"
    " ACK Flag Count, FIN Flag Count, RST Flag Count, PSH Flag Count,"
    " URG Flag Count, Label"
)
_BENIGN_ROW = (
    "443,1000000,5,4,600,400,"
    "150,100,120,15,120,80,100,12,50000,10000,80000,20000,1,4,1,0,3,0,BENIGN"
)
_DDOS_ROW = (
    "80,500000,100,1,6000,60,"
    "60,60,60,0,60,60,60,0,5000,1000,8000,2000,100,1,0,0,0,0,DDoS"
)


def _write_fixture_csv(path: Path) -> Path:
    path.write_text(_CICIDS_HEADER + "\n" + _BENIGN_ROW + "\n" + _DDOS_ROW + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("main", [lightgbm_main, isolation_forest_main])
def test_missing_dataset_file_exits_nonzero_with_actionable_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], main: Callable[[list[str] | None], int]
) -> None:
    exit_code = main(
        [
            "--dataset",
            "cicids",
            "--dataset-path",
            str(tmp_path / "does_not_exist.csv"),
            "--model-version",
            "0.0.1",
        ]
    )
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "download" in captured.err.lower() or "Download" in captured.err


def test_lightgbm_cli_trains_and_saves_artifact(tmp_path: Path) -> None:
    csv_path = _write_fixture_csv(tmp_path / "cicids.csv")
    output_dir = tmp_path / "artifacts"

    exit_code = lightgbm_main(
        [
            "--dataset",
            "cicids",
            "--dataset-path",
            str(csv_path),
            "--model-version",
            "0.0.1-placeholder",
            "--output-dir",
            str(output_dir),
            "--placeholder",
            "--notes",
            "NOT trained on real data — placeholder for pipeline testing",
        ]
    )

    assert exit_code == 0
    assert (output_dir / "lightgbm_model.txt").is_file()
    assert (output_dir / "lightgbm_model.txt.metadata.json").is_file()


def test_isolation_forest_cli_trains_and_saves_artifact(tmp_path: Path) -> None:
    csv_path = _write_fixture_csv(tmp_path / "cicids.csv")
    output_dir = tmp_path / "artifacts"

    exit_code = isolation_forest_main(
        [
            "--dataset",
            "cicids",
            "--dataset-path",
            str(csv_path),
            "--model-version",
            "0.0.1-placeholder",
            "--output-dir",
            str(output_dir),
            "--placeholder",
        ]
    )

    assert exit_code == 0
    assert (output_dir / "isolation_forest_model.joblib").is_file()
    assert (output_dir / "isolation_forest_model.joblib.metadata.json").is_file()

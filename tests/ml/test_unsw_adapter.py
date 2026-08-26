"""`load_unsw_nb15` against small synthetic fixture CSVs (spec §12, §13)."""

from pathlib import Path

import pytest

from pirewall.core.enums import Protocol
from pirewall.core.exceptions import DatasetError
from pirewall.ml.preprocessing.unsw_adapter import load_unsw_nb15

_HEADER = "dur,proto,spkts,dpkts,sbytes,dbytes,smean,dmean,sinpkt,dinpkt,attack_cat,label"

_NORMAL_ROW = "1.5,tcp,10,8,1000,800,100,100,50,60,,0"
_EXPLOIT_ROW = "0.2,tcp,50,1,3000,60,60,60,5,100,Exploits,1"
_BLANK_ATTACK_CAT_LABEL_ONE_ROW = "0.3,udp,5,5,500,500,50,50,10,10,,1"
_MISSING_VALUE_ROW = ",tcp,10,8,1000,800,100,100,50,60,,0"
_UNKNOWN_PROTOCOL_ROW = "0.5,unas,4,4,400,400,50,50,20,20,,0"


def _write_csv(path: Path, rows: list[str]) -> Path:
    content = _HEADER + "\n" + "\n".join(rows) + "\n"
    path.write_text(content, encoding="utf-8")
    return path


def test_loads_valid_rows(tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "unsw.csv", [_NORMAL_ROW, _EXPLOIT_ROW])
    result = load_unsw_nb15(csv_path)

    assert result.skipped_rows == 0
    assert len(result.labeled_flows) == 2

    normal = result.labeled_flows[0]
    assert normal.label == "Normal"
    assert normal.flow.protocol is Protocol.TCP
    assert normal.flow.packet_count == 18
    assert normal.flow.byte_count == 1800
    assert normal.flow.duration_seconds == 1.5
    assert normal.flow.source_port is None
    assert normal.flow.tcp_flags.syn == 0

    exploit = result.labeled_flows[1]
    assert exploit.label == "Exploits"


def test_blank_attack_cat_falls_back_to_label_column(tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "unsw.csv", [_BLANK_ATTACK_CAT_LABEL_ONE_ROW])
    result = load_unsw_nb15(csv_path)

    assert result.labeled_flows[0].label == "Attack"
    assert result.labeled_flows[0].flow.protocol is Protocol.UDP


def test_unknown_protocol_maps_to_other(tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "unsw.csv", [_UNKNOWN_PROTOCOL_ROW])
    result = load_unsw_nb15(csv_path)

    assert result.skipped_rows == 0
    assert result.labeled_flows[0].flow.protocol is Protocol.OTHER


def test_missing_value_is_skipped_and_counted(tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "unsw.csv", [_NORMAL_ROW, _MISSING_VALUE_ROW])
    result = load_unsw_nb15(csv_path)

    assert len(result.labeled_flows) == 1
    assert result.skipped_rows == 1


def test_missing_required_column_raises_dataset_error(tmp_path: Path) -> None:
    broken_header = _HEADER.replace("dur,", "")
    csv_path = tmp_path / "unsw.csv"
    csv_path.write_text(broken_header + "\n" + _NORMAL_ROW + "\n", encoding="utf-8")

    with pytest.raises(DatasetError, match="dur"):
        load_unsw_nb15(csv_path)


def test_missing_file_raises_dataset_error_with_actionable_message(tmp_path: Path) -> None:
    with pytest.raises(DatasetError, match=r"download|Download"):
        load_unsw_nb15(tmp_path / "does_not_exist.csv")

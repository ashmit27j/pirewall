"""`load_cicids2017` against small synthetic fixture CSVs (spec §12, §13).

Fixture header matches the real, published "MachineLearningCVE" CICIDS2017
column layout, verified against all 8 real files this project trains
against: no Source IP, Source Port, Destination IP, or Protocol column.
"""

from pathlib import Path

import pytest

from pirewall.core.enums import Protocol
from pirewall.core.exceptions import DatasetError
from pirewall.ml.preprocessing.cicids_adapter import load_cicids2017

# Matches the adapter's own documented placeholder (this dataset variant has
# no real source/destination IP columns).
_PLACEHOLDER_SOURCE_IP = "10.255.255.1"
_PLACEHOLDER_DESTINATION_IP = "10.255.255.2"

_HEADER = (
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
    "443,"
    "1000000,5,4,600,400,"
    "150,100,120,15,"
    "120,80,100,12,"
    "50000,10000,80000,20000,1,"
    "4,1,0,3,"
    "0,BENIGN"
)

_DDOS_ROW = (
    "80,"
    "500000,100,1,6000,60,"
    "60,60,60,0,"
    "60,60,60,0,"
    "5000,1000,8000,2000,100,"
    "1,0,0,0,"
    "0,DDoS"
)

# All TCP flag counts zero, on a well-known UDP port -- exercises the
# fallback branch of `_infer_protocol`.
_UDP_ROW = (
    "53,200000,2,2,120,120,"
    "60,60,60,0,60,60,60,0,100000,0,100000,100000,0,0,0,0,0,0,BENIGN"
)

_MISSING_VALUE_ROW = (
    ",1000000,5,4,600,400,"
    "150,100,120,15,120,80,100,12,50000,10000,80000,20000,1,4,1,0,3,0,BENIGN"
)

_INVALID_VALUE_ROW = (
    "not-a-port,1000000,5,4,600,400,"
    "150,100,120,15,120,80,100,12,50000,10000,80000,20000,1,4,1,0,3,0,BENIGN"
)


def _write_csv(path: Path, rows: list[str]) -> Path:
    content = _HEADER + "\n" + "\n".join(rows) + "\n"
    path.write_text(content, encoding="utf-8")
    return path


def test_loads_valid_rows(tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "cicids.csv", [_BENIGN_ROW, _DDOS_ROW, _UDP_ROW])
    result = load_cicids2017(csv_path)

    assert result.skipped_rows == 0
    assert len(result.labeled_flows) == 3

    benign = result.labeled_flows[0]
    assert benign.label == "BENIGN"
    assert benign.flow.protocol is Protocol.TCP
    assert benign.flow.source_ip.compressed == _PLACEHOLDER_SOURCE_IP
    assert benign.flow.destination_ip.compressed == _PLACEHOLDER_DESTINATION_IP
    assert benign.flow.source_port is None
    assert benign.flow.destination_port == 443
    assert benign.flow.packet_count == 9
    assert benign.flow.byte_count == 1000
    assert benign.flow.duration_seconds == 1.0  # microseconds -> seconds
    assert benign.flow.tcp_flags.syn == 1
    assert benign.flow.tcp_flags.ack == 4

    udp = result.labeled_flows[2]
    assert udp.flow.protocol is Protocol.UDP  # inferred: zero flags + well-known UDP port


def test_missing_value_is_skipped_and_counted(tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "cicids.csv", [_BENIGN_ROW, _MISSING_VALUE_ROW])
    result = load_cicids2017(csv_path)

    assert len(result.labeled_flows) == 1
    assert result.skipped_rows == 1


def test_invalid_value_is_skipped_and_counted(tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "cicids.csv", [_BENIGN_ROW, _INVALID_VALUE_ROW])
    result = load_cicids2017(csv_path)

    assert len(result.labeled_flows) == 1
    assert result.skipped_rows == 1


def test_missing_required_column_raises_dataset_error(tmp_path: Path) -> None:
    broken_header = _HEADER.replace(" Flow Duration,", "")
    csv_path = tmp_path / "cicids.csv"
    csv_path.write_text(broken_header + "\n" + _BENIGN_ROW + "\n", encoding="utf-8")

    with pytest.raises(DatasetError, match="flow duration"):
        load_cicids2017(csv_path)


def test_missing_file_raises_dataset_error_with_actionable_message(tmp_path: Path) -> None:
    with pytest.raises(DatasetError, match=r"download|Download"):
        load_cicids2017(tmp_path / "does_not_exist.csv")

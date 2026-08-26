"""UNSW-NB15 -> canonical dataset adapter (spec §12, §13).

Targets the widely-distributed `UNSW_NB15_training-set.csv` /
`UNSW_NB15_testing-set.csv` partition files (the "48-feature" ML-ready
release), not the raw 4-part pcap-derived CSVs. This partition format has
**no source/destination IP or port columns** and **no per-packet TCP flag
counts** — both are documented, honest limitations of this dataset variant
rather than something this adapter fabricates:

* `source_ip`/`destination_ip` are set to a fixed documented placeholder
  (this format carries no real network identity).
* `source_port`/`destination_port` are always `None`.
* `Flow.tcp_flags` is always all-zero.
* `packet_size_stats`/`inter_arrival_stats` only have a real *mean* (from
  `smean`/`dmean` and `sinpkt`/`dinpkt`) — `min`/`max` are set equal to the
  mean and `std` to 0.0, since this format doesn't report per-packet
  distributions, only per-flow means.

`dur` is already in seconds and `proto`/`service`/`state` are lowercase
strings (unlike CICIDS2017's numeric protocol column) — see
`pirewall.ml.preprocessing.cicids_adapter` for that dataset's own quirks.
"""

import csv
from datetime import timedelta
from pathlib import Path

from pirewall.core.enums import Protocol
from pirewall.core.exceptions import DatasetError
from pirewall.core.models.flow import Flow
from pirewall.ml.preprocessing.common import SYNTHETIC_EPOCH, DatasetLoadResult, LabeledFlow, parse_float

_REQUIRED_COLUMNS = (
    "dur",
    "proto",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "smean",
    "dmean",
    "sinpkt",
    "dinpkt",
    "attack_cat",
    "label",
)

_PLACEHOLDER_SOURCE_IP = "10.255.255.1"
_PLACEHOLDER_DESTINATION_IP = "10.255.255.2"

_PROTOCOL_BY_NAME = {"tcp": Protocol.TCP, "udp": Protocol.UDP, "icmp": Protocol.ICMP}


def _build_header_map(fieldnames: list[str]) -> dict[str, str]:
    normalized = {name.strip().lower(): name for name in fieldnames}
    missing = [column for column in _REQUIRED_COLUMNS if column not in normalized]
    if missing:
        raise DatasetError(f"UNSW-NB15 CSV is missing required column(s): {missing}")
    return normalized


def load_unsw_nb15(path: Path) -> DatasetLoadResult:
    """Load a UNSW-NB15 training/testing partition CSV into a `DatasetLoadResult`.

    Raises `DatasetError` if the file can't be opened or is missing a
    required column. Per-row parse failures are skipped and counted, not
    raised.
    """
    if not path.is_file():
        raise DatasetError(
            f"UNSW-NB15 dataset file not found at {path}. Download "
            "UNSW_NB15_training-set.csv / UNSW_NB15_testing-set.csv from "
            "https://research.unsw.edu.au/projects/unsw-nb15-dataset and point the "
            "training script at one of the extracted CSV files."
        )

    result = DatasetLoadResult()
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise DatasetError(f"UNSW-NB15 CSV at {path} has no header row")
        header = _build_header_map(list(reader.fieldnames))

        for index, raw_row in enumerate(reader):
            try:
                result.labeled_flows.append(_parse_row(raw_row, header, index))
            except ValueError as exc:
                result.record_skip(str(exc))

    return result


def _parse_row(raw_row: dict[str, str], header: dict[str, str], index: int) -> LabeledFlow:
    def get(column: str) -> str:
        return raw_row[header[column]]

    duration_seconds = parse_float(raw_row, header["dur"])
    protocol = _PROTOCOL_BY_NAME.get(get("proto").strip().lower(), Protocol.OTHER)

    spkts = parse_float(raw_row, header["spkts"])
    dpkts = parse_float(raw_row, header["dpkts"])
    sbytes = parse_float(raw_row, header["sbytes"])
    dbytes = parse_float(raw_row, header["dbytes"])

    smean = parse_float(raw_row, header["smean"])
    dmean = parse_float(raw_row, header["dmean"])
    sinpkt_ms = parse_float(raw_row, header["sinpkt"])
    dinpkt_ms = parse_float(raw_row, header["dinpkt"])

    total_packets = spkts + dpkts
    mean_bytes = (smean * spkts + dmean * dpkts) / total_packets if total_packets > 0 else 0.0
    mean_inter_arrival_seconds = (
        ((sinpkt_ms * spkts + dinpkt_ms * dpkts) / total_packets) / 1000.0 if total_packets > 0 else 0.0
    )
    mean_inter_arrival_seconds = max(mean_inter_arrival_seconds, 0.0)

    attack_cat = get("attack_cat").strip()
    label = attack_cat if attack_cat else ("Attack" if get("label").strip() == "1" else "Normal")

    flow = Flow.model_validate(
        {
            "flow_id": f"unsw-{index}",
            "source_ip": _PLACEHOLDER_SOURCE_IP,
            "destination_ip": _PLACEHOLDER_DESTINATION_IP,
            "source_port": None,
            "destination_port": None,
            "protocol": protocol,
            "first_seen": SYNTHETIC_EPOCH,
            "last_seen": SYNTHETIC_EPOCH + timedelta(seconds=duration_seconds),
            "packet_count": round(spkts) + round(dpkts),
            "byte_count": round(sbytes) + round(dbytes),
            "forward_packet_count": round(spkts),
            "backward_packet_count": round(dpkts),
            "forward_byte_count": round(sbytes),
            "backward_byte_count": round(dbytes),
            "tcp_flags": {},
            "packet_size_stats": {
                "min_bytes": round(max(mean_bytes, 0.0)),
                "max_bytes": round(max(mean_bytes, 0.0)),
                "mean_bytes": max(mean_bytes, 0.0),
                "std_bytes": 0.0,
            },
            "inter_arrival_stats": {
                "min_seconds": mean_inter_arrival_seconds,
                "max_seconds": mean_inter_arrival_seconds,
                "mean_seconds": mean_inter_arrival_seconds,
                "std_seconds": 0.0,
            },
        }
    )
    return LabeledFlow(flow=flow, label=label)

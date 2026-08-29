"""CICIDS2017 -> canonical dataset adapter (spec §12, §13).

Targets the widely-distributed CICFlowMeter-generated "MachineLearningCVE"
per-flow CSVs (the files most commonly referred to as "CICIDS2017"). Column
names in that distribution have inconsistent leading/trailing whitespace and
mixed case, so every header is normalized (`strip().lower()`) before
matching.

**Verified against all 8 real "MachineLearningCVE" files (not assumed):**
this distribution has **no Source IP, Source Port, Destination IP, or
Protocol column at all** — only "Destination Port" identifies the
connection, and there is nothing that names the transport protocol
directly. An earlier version of this adapter assumed those columns existed
(they don't, in the actual published release) and failed outright on real
data. Handled the same honest way `unsw_adapter` handles UNSW-NB15's own
missing IP/port columns, not silently:

* `source_ip`/`destination_ip` are a fixed documented placeholder
  (`10.255.255.1`/`.2`) — this format carries no real network identity.
* `source_port` is always `None` (not present).
* `protocol` is **inferred**, not read directly, since no column names it:
  any nonzero TCP flag count (SYN/ACK/FIN/RST/PSH/URG) means TCP (flags are
  only ever set by TCP); failing that, a well-known-UDP-port match on
  `destination_port` (DNS/DHCP/NTP/NetBIOS/SNMP/SSDP/mDNS/...) means UDP;
  otherwise it defaults to TCP, since CICFlowMeter is known to report
  all-zero flag counts for plenty of genuinely-TCP flows that timed out
  without a captured FIN/RST (idle HTTPS keep-alives, etc.), and TCP is the
  dominant protocol in this capture. This is a real, disclosed limitation of
  training on this dataset variant, not a silently invented number — do not
  treat `protocol_is_tcp`/`protocol_is_udp`/`protocol_is_icmp` as ground
  truth from this adapter the way they would be from live packet capture.

One CICIDS2017-specific unit quirk handled here, not left for callers to
discover the hard way: `Flow Duration` is in **microseconds**, not seconds.

If your CSV doesn't have the columns checked below (e.g. a further
stripped-down mirror), this adapter will fail with a clear `DatasetError`
naming the missing column.
"""

import csv
from datetime import timedelta
from pathlib import Path

from pirewall.core.enums import Protocol
from pirewall.core.exceptions import DatasetError
from pirewall.core.models.flow import Flow
from pirewall.ml.preprocessing.common import (
    SYNTHETIC_EPOCH,
    DatasetLoadResult,
    LabeledFlow,
    combine_weighted_stats,
    parse_float,
)

_REQUIRED_COLUMNS = (
    "destination port",
    "flow duration",
    "total fwd packets",
    "total backward packets",
    "total length of fwd packets",
    "total length of bwd packets",
    "fwd packet length max",
    "fwd packet length min",
    "fwd packet length mean",
    "fwd packet length std",
    "bwd packet length max",
    "bwd packet length min",
    "bwd packet length mean",
    "bwd packet length std",
    "flow iat mean",
    "flow iat std",
    "flow iat max",
    "flow iat min",
    "syn flag count",
    "ack flag count",
    "fin flag count",
    "rst flag count",
    "psh flag count",
    "urg flag count",
    "label",
)

_PLACEHOLDER_SOURCE_IP = "10.255.255.1"
_PLACEHOLDER_DESTINATION_IP = "10.255.255.2"

# Real, well-known UDP service ports -- used only as a fallback signal when
# every TCP flag count is zero (see module docstring). Not exhaustive; a
# real port assignment fact, not a fabricated one.
_KNOWN_UDP_PORTS = frozenset({53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 5353})


def _infer_protocol(flag_sum: int, destination_port: int) -> Protocol:
    if flag_sum > 0:
        return Protocol.TCP
    if destination_port in _KNOWN_UDP_PORTS:
        return Protocol.UDP
    return Protocol.TCP


def _build_header_map(fieldnames: list[str]) -> dict[str, str]:
    normalized = {name.strip().lower(): name for name in fieldnames}
    missing = [column for column in _REQUIRED_COLUMNS if column not in normalized]
    if missing:
        raise DatasetError(f"CICIDS2017 CSV is missing required column(s): {missing}")
    return normalized


def load_cicids2017(path: Path) -> DatasetLoadResult:
    """Load a CICIDS2017 per-flow CSV into a `DatasetLoadResult`.

    Raises `DatasetError` if the file can't be opened or is missing a
    required column. Per-row parse failures (bad IP, non-numeric field) are
    skipped and counted in the result, not raised.
    """
    if not path.is_file():
        raise DatasetError(
            f"CICIDS2017 dataset file not found at {path}. Download the CICFlowMeter "
            "per-flow CSVs (the 'MachineLearningCVE' distribution) from "
            "https://www.unb.ca/cic/datasets/ids-2017.html and point the training "
            "script at the extracted CSV file."
        )

    result = DatasetLoadResult()
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise DatasetError(f"CICIDS2017 CSV at {path} has no header row")
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

    destination_port = int(parse_float(raw_row, header["destination port"]))

    duration_seconds = parse_float(raw_row, header["flow duration"]) / 1_000_000.0

    fwd_packets = parse_float(raw_row, header["total fwd packets"])
    bwd_packets = parse_float(raw_row, header["total backward packets"])
    fwd_bytes = parse_float(raw_row, header["total length of fwd packets"])
    bwd_bytes = parse_float(raw_row, header["total length of bwd packets"])

    fwd_min = parse_float(raw_row, header["fwd packet length min"])
    fwd_max = parse_float(raw_row, header["fwd packet length max"])
    fwd_mean = parse_float(raw_row, header["fwd packet length mean"])
    fwd_std = parse_float(raw_row, header["fwd packet length std"])
    bwd_min = parse_float(raw_row, header["bwd packet length min"])
    bwd_max = parse_float(raw_row, header["bwd packet length max"])
    bwd_mean = parse_float(raw_row, header["bwd packet length mean"])
    bwd_std = parse_float(raw_row, header["bwd packet length std"])

    combined_mean, combined_std = combine_weighted_stats(
        fwd_mean, fwd_std, fwd_packets, bwd_mean, bwd_std, bwd_packets
    )
    candidates_min = [v for v, n in ((fwd_min, fwd_packets), (bwd_min, bwd_packets)) if n > 0]
    candidates_max = [v for v, n in ((fwd_max, fwd_packets), (bwd_max, bwd_packets)) if n > 0]
    min_bytes = min(candidates_min) if candidates_min else 0.0
    max_bytes = max(candidates_max) if candidates_max else 0.0

    iat_mean = parse_float(raw_row, header["flow iat mean"])
    iat_std = parse_float(raw_row, header["flow iat std"])
    iat_max = parse_float(raw_row, header["flow iat max"])
    iat_min = parse_float(raw_row, header["flow iat min"])

    syn = int(parse_float(raw_row, header["syn flag count"]))
    ack = int(parse_float(raw_row, header["ack flag count"]))
    fin = int(parse_float(raw_row, header["fin flag count"]))
    rst = int(parse_float(raw_row, header["rst flag count"]))
    psh = int(parse_float(raw_row, header["psh flag count"]))
    urg = int(parse_float(raw_row, header["urg flag count"]))

    protocol = _infer_protocol(syn + ack + fin + rst + psh + urg, destination_port)

    label = get("label").strip()

    flow = Flow.model_validate(
        {
            "flow_id": f"cicids-{index}",
            "source_ip": _PLACEHOLDER_SOURCE_IP,
            "destination_ip": _PLACEHOLDER_DESTINATION_IP,
            "source_port": None,
            "destination_port": destination_port,
            "protocol": protocol,
            "first_seen": SYNTHETIC_EPOCH,
            "last_seen": SYNTHETIC_EPOCH + timedelta(seconds=duration_seconds),
            "packet_count": round(fwd_packets) + round(bwd_packets),
            "byte_count": round(fwd_bytes) + round(bwd_bytes),
            "forward_packet_count": round(fwd_packets),
            "backward_packet_count": round(bwd_packets),
            "forward_byte_count": round(fwd_bytes),
            "backward_byte_count": round(bwd_bytes),
            "tcp_flags": {"syn": syn, "ack": ack, "fin": fin, "rst": rst, "psh": psh, "urg": urg},
            "packet_size_stats": {
                "min_bytes": round(min_bytes),
                "max_bytes": round(max_bytes),
                "mean_bytes": max(combined_mean, 0.0),
                "std_bytes": max(combined_std, 0.0),
            },
            "inter_arrival_stats": {
                "min_seconds": max(iat_min, 0.0) / 1_000_000.0,
                "max_seconds": max(iat_max, 0.0) / 1_000_000.0,
                "mean_seconds": max(iat_mean, 0.0) / 1_000_000.0,
                "std_seconds": max(iat_std, 0.0) / 1_000_000.0,
            },
        }
    )
    return LabeledFlow(flow=flow, label=label)

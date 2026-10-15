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

**What the size columns actually mean (feature schema 2.0.0).** Measured on
the real CSVs, not assumed: every "Packet Length" / "Total Length of ...
Packets" column is **L4 payload bytes** (84% of benign port-443 flows have
a 0-byte minimum packet, impossible for an IP length), and every std column
is **sample** std (a two-packet flow with sizes 0 and 7 reports 4.9497 =
7/sqrt(2)). They map onto `Flow.payload_stats`, which is what the 2.0.0
extractor reads — schema 1.0.0 put them into the IP-level `byte_count`/
`packet_size_stats` fields that runtime fills with *total* length, which is
the training/runtime mismatch behind docs/KNOWN_ISSUES.md #1-#2.

Two further adjustments, both documented rather than silent:

* **Ethernet padding.** CICFlowMeter computes payload as frame length minus
  headers, so a wired frame padded up to the 60-byte Ethernet minimum
  reports 6 bytes of "payload" for a bare ACK (14% of benign HTTPS flows have
  minimum exactly 6). pirewall computes payload from the IP header's own
  length — and the deployment captures Wi-Fi, which has no padding at all —
  so runtime reports 0 for the same packet. A minimum of 1..6 bytes is
  therefore normalized to 0 here. Sums and means keep the (<= 6 bytes per
  padded packet) inflation, which cannot be undone from aggregate columns.
* **IP-level fields** (`byte_count`, `packet_size_stats`) are not features;
  they are reconstructed as payload + the CSV's own L4 header-length
  columns + a 20-byte IPv4 header per packet, only so the `Flow` is
  internally consistent.

If your CSV doesn't have the columns checked below (e.g. a further
stripped-down mirror), this adapter will fail with a clear `DatasetError`
naming the missing column.
"""

import csv
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

from pirewall.core.enums import Protocol
from pirewall.core.exceptions import DatasetError
from pirewall.core.models.flow import Flow
from pirewall.ml.preprocessing.common import (
    SYNTHETIC_EPOCH,
    DatasetLoadResult,
    LabeledFlow,
    SkipCounter,
    combine_weighted_sample_stats,
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
    "fwd header length",
    "bwd header length",
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
# Largest "payload" CICFlowMeter can report for an empty segment padded to the
# Ethernet minimum frame (60 - 14 Ethernet - 20 IPv4 - 20 TCP).
_MAX_ETHERNET_PADDING_BYTES = 6
_IPV4_HEADER_BYTES = 20

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


def iter_cicids2017(path: Path, skips: SkipCounter | None = None) -> Iterator[LabeledFlow]:
    """Yield one `LabeledFlow` per parseable row, holding only one at a time.

    The streaming counterpart to `load_cicids2017`. It exists because
    `Flow` is a Pydantic model costing ~3.9 KB per row: materialising all
    2.83M CICIDS2017 flows at once needs ~10.2 GB, which does not fit on a
    typical development machine (measured, see `docs/ML_DATA_AUDIT.md` §H).
    Callers that only need features should consume this and let each flow
    be collected immediately.

    Per-row parse failures are recorded in `skips` (if given) and the row
    skipped, matching `load_cicids2017`'s behaviour rather than aborting
    the whole load (spec §13).
    """
    if not path.is_file():
        raise DatasetError(
            f"CICIDS2017 dataset file not found at {path}. Download the CICFlowMeter "
            "per-flow CSVs (the 'MachineLearningCVE' distribution) from "
            "https://www.unb.ca/cic/datasets/ids-2017.html and point the training "
            "script at the extracted CSV file."
        )

    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise DatasetError(f"CICIDS2017 CSV at {path} has no header row")
        header = _build_header_map(list(reader.fieldnames))

        for index, raw_row in enumerate(reader):
            try:
                yield _parse_row(raw_row, header, index)
            except ValueError as exc:
                if skips is not None:
                    skips.record_skip(str(exc))


def load_cicids2017(path: Path) -> DatasetLoadResult:
    """Load a CICIDS2017 per-flow CSV into a `DatasetLoadResult`.

    Raises `DatasetError` if the file can't be opened or is missing a
    required column. Per-row parse failures (bad IP, non-numeric field) are
    skipped and counted in the result, not raised.

    **This holds every flow in memory at once** (~3.9 KB per row). For a
    full-size dataset use `iter_cicids2017` instead — see its docstring.
    """
    result = DatasetLoadResult()
    result.labeled_flows.extend(iter_cicids2017(path, skips=result))
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

    payload_mean, payload_std = combine_weighted_sample_stats(
        fwd_mean, fwd_std, fwd_packets, bwd_mean, bwd_std, bwd_packets
    )
    candidates_min = [v for v, n in ((fwd_min, fwd_packets), (bwd_min, bwd_packets)) if n > 0]
    candidates_max = [v for v, n in ((fwd_max, fwd_packets), (bwd_max, bwd_packets)) if n > 0]
    payload_min = min(candidates_min) if candidates_min else 0.0
    payload_max = max(candidates_max) if candidates_max else 0.0
    if 0 < payload_min <= _MAX_ETHERNET_PADDING_BYTES:
        payload_min = 0.0

    # Not features (see module docstring) -- reconstructed only so the Flow
    # is internally consistent. Header columns are occasionally negative in
    # the published CSVs (a known CICFlowMeter overflow), hence the clamp.
    total_packets = fwd_packets + bwd_packets
    header_bytes = max(parse_float(raw_row, header["fwd header length"]), 0.0) + max(
        parse_float(raw_row, header["bwd header length"]), 0.0
    )
    per_packet_overhead = (
        header_bytes / total_packets + _IPV4_HEADER_BYTES if total_packets > 0 else 0.0
    )
    fwd_ip_bytes = round(fwd_bytes + fwd_packets * per_packet_overhead)
    bwd_ip_bytes = round(bwd_bytes + bwd_packets * per_packet_overhead)

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
            "byte_count": fwd_ip_bytes + bwd_ip_bytes,
            "forward_packet_count": round(fwd_packets),
            "backward_packet_count": round(bwd_packets),
            "forward_byte_count": fwd_ip_bytes,
            "backward_byte_count": bwd_ip_bytes,
            "tcp_flags": {"syn": syn, "ack": ack, "fin": fin, "rst": rst, "psh": psh, "urg": urg},
            "packet_size_stats": {
                "min_bytes": round(payload_min + per_packet_overhead),
                "max_bytes": round(payload_max + per_packet_overhead),
                "mean_bytes": max(payload_mean, 0.0) + per_packet_overhead,
                "std_bytes": max(payload_std, 0.0),
            },
            "payload_stats": {
                "forward_bytes": round(fwd_bytes),
                "backward_bytes": round(bwd_bytes),
                "min_bytes": round(payload_min),
                "max_bytes": round(payload_max),
                "mean_bytes": max(payload_mean, 0.0),
                "std_bytes": max(payload_std, 0.0),
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

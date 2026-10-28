"""Replay pcaps through the runtime flow engine and write one row per flow record.

    uv run python -m scripts.dataset.pcap_to_flows CAPTURE [CAPTURE ...] --out DIR \\
        [--config config/local_config.toml] [--ground-truth ground_truth.jsonl [--strict]] \\
        [--engine auto|native|python] [--continuous] [--env-tag mock|sandbox|pi-live|pi-scripted]

Why this exists (ADDENDUM_4.md D6, audit v1 #4): training features used to
come from CICFlowMeter CSVs, which segment and measure flows differently
from pirewall's own engine. Here every row comes from `FlowEngine.feed`,
the call live capture makes, with the runtime's own flow config (timeouts,
table bound, protected network, sweep cadence), and from
`pirewall.features.extract_features`, the runtime's own extractor. So a
model trained on this output sees the features it will see live, byte for
byte (`tests/integration/test_pcap_to_flows_parity.py`).

**Rows.** One per completed flow record, in completion order: the schema
features (`pirewall.features.schema.FEATURE_NAMES`), flow metadata (the
capture file being read when it completed, MACs, 5-tuple, first/last seen in Unix microseconds) and a
`connection_start` flag (`ConnectionStartTracker`, V2_CONTRACTS §11, the
same class phase 17 counts with live). MACs are metadata for labelling and
identity, never features.

**Clock.** Flows are swept for timeouts on the capture's own clock, every
`flow.cleanup_interval_seconds` of capture time, as core does on the wall
clock. Each capture file is its own stream (a fresh engine and tracker)
unless `--continuous` treats the inputs as one capture in the order given.

**Labels** (optional). `--ground-truth` is JSON lines, one window each:
`{"mac": "02:00:00:00:00:ee", "start": <unix seconds>, "end": <unix seconds>,
"label": "syn_scan"}`. A flow is labelled with the first window whose MAC is
its source or destination MAC and whose time span overlaps the flow's.
Every other flow is `benign`, or `unlabelled` with `--strict`.

**Output.** `DIR/flows.parquet` when pyarrow is already installed (it is not
a pirewall dependency), else `DIR/flows.csv`; and `DIR/manifest.json` with
the input SHA-256s, engine and version, config hash, env tag (D7) and row
counts. Nothing here touches a network interface or needs root.
"""

import argparse
import csv
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Network
from pathlib import Path
from typing import Any, Literal

from pirewall.capture.pcapio import PcapReader, PcapStats, capture_files
from pirewall.config.loader import load_config
from pirewall.config.models import FlowConfig
from pirewall.core.enums import EnvTag
from pirewall.core.exceptions import PirewallError
from pirewall.core.models.flow import Flow
from pirewall.features.extractor import extract_features
from pirewall.features.schema import FEATURE_NAMES, SCHEMA_VERSION
from pirewall.flow.connection_start import ConnectionStartTracker
from pirewall.flow.fallback import FallbackFlowEngine
from pirewall.flow.native import from_microseconds, native_engine_available, to_microseconds

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "config" / "default_config.toml"
TOOL = "scripts/dataset/pcap_to_flows.py"
BENIGN = "benign"
UNLABELLED = "unlabelled"
# Drain the engine this often (frames), as core drains after each ring poll.
_DRAIN_EVERY = 1_000
METADATA_COLUMNS = (
    "source_pcap",
    "source_mac",
    "destination_mac",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "first_seen_us",
    "last_seen_us",
    "connection_start",
)

EngineChoice = Literal["auto", "native", "python"]
Row = dict[str, str | int | float | bool | None]


@dataclass(frozen=True, slots=True)
class GroundTruthWindow:
    """One labelled window: traffic to or from `mac` within [start_us, end_us]."""

    mac: str
    start_us: int
    end_us: int
    label: str


@dataclass(slots=True)
class RunStats:
    """What one conversion did, for the manifest."""

    pcap_stats: list[tuple[Path, PcapStats]] = field(default_factory=list[tuple[Path, PcapStats]])
    frames_seen: int = 0
    frames_malformed: int = 0
    backends_used: set[str] = field(default_factory=set[str])
    panics: int = 0
    fell_back: bool = False
    flows_lost_to_panics: int = 0
    connection_start_evictions: int = 0


def load_ground_truth(path: Path) -> list[GroundTruthWindow]:
    """Parse a `ground_truth.jsonl`. Raises `ValueError` naming the bad line."""
    windows: list[GroundTruthWindow] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            mac = str(entry["mac"]).lower()
            start, end, label = float(entry["start"]), float(entry["end"]), str(entry["label"])
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"{path}:{number}: expected {{mac, start, end, label}}: {exc}") from exc
        if end < start or not label or label in (BENIGN, UNLABELLED):
            raise ValueError(
                f"{path}:{number}: needs end >= start and a label other than {BENIGN}/{UNLABELLED}"
            )
        windows.append(GroundTruthWindow(mac, round(start * 1e6), round(end * 1e6), label))
    return windows


def label_for(flow: Flow, windows: Sequence[GroundTruthWindow], strict: bool) -> str:
    """The first window matching `flow`'s MACs and overlapping its time span, else benign/unlabelled."""
    first_us, last_us = to_microseconds(flow.first_seen), to_microseconds(flow.last_seen)
    macs = {str(flow.source_mac), str(flow.destination_mac)}
    for window in windows:
        if window.mac in macs and first_us <= window.end_us and last_us >= window.start_us:
            return window.label
    return UNLABELLED if strict else BENIGN


def _row(flow: Flow, source: str, connection_start: bool) -> Row:
    vector = extract_features(flow)
    row: Row = {
        "source_pcap": source,
        "source_mac": None if flow.source_mac is None else str(flow.source_mac),
        "destination_mac": None if flow.destination_mac is None else str(flow.destination_mac),
        "source_ip": str(flow.source_ip),
        "destination_ip": str(flow.destination_ip),
        "source_port": flow.source_port,
        "destination_port": flow.destination_port,
        "protocol": flow.protocol.value,
        "first_seen_us": to_microseconds(flow.first_seen),
        "last_seen_us": to_microseconds(flow.last_seen),
        "connection_start": connection_start,
    }
    row.update(zip(vector.feature_names, vector.values, strict=True))
    return row


def _new_engine(
    flow_config: FlowConfig, protected: IPv4Network | None, engine: EngineChoice, max_panics: int
) -> FallbackFlowEngine:
    if engine == "native" and not native_engine_available():
        raise PirewallError("--engine native, but pirewall_native is not installed (uv sync --extra native)")
    return FallbackFlowEngine(
        flow_config, protected, max_panics_per_minute=max_panics, prefer_native=engine != "python"
    )


def _observed(
    records: Iterable[Flow], source: str, tracker: ConnectionStartTracker
) -> Iterable[tuple[Flow, str, bool]]:
    for flow in records:
        yield flow, source, tracker.observe(flow)


def flows_from_captures(
    captures: Sequence[Path],
    flow_config: FlowConfig,
    protected: IPv4Network | None,
    engine: EngineChoice = "auto",
    continuous: bool = False,
    max_panics_per_minute: int = 5,
    stats: RunStats | None = None,
) -> Iterable[tuple[Flow, str, bool]]:
    """Yield `(flow, capture file, connection_start)` for every record, in completion order.

    The capture file is the one being read when the record completed (with
    `--continuous`, a flow can start in the previous file).
    """
    stats = stats if stats is not None else RunStats()
    streams: list[list[Path]] = [list(captures)] if continuous else [[path] for path in captures]
    interval_us = flow_config.cleanup_interval_seconds * 1_000_000
    for stream in streams:
        flows = _new_engine(flow_config, protected, engine, max_panics_per_minute)
        tracker = ConnectionStartTracker(flow_config.connection_start_max_tracked)
        next_sweep_us: int | None = None
        source = stream[0].name
        fed = 0
        for path in stream:
            source = path.name
            reader = PcapReader(path)
            stats.pcap_stats.append((path, reader.stats))
            for record in reader:
                if next_sweep_us is None:
                    next_sweep_us = record.ts_us + interval_us
                elif record.ts_us >= next_sweep_us:
                    # The last sweep tick at or before this frame; one sweep
                    # there closes everything the skipped ticks would have.
                    ticks = (record.ts_us - next_sweep_us) // interval_us
                    sweep_at = next_sweep_us + ticks * interval_us
                    yield from _observed(flows.drain().completed, source, tracker)
                    yield from _observed(flows.sweep_timeouts(from_microseconds(sweep_at)), source, tracker)
                    next_sweep_us = sweep_at + interval_us
                flows.feed_us(record.data, record.ts_us)
                fed += 1
                if fed % _DRAIN_EVERY == 0:
                    yield from _observed(flows.drain().completed, source, tracker)
        yield from _observed(flows.drain().completed, source, tracker)
        yield from _observed(flows.flush(), source, tracker)
        seen, malformed = flows.counters()
        stats.frames_seen += seen
        stats.frames_malformed += malformed
        stats.backends_used.add(flows.backend)
        stats.panics += flows.budget.total
        stats.fell_back = stats.fell_back or flows.budget.exhausted
        stats.flows_lost_to_panics += flows.flows_lost_to_panics
        stats.connection_start_evictions += tracker.evictions


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_config_fingerprint(
    flow_config: FlowConfig, protected: IPv4Network | None, max_panics_per_minute: int
) -> dict[str, object]:
    """Every setting that shapes a row: hashed into the manifest."""
    return {
        "flow": flow_config.model_dump(mode="json"),
        "protected_network": None if protected is None else str(protected),
        "native_max_panics_per_minute": max_panics_per_minute,
        "drain_every_frames": _DRAIN_EVERY,
        "feature_schema_version": SCHEMA_VERSION,
    }


def _native_version() -> str | None:
    try:
        return importlib.metadata.version("pirewall-native")
    except importlib.metadata.PackageNotFoundError:
        return None


def _write_rows(rows: list[Row], columns: list[str], out_dir: Path) -> tuple[Path, str]:
    if importlib.util.find_spec("pyarrow") is not None:
        # pyarrow is optional and untyped here; only used when already installed.
        pa: Any = importlib.import_module("pyarrow")  # Any: optional, unstubbed module
        pq: Any = importlib.import_module("pyarrow.parquet")  # Any: optional, unstubbed module
        table = pa.Table.from_pylist(rows) if rows else pa.table({name: [] for name in columns})
        path = out_dir / "flows.parquet"
        pq.write_table(table, path)
        return path, "parquet"
    path = out_dir / "flows.csv"
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    return path, "csv"


def convert(
    inputs: Sequence[Path],
    out_dir: Path,
    flow_config: FlowConfig,
    protected: IPv4Network | None,
    env_tag: EnvTag,
    engine: EngineChoice = "auto",
    continuous: bool = False,
    ground_truth: Path | None = None,
    strict: bool = False,
    max_panics_per_minute: int = 5,
) -> dict[str, object]:
    """Convert `inputs` (files or directories) into `out_dir`; returns the manifest written there."""
    captures = [path for source in inputs for path in capture_files(source)]
    windows = load_ground_truth(ground_truth) if ground_truth is not None else None
    stats = RunStats()
    rows: list[Row] = []
    labels: Counter[str] = Counter()
    starts = 0
    for flow, source, connection_start in flows_from_captures(
        captures, flow_config, protected, engine, continuous, max_panics_per_minute, stats
    ):
        row = _row(flow, source, connection_start)
        if windows is not None:
            row["label"] = label_for(flow, windows, strict)
            labels[str(row["label"])] += 1
        starts += connection_start
        rows.append(row)

    columns = [*METADATA_COLUMNS, *(["label"] if windows is not None else []), *FEATURE_NAMES]
    out_dir.mkdir(parents=True, exist_ok=True)
    output, output_format = _write_rows(rows, columns, out_dir)
    fingerprint = runtime_config_fingerprint(flow_config, protected, max_panics_per_minute)
    manifest: dict[str, object] = {
        "tool": TOOL,
        "env_tag": env_tag.value,
        "created_at": datetime.now(UTC).isoformat(),
        "engine": {
            "requested": engine,
            "backends_used": sorted(stats.backends_used),
            "pirewall_native_version": _native_version(),
            "panics_caught": stats.panics,
            "fell_back_to_python": stats.fell_back,
            "flows_lost_to_panics": stats.flows_lost_to_panics,
        },
        "feature_schema_version": SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "config": fingerprint,
        "config_sha256": hashlib.sha256(json.dumps(fingerprint, sort_keys=True).encode()).hexdigest(),
        "continuous": continuous,
        "inputs": [
            {
                "path": str(path),
                "sha256": _sha256(path),
                "bytes": path.stat().st_size,
                "records": pcap.records,
                "truncated_records": pcap.truncated_records,
                "skipped_non_ethernet": pcap.skipped_non_ethernet,
                "skipped_without_timestamp": pcap.skipped_without_timestamp,
                "truncated_tail": pcap.truncated_tail,
            }
            for path, pcap in stats.pcap_stats
        ],
        "frames": {"seen": stats.frames_seen, "malformed_or_unsupported": stats.frames_malformed},
        "ground_truth": None
        if ground_truth is None
        else {"path": str(ground_truth), "sha256": _sha256(ground_truth), "strict": strict,
              "windows": len(windows or [])},
        "rows": {
            "total": len(rows),
            "connection_starts": starts,
            "by_label": dict(sorted(labels.items())) if windows is not None else None,
        },
        "connection_start": {
            "max_tracked": flow_config.connection_start_max_tracked,
            "evictions": stats.connection_start_evictions,
        },
        "output": {"path": output.name, "format": output_format, "columns": columns},
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("inputs", nargs="+", type=Path, help="pcap/pcapng files or directories of them")
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="pirewall config (flow settings)")
    parser.add_argument("--ground-truth", type=Path, help="ground_truth.jsonl (attacker MAC + time window)")
    parser.add_argument("--strict", action="store_true", help="unmatched flows are 'unlabelled', not benign")
    parser.add_argument("--engine", choices=("auto", "native", "python"), default="auto")
    parser.add_argument("--continuous", action="store_true", help="treat all inputs as one capture")
    parser.add_argument(
        "--env-tag",
        choices=[tag.value for tag in EnvTag],
        help="ADDENDUM_4.md D7 tag for every artifact written (default: the config's lab.env_tag)",
    )
    args = parser.parse_args(argv)
    if args.strict and args.ground_truth is None:
        parser.error("--strict needs --ground-truth")
    try:
        config = load_config(args.config)
        manifest = convert(
            inputs=args.inputs,
            out_dir=args.out,
            flow_config=config.flow,
            protected=config.network.protected_network,
            env_tag=EnvTag(args.env_tag) if args.env_tag else config.lab.env_tag,
            engine=args.engine,
            continuous=args.continuous,
            ground_truth=args.ground_truth,
            strict=args.strict,
            max_panics_per_minute=config.capture.native_max_panics_per_minute,
        )
    except (PirewallError, OSError, ValueError) as exc:
        print(f"pcap_to_flows: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"rows": manifest["rows"], "engine": manifest["engine"],
                      "output": manifest["output"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

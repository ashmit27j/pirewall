"""Fit the D1 thresholds from benign `pcap_to_flows` output (ADDENDUM_4.md D4, PLAN_FINAL §4.5).

    uv run python -m scripts.train.fit_d1_thresholds FLOWS_DIR [FLOWS_DIR ...] \\
        [--out config/d1_thresholds.toml] [--config config/local_config.toml] \\
        [--margin 1.5] [--train-fraction 0.75 | --block-start UNIX --block-end UNIX] \\
        [--exclude-mac MAC ...] [--freeze]
    uv run python -m scripts.train.fit_d1_thresholds --floors-only [--out ...]

**What it does.** Reads each directory's `flows.csv` and `manifest.json`
(written by `scripts/dataset/pcap_to_flows.py`), keeps the benign rows of
the *training block*, replays their connection starts in time order
through `pirewall.detection_v2.d1.D1State` — the class core runs live, with
the same `measure_*` functions — and records every detector's value at
every start. Each threshold is then
`clamp(P99.9 x margin, floor, ceiling)` with the documented priors
(`pirewall.detection_v2.thresholds.DEFAULT_PRIORS`).

* **Benign only.** Rows labelled anything but `benign` are dropped; a
  directory without labels is refused unless `--assume-benign` (critique
  redteam item 11: a poisoned soak inflates the quantiles). Lab/attack
  MACs can be excluded with `--exclude-mac`.
* **The training block** is the first `--train-fraction` of the benign
  time span (default 0.75; the rest is the held-out test block,
  critique_round2 item 9), or exactly `[--block-start, --block-end)`.
* **Deterministic.** Same inputs, same arguments -> byte-identical file.
* **Provenance** in the file: each input's manifest SHA-256 and env tag,
  the block boundaries, margin, and per-threshold sample counts.
  Inputs with different env tags are refused (D7: never mixed).
* Detectors the rows cannot measure (new-lease rate, portal failures,
  slow-rate DoS: no lease, portal or open-flow data in flow rows) keep
  their floors, recorded with `samples = 0`.
* `--freeze` writes `frozen = true`; the phase-18 harness checks it before
  campaign #2. `--floors-only` writes the floors with `frozen = false`, the
  shipped default until real benign data exists.

Fitting on real `pi-live` data is Environment-dependent (RUNBOOK H20).
No network access, no root.
"""

import argparse
import csv
import hashlib
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

from pirewall.config.loader import load_config
from pirewall.config.models import D1Config
from pirewall.detection_v2.d1 import D1State, start_from_features
from pirewall.detection_v2.thresholds import (
    DEFAULT_PRIORS,
    D1ThresholdFile,
    ThresholdEntry,
    ThresholdKey,
    assemble_thresholds,
    dump_thresholds,
    floors_file,
    threshold_from_benign,
)
from pirewall.features.schema import FEATURE_NAMES

DEFAULT_OUT = Path("config/d1_thresholds.toml")
DEFAULT_MARGIN = 1.5
DEFAULT_TRAIN_FRACTION = 0.75
_BENIGN = "benign"


class FitError(Exception):
    """A refusal with a message for the operator (exit 2)."""


@dataclass(frozen=True, slots=True)
class _Input:
    directory: Path
    manifest_sha256: str
    env_tag: str


@dataclass(frozen=True, slots=True)
class _Row:
    at_us: int
    source_mac: str | None
    source_ip: IPv4Address
    destination_ip: IPv4Address
    destination_port: int | None
    connection_start: bool
    features: dict[str, float]


def _read_input(directory: Path, assume_benign: bool, exclude: frozenset[str]) -> tuple[_Input, list[_Row]]:
    manifest_path = directory / "manifest.json"
    flows_path = directory / "flows.csv"
    if not manifest_path.is_file() or not flows_path.is_file():
        raise FitError(f"{directory}: needs flows.csv and manifest.json from pcap_to_flows (CSV output)")
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    env_tag = str(manifest.get("env_tag", "unknown"))
    rows: list[_Row] = []
    with flows_path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        labelled = reader.fieldnames is not None and "label" in reader.fieldnames
        if not labelled and not assume_benign:
            raise FitError(
                f"{directory}: rows carry no label column; pass --assume-benign if it is all benign"
            )
        for raw in reader:
            if labelled and raw.get("label") != _BENIGN:
                continue
            mac = raw.get("source_mac") or None
            if mac is not None and mac.lower() in exclude:
                continue
            if raw.get("protocol") != "tcp":
                continue
            port = raw.get("destination_port")
            rows.append(
                _Row(
                    at_us=int(raw["first_seen_us"]),
                    source_mac=mac,
                    source_ip=IPv4Address(raw["source_ip"]),
                    destination_ip=IPv4Address(raw["destination_ip"]),
                    # The feature column of the same name overwrites it in pcap_to_flows rows: "443.0".
                    destination_port=int(float(port)) if port else None,
                    connection_start=raw.get("connection_start") in ("True", "true", "1"),
                    features={name: float(raw[name]) for name in FEATURE_NAMES},
                )
            )
    return _Input(directory, hashlib.sha256(manifest_bytes).hexdigest(), env_tag), rows


def _block(rows: Sequence[_Row], fraction: float, start: float | None, end: float | None) -> tuple[int, int]:
    if start is not None and end is not None:
        return int(start * 1_000_000), int(end * 1_000_000)
    first = min(row.at_us for row in rows)
    last = max(row.at_us for row in rows)
    return first, first + int((last - first) * fraction) + 1


def _measure(rows: Sequence[_Row], config: D1Config) -> dict[ThresholdKey, list[float]]:
    """Replay the training block's starts through `D1State`; collect each detector's value per start."""
    # Thresholds are irrelevant to measurement; the floors file only satisfies the constructor.
    state = D1State(config, floors_file(config.windows_seconds, {}))
    samples: dict[ThresholdKey, list[float]] = {}
    for row in rows:
        start = start_from_features(
            is_start=row.connection_start,
            source_mac=row.source_mac,
            source_ip=row.source_ip,
            destination_ip=row.destination_ip,
            destination_port=row.destination_port,
            first_seen=datetime.fromtimestamp(row.at_us / 1_000_000, UTC),
            features=row.features,
        )
        if start is None:
            continue
        state.observe(start)
        measured = {
            **state.measure_device(start.mac, start.at),
            **state.measure_destination(start.destination_ip, start.at),
            **state.measure_global(start.at),
        }
        for key, value in measured.items():
            samples.setdefault(key, []).append(value)
    return samples


_UNMEASURABLE = ("new_lease_rate", "portal_auth_failures", "slow_rate_dos")


def fit(
    directories: Sequence[Path],
    *,
    config: D1Config,
    margin: float,
    train_fraction: float,
    block_start: float | None,
    block_end: float | None,
    exclude: Sequence[str],
    assume_benign: bool,
    freeze: bool,
) -> D1ThresholdFile:
    """Fit thresholds from `directories`. Raises `FitError`."""
    excluded = frozenset(mac.lower() for mac in exclude)
    inputs: list[_Input] = []
    rows: list[_Row] = []
    for directory in directories:
        item, found = _read_input(directory, assume_benign, excluded)
        inputs.append(item)
        rows.extend(found)
    tags = {item.env_tag for item in inputs}
    if len(tags) != 1:
        raise FitError(f"inputs mix env tags {sorted(tags)}; fit each tag separately (D7)")
    if not rows:
        raise FitError("no benign TCP rows in the inputs")
    rows.sort(key=lambda row: (row.at_us, str(row.source_ip), row.destination_port or 0))
    low, high = _block(rows, train_fraction, block_start, block_end)
    block = [row for row in rows if low <= row.at_us < high]
    if not block:
        raise FitError("the training block holds no rows")
    samples = _measure(block, config)
    entries: list[ThresholdEntry] = []
    for key, prior in sorted(DEFAULT_PRIORS.items()):
        if key.window_seconds not in config.windows_seconds:
            continue
        values = samples.get(key, [])
        if not values or key.detector.value in _UNMEASURABLE:
            entries.append(
                ThresholdEntry(name=str(key), value=prior.floor, floor=prior.floor, ceiling=prior.ceiling)
            )
            continue
        value, p999 = threshold_from_benign(values, margin, prior)
        entries.append(
            ThresholdEntry(
                name=str(key),
                value=value,
                floor=prior.floor,
                ceiling=prior.ceiling,
                benign_p999=p999,
                margin=margin,
                samples=len(values),
            )
        )
    provenance: dict[str, str | int | float | bool | list[str]] = {
        "source": "fitted",
        "env_tag": tags.pop(),
        "inputs": [f"{item.directory.name}:{item.manifest_sha256}" for item in inputs],
        "block_start_us": low,
        "block_end_us": high,
        "block_rows": len(block),
        "margin": margin,
        "excluded_macs": sorted(excluded),
    }
    return assemble_thresholds(entries, frozen=freeze, provenance=provenance)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Exit 0 on success, 2 on a refusal."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("inputs", nargs="*", type=Path, help="pcap_to_flows output directories")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--config", type=Path, default=None, help="pirewall config ([d1] windows and bounds)")
    parser.add_argument("--margin", type=float, default=DEFAULT_MARGIN)
    parser.add_argument("--train-fraction", type=float, default=DEFAULT_TRAIN_FRACTION)
    parser.add_argument("--block-start", type=float, default=None, help="training block start, Unix seconds")
    parser.add_argument("--block-end", type=float, default=None, help="training block end, Unix seconds")
    parser.add_argument("--exclude-mac", action="append", default=[], help="lab/attack MAC to leave out")
    parser.add_argument("--assume-benign", action="store_true", help="inputs without labels are all benign")
    parser.add_argument("--freeze", action="store_true", help="write frozen = true (before campaign #2)")
    parser.add_argument(
        "--floors-only", action="store_true", help="write the documented floors, frozen = false"
    )
    args = parser.parse_args(argv)
    d1 = load_config(args.config).d1 if args.config is not None else D1Config()
    try:
        if args.floors_only:
            result = floors_file(d1.windows_seconds, {"note": "no benign data fitted yet"})
        else:
            if not args.inputs:
                raise FitError("give pcap_to_flows output directories, or --floors-only")
            if (args.block_start is None) != (args.block_end is None):
                raise FitError("--block-start and --block-end go together")
            if not 0.0 < args.train_fraction <= 1.0:
                raise FitError("--train-fraction must be in (0, 1]")
            if args.margin <= 0:
                raise FitError("--margin must be positive")
            result = fit(
                args.inputs,
                config=d1,
                margin=args.margin,
                train_fraction=args.train_fraction,
                block_start=args.block_start,
                block_end=args.block_end,
                exclude=args.exclude_mac,
                assume_benign=args.assume_benign,
                freeze=args.freeze,
            )
    except FitError as exc:
        print(f"fit_d1_thresholds: {exc}", file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(dump_thresholds(result), encoding="utf-8", newline="\n")
    print(
        f"wrote {args.out}: {len(result.thresholds)} thresholds, "
        f"frozen={result.frozen}, sha256={result.sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

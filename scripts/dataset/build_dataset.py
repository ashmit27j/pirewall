"""Build leak-free D2/D3 datasets from `pcap_to_flows` output (phase 19).

    uv run python -m scripts.dataset.build_dataset FLOWS_DIR [FLOWS_DIR ...] \\
        --out DIR \\
        [--allow-mixed-benign pi-live,pi-scripted] \\
        [--max-rows-per-run 5000] [--seed 42] \\
        [--benign-gap-hours 1.0] \\
        [--held-out-tool masscan] [--parameter-holdout-suffix random] \\
        [--assume-benign] [--allow-test-rewrite]

**Inputs.** Each directory must contain `flows.csv` and `manifest.json` from
`scripts/dataset/pcap_to_flows.py --schema 3.0.0`. Rows may carry a `label`
column (from `--ground-truth`); a directory without one is treated as benign
and recorded as such (`--assume-benign` is the explicit opt-in for auditing
that choice). If the manifest points at a ground-truth JSONL, its optional
`run_id`/`tool`/`pcap` fields enrich the run metadata; otherwise the capture
stem is the run ID and the label is the tool.

**Splits** (`docs/v2/critique_ml.md` §4):

* Benign is temporal: the first 60% of the *usable* span trains, the next 15%
  validates, a gap of at least `--benign-gap-hours` is discarded, and the
  final 25% is the test block. A connection that would straddle a boundary
  is dropped whole (and counted), so no 5-tuple spans splits.
* Attacks are grouped by run ID. Runs whose tool/label/run matches
  `--held-out-tool` (default `masscan`) form the leave-one-tool-out set;
  runs whose label ends in `--parameter-holdout-suffix` (default `random`)
  form the parameter-variant set; a deterministic 20% of each tool's
  remaining runs is the run-holdout test set; every fourth remaining run is
  validation; the rest train. No run is ever in two splits.
* Rows are capped per `(run_id)` with a seeded sample so one flood cannot
  dominate the matrix. The cap is recorded, not silently applied.

**Provenance.** Every split file gets a SHA-256 in `dataset_manifest.json`
alongside the input manifest hashes, env tags, schema version, seeds and the
actual block boundaries. Every test split written is appended to
`test_access_ledger.jsonl` in the output directory (append-only). Rebuilding
a different test set into the same directory is refused unless
`--allow-test-rewrite` is passed, and that override is itself recorded.

**Env tags (ADDENDUM_4 D7).** A dataset spanning several tags is refused.
`--allow-mixed-benign pi-live,pi-scripted` permits the named tags only when
the benign side is the mixed party; the choice is recorded in the manifest.
`mock` work must stay labelled `mock` — this tool never relabels it.

No network access, no root.
"""

import argparse
import csv
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pirewall.core.enums import EnvTag
from pirewall.features.schema import SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS, feature_names

BENIGN = "benign"
UNLABELLED = "unlabelled"
BUILDER_VERSION = "1.0.0"
LEDGER_NAME = "test_access_ledger.jsonl"
MANIFEST_NAME = "dataset_manifest.json"
SPLIT_COLUMNS = ("run_id", "tool", "family", "env_tag", "split")
_METADATA_COLUMNS = (
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
SplitName = Literal[
    "benign_train",
    "benign_validation",
    "benign_gap",
    "benign_test",
    "attack_train",
    "attack_validation",
    "attack_test_run_holdout",
    "attack_test_leave_one_tool_out",
    "attack_test_parameter_holdout",
]
TEST_SPLITS: tuple[SplitName, ...] = (
    "benign_test",
    "attack_test_run_holdout",
    "attack_test_leave_one_tool_out",
    "attack_test_parameter_holdout",
)
Row = dict[str, str]


class DatasetError(Exception):
    """A refusal with an operator-actionable message (exit 2)."""


@dataclass(slots=True)
class _Input:
    directory: Path
    manifest_sha256: str
    env_tag: str
    schema_version: str
    rows: list[Row] = field(default_factory=list)
    labelled: bool = False
    role: str = BENIGN


@dataclass(frozen=True, slots=True)
class _GroundTruthRun:
    run_id: str | None
    tool: str | None


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_ground_truth_runs(path: Path) -> dict[tuple[str, str], _GroundTruthRun]:
    """Map `(pcap basename, label)` to the harness's optional run/tool metadata."""
    mapping: dict[tuple[str, str], _GroundTruthRun] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        label = str(entry.get("label", ""))
        pcap = entry.get("pcap") or entry.get("pcap_file") or entry.get("capture")
        pcap_name = Path(str(pcap)).name if pcap else ""
        run_id = entry.get("run_id")
        tool = entry.get("tool")
        mapping[(pcap_name, label)] = _GroundTruthRun(
            run_id=None if run_id is None else str(run_id),
            tool=None if tool is None else str(tool),
        )
    return mapping


def _read_input(directory: Path, assume_benign: bool) -> tuple[_Input, Counter[str]]:
    manifest_path = directory / "manifest.json"
    flows_path = directory / "flows.csv"
    if not manifest_path.is_file() or not flows_path.is_file():
        raise DatasetError(
            f"{directory}: needs flows.csv and manifest.json from pcap_to_flows (CSV output)"
        )
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    schema_version = str(manifest.get("feature_schema_version", ""))
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise DatasetError(
            f"{directory}: unsupported feature schema {schema_version!r}; "
            f"expected one of {SUPPORTED_SCHEMA_VERSIONS}"
        )
    if schema_version != SCHEMA_VERSION:
        raise DatasetError(
            f"{directory}: schema {schema_version!r}; phase-19 training needs "
            f"{SCHEMA_VERSION!r} rows (rerun pcap_to_flows --schema {SCHEMA_VERSION})"
        )
    names = feature_names(schema_version)
    manifest_names = manifest.get("feature_names")
    if manifest_names is not None and tuple(manifest_names) != names:
        raise DatasetError(f"{directory}: manifest feature_names disagree with schema {schema_version}")

    truth: dict[tuple[str, str], _GroundTruthRun] = {}
    ground_truth = manifest.get("ground_truth")
    if isinstance(ground_truth, dict) and ground_truth.get("path"):
        truth_path = Path(str(ground_truth["path"]))
        if truth_path.is_file():
            truth = _read_ground_truth_runs(truth_path)

    rows: list[Row] = []
    dropped: Counter[str] = Counter()
    with flows_path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        fieldnames = reader.fieldnames or []
        labelled = "label" in fieldnames
        missing = [name for name in (*_METADATA_COLUMNS, *names) if name not in fieldnames]
        if missing:
            raise DatasetError(f"{directory}: flows.csv is missing columns {missing}")
        for raw in reader:
            label = raw.get("label", BENIGN) or BENIGN
            if label == UNLABELLED:
                dropped["unlabelled"] += 1
                continue
            if not labelled and not assume_benign:
                raise DatasetError(
                    f"{directory}: rows carry no label column; pass --assume-benign for a "
                    "benign-only capture"
                )
            if labelled and label != BENIGN and any(
                raw.get(name) in (None, "") for name in ("source_ip", "first_seen_us")
            ):
                dropped["unparseable"] += 1
                continue
            try:
                int(raw["first_seen_us"])
                int(raw["last_seen_us"])
            except (KeyError, ValueError):
                dropped["bad_timestamp"] += 1
                continue
            pcap = Path(raw.get("source_pcap", "")).name
            meta = truth.get((pcap, label), _GroundTruthRun(None, None))
            run_id = meta.run_id or Path(pcap).stem or label
            tool = meta.tool or label or "unknown"
            enriched = dict(raw)
            enriched.update(
                {
                    "label": label,
                    "run_id": run_id,
                    "tool": tool,
                    "family": _family_for(label),
                    "env_tag": str(manifest.get("env_tag", "unknown")),
                }
            )
            rows.append(enriched)
    if not rows:
        raise DatasetError(f"{directory}: no usable rows")
    role = BENIGN if all(row["label"] == BENIGN for row in rows) else "attack"
    item = _Input(
        directory=directory,
        manifest_sha256=_sha256_bytes(manifest_bytes),
        env_tag=str(manifest.get("env_tag", "unknown")),
        schema_version=schema_version,
        rows=rows,
        labelled=labelled,
        role=role,
    )
    return item, dropped


def _family_for(label: str) -> str:
    """Coarse attack family head (phase 19 D3). Documented heuristic, not a label."""
    text = label.lower()
    if "slow" in text or "loris" in text:
        return "slow_dos"
    if any(word in text for word in ("scan", "masscan", "nmap", "rustscan")):
        return "scan"
    if any(word in text for word in ("brute", "patator", "hydra")):
        return "bruteforce"
    if any(word in text for word in ("flood", "ddos", "dos")):
        return "flood"
    if any(word in text for word in ("spoof", "poison", "churn", "arp")):
        return "spoof"
    return label


def _connection_key(row: Row) -> tuple[str, ...]:
    return (
        row.get("source_ip", ""),
        row.get("source_port", ""),
        row.get("destination_ip", ""),
        row.get("destination_port", ""),
        row.get("protocol", ""),
    )


def _cap_per_run(rows: Sequence[Row], max_rows: int, seed: int) -> tuple[list[Row], dict[str, int]]:
    if max_rows <= 0:
        return list(rows), {}
    grouped: dict[str, list[Row]] = defaultdict(list)
    for row in rows:
        grouped[row["run_id"]].append(row)
    kept: list[Row] = []
    capped: dict[str, int] = {}
    for run_id, group in sorted(grouped.items()):
        ordered = sorted(
            group,
            key=lambda row: (
                int(row["first_seen_us"]),
                row.get("source_ip", ""),
                row.get("source_port", ""),
                row.get("destination_ip", ""),
                row.get("destination_port", ""),
            ),
        )
        if len(ordered) <= max_rows:
            kept.extend(ordered)
            continue
        rng = random.Random(f"{seed}:{run_id}")
        sample = sorted(rng.sample(ordered, max_rows), key=lambda row: int(row["first_seen_us"]))
        kept.extend(sample)
        capped[run_id] = len(ordered) - max_rows
    return kept, capped


def _row_blocks(row: Row, boundaries: Sequence[int]) -> set[int]:
    """Every block a row's [first, last] interval touches."""
    first = int(row["first_seen_us"])
    last = int(row["last_seen_us"])
    start_block = sum(1 for boundary in boundaries if first >= boundary)
    end_block = sum(1 for boundary in boundaries if last >= boundary)
    return set(range(start_block, end_block + 1))


def _crossing_connections(rows: Sequence[Row], boundaries: Sequence[int]) -> set[tuple[str, ...]]:
    """Connections whose rows (or whose own interval) touch more than one block."""
    blocks: dict[tuple[str, ...], set[int]] = defaultdict(set)
    for row in rows:
        blocks[_connection_key(row)].update(_row_blocks(row, boundaries))
    return {key for key, found in blocks.items() if len(found) > 1}



def _split_benign(
    rows: Sequence[Row], *, gap_hours: float
) -> tuple[dict[SplitName, list[Row]], dict[str, object], int]:
    if not rows:
        raise DatasetError("no benign rows")
    gap_us = round(gap_hours * 3_600_000_000)
    first = min(int(row["first_seen_us"]) for row in rows)
    last = max(int(row["last_seen_us"]) for row in rows)
    span = last - first
    if span <= gap_us:
        raise DatasetError(
            f"benign span {span / 3_600_000_000:.3f} h is not longer than the "
            f"{gap_hours:g} h gap; capture more benign traffic"
        )
    usable = span - gap_us
    train_end = first + round(0.60 * usable)
    validation_end = first + round(0.75 * usable)
    gap_end = validation_end + gap_us
    test_start = gap_end
    boundaries = (train_end, validation_end, test_start)

    # A connection whose rows fall on different sides of a boundary is
    # dropped whole; percentages may shift slightly, but no 5-tuple leaks.
    dropped_keys = _crossing_connections(rows, boundaries)

    splits: dict[SplitName, list[Row]] = {
        "benign_train": [],
        "benign_validation": [],
        "benign_gap": [],
        "benign_test": [],
    }
    for row in rows:
        if _connection_key(row) in dropped_keys:
            continue
        at = int(row["first_seen_us"])
        if at < train_end:
            splits["benign_train"].append(row)
        elif at < validation_end:
            splits["benign_validation"].append(row)
        elif at < gap_end:
            splits["benign_gap"].append(row)
        else:
            splits["benign_test"].append(row)
    for name in ("benign_train", "benign_validation", "benign_test"):
        if not splits[name]:  # type: ignore[literal-required]
            raise DatasetError(
                f"{name} is empty after the temporal/gap split; capture more benign traffic "
                "or shorten --benign-gap-hours"
            )
    bounds: dict[str, object] = {
        "first_us": first,
        "last_us": last,
        "train_end_us": train_end,
        "validation_end_us": validation_end,
        "gap_end_us": gap_end,
        "test_start_us": test_start,
        "gap_us": gap_us,
        "dropped_crossing_connections": len(dropped_keys),
    }
    return splits, bounds, len(dropped_keys)


def _held_out_tool(row: Row, tool: str) -> bool:
    needle = tool.lower()
    return any(
        needle in str(row.get(field, "")).lower()
        for field in ("tool", "label", "run_id", "family")
    )


def _split_attacks(
    rows: Sequence[Row],
    *,
    held_out_tool: str,
    parameter_suffix: str,
) -> tuple[dict[SplitName, list[Row]], dict[str, object]]:
    if not rows:
        return {}, {"runs": 0}
    by_run: dict[str, list[Row]] = defaultdict(list)
    for row in rows:
        by_run[row["run_id"]].append(row)
    run_tool = {run: group[0].get("tool", "unknown") for run, group in by_run.items()}
    runs = sorted(by_run)
    tool_holdout = {run for run in runs if _held_out_tool(by_run[run][0], held_out_tool)}
    parameter_holdout = {
        run
        for run in runs
        if run not in tool_holdout
        and any(
            str(row.get("label", "")).lower().endswith(parameter_suffix.lower())
            for row in by_run[run]
        )
    }
    remaining = [run for run in runs if run not in tool_holdout | parameter_holdout]
    if not remaining:
        raise DatasetError("no attack runs left for training after the tool/parameter holdouts")
    by_tool: dict[str, list[str]] = defaultdict(list)
    for run in remaining:
        by_tool[run_tool[run]].append(run)
    run_holdout: set[str] = set()
    for _tool, tool_runs in sorted(by_tool.items()):
        ordered = sorted(tool_runs)
        # Never hold out a tool's only run: that would leave the tool with
        # no training example at all. With two runs, one may be held out.
        if len(ordered) < 2:
            continue
        count = min(max(1, round(0.20 * len(ordered))), len(ordered) - 1)
        run_holdout.update(ordered[-count:])
    training_candidates = [run for run in remaining if run not in run_holdout]
    validation = {run for index, run in enumerate(sorted(training_candidates)) if index % 4 == 0}
    training = {run for run in training_candidates if run not in validation}
    if not training:
        raise DatasetError("no attack runs left for training; add more runs")

    assignment: dict[str, SplitName] = {}
    for run in tool_holdout:
        assignment[run] = "attack_test_leave_one_tool_out"
    for run in parameter_holdout:
        assignment[run] = "attack_test_parameter_holdout"
    for run in run_holdout:
        assignment[run] = "attack_test_run_holdout"
    for run in validation:
        assignment[run] = "attack_validation"
    for run in training:
        assignment[run] = "attack_train"

    splits: dict[SplitName, list[Row]] = {
        "attack_train": [],
        "attack_validation": [],
        "attack_test_run_holdout": [],
        "attack_test_leave_one_tool_out": [],
        "attack_test_parameter_holdout": [],
    }
    for run, group in by_run.items():
        splits[assignment[run]].extend(group)

    # Run-level assignment should already keep every 5-tuple whole; verify it
    # rather than trusting that attack runs never overlap in time.
    owners: dict[tuple[str, ...], set[SplitName]] = defaultdict(set)
    for name, group in splits.items():
        for row in group:
            owners[_connection_key(row)].add(name)
    leaked = {key: sorted(names) for key, names in owners.items() if len(names) > 1}
    if leaked:
        example = next(iter(leaked.items()))
        raise DatasetError(
            f"a connection spans attack splits ({example[0]} -> {example[1]}); "
            "this should be impossible with run grouping"
        )
    return splits, {
        "runs": len(runs),
        "tool_holdout_runs": sorted(tool_holdout),
        "parameter_holdout_runs": sorted(parameter_holdout),
        "run_holdout_runs": sorted(run_holdout),
        "validation_runs": sorted(validation),
        "training_runs": sorted(training),
    }


def _write_split(path: Path, rows: Sequence[Row], columns: Sequence[str]) -> str:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(columns))
        writer.writeheader()
        writer.writerows({name: row.get(name, "") for name in columns} for row in rows)
    return _sha256_file(path)


def _append_ledger(ledger: Path, entries: Iterable[dict[str, object]]) -> None:
    with ledger.open("a", encoding="utf-8", newline="\n") as stream:
        for entry in entries:
            stream.write(json.dumps(entry, sort_keys=True) + "\n")
        stream.flush()


def _load_ledger(ledger: Path) -> list[dict[str, object]]:
    if not ledger.is_file():
        return []
    entries: list[dict[str, object]] = []
    for line in ledger.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(json.loads(line))
    return entries


def _summary(rows: Sequence[Row], path: Path, sha256: str) -> dict[str, object]:
    if not rows:
        return {"path": path.name, "sha256": sha256, "rows": 0}
    return {
        "path": path.name,
        "sha256": sha256,
        "rows": len(rows),
        "env_tags": sorted({row["env_tag"] for row in rows}),
        "labels": dict(sorted(Counter(row["label"] for row in rows).items())),
        "families": dict(sorted(Counter(row["family"] for row in rows).items())),
        "runs": len({row["run_id"] for row in rows}),
        "first_us": min(int(row["first_seen_us"]) for row in rows),
        "last_us": max(int(row["last_seen_us"]) for row in rows),
    }


def build(
    directories: Sequence[Path],
    *,
    out_dir: Path,
    allow_mixed_benign: Sequence[str] = (),
    max_rows_per_run: int = 5_000,
    seed: int = 42,
    benign_gap_hours: float = 1.0,
    held_out_tool: str = "masscan",
    parameter_holdout_suffix: str = "random",
    assume_benign: bool = False,
    allow_test_rewrite: bool = False,
) -> dict[str, object]:
    """Build all splits under `out_dir` and return the dataset manifest."""
    if not directories:
        raise DatasetError("give at least one pcap_to_flows output directory")
    if benign_gap_hours <= 0:
        raise DatasetError("--benign-gap-hours must be positive")
    if max_rows_per_run < 0:
        raise DatasetError("--max-rows-per-run must be >= 0 (0 disables the cap)")

    inputs: list[_Input] = []
    dropped: Counter[str] = Counter()
    for directory in directories:
        item, lost = _read_input(directory, assume_benign)
        inputs.append(item)
        dropped.update(lost)

    tags = {item.env_tag for item in inputs}
    allowed = {tag.strip() for tag in allow_mixed_benign if tag.strip()}
    unknown_allowed = allowed - {tag.value for tag in EnvTag}
    if unknown_allowed:
        raise DatasetError(f"unknown --allow-mixed-benign tags {sorted(unknown_allowed)}")
    mixed_allowed = False
    if len(tags) > 1:
        if not allowed or not tags <= allowed:
            raise DatasetError(
                f"inputs mix env tags {sorted(tags)}; build each tag separately or pass "
                f"--allow-mixed-benign {','.join(sorted(tags))} (benign only)"
            )
        benign_tags = {item.env_tag for item in inputs if item.role == BENIGN}
        if not benign_tags <= allowed:
            raise DatasetError(
                f"benign inputs mix tags {sorted(benign_tags)} not covered by "
                f"--allow-mixed-benign {','.join(sorted(allowed))}"
            )
        mixed_allowed = True

    benign_rows = [row for item in inputs for row in item.rows if row["label"] == BENIGN]
    attack_rows = [row for item in inputs for row in item.rows if row["label"] != BENIGN]
    benign_rows, benign_capped = _cap_per_run(benign_rows, max_rows_per_run, seed)
    attack_rows, attack_capped = _cap_per_run(attack_rows, max_rows_per_run, seed)
    if not benign_rows:
        raise DatasetError("no benign rows in the inputs")

    benign_splits, bounds, crossing = _split_benign(benign_rows, gap_hours=benign_gap_hours)
    attack_splits, attack_policy = _split_attacks(
        attack_rows,
        held_out_tool=held_out_tool,
        parameter_suffix=parameter_holdout_suffix,
    )
    all_splits: dict[SplitName, list[Row]] = {**benign_splits, **attack_splits}

    columns: list[str] = []
    for item in inputs:
        for name in item.rows[0]:
            if name not in columns:
                columns.append(name)
    for name in SPLIT_COLUMNS:
        if name not in columns:
            columns.append(name)
    for name in ("label", "run_id", "tool", "family", "env_tag", "split"):
        if name not in columns:
            columns.append(name)

    out_dir.mkdir(parents=True, exist_ok=True)
    ledger_path = out_dir / LEDGER_NAME
    previous_ledger = _load_ledger(ledger_path)
    dataset_id_seed = {
        name: _sha256_bytes(
            json.dumps(
                [
                    (row["run_id"], row["first_seen_us"], row["label"], _connection_key(row))
                    for row in rows
                ],
                sort_keys=True,
            ).encode()
        )
        for name, rows in sorted(all_splits.items())
        if rows
    }
    dataset_id = _sha256_bytes(json.dumps(dataset_id_seed, sort_keys=True).encode())
    previous_tests = {
        str(entry.get("split")): str(entry.get("dataset_id"))
        for entry in previous_ledger
        if entry.get("action") in ("written", "rewritten")
    }
    changed = {
        name: previous_tests[name]
        for name in TEST_SPLITS
        if name in previous_tests and previous_tests[name] != dataset_id
    }
    if changed and not allow_test_rewrite:
        raise DatasetError(
            f"{ledger_path} already records a different test dataset for {sorted(changed)}; "
            "use a new --out directory or pass --allow-test-rewrite (the override is recorded)"
        )

    split_summaries: dict[str, dict[str, object]] = {}
    for name, rows in sorted(all_splits.items()):
        for row in rows:
            row["split"] = name
        path = out_dir / f"{name}.csv"
        sha256 = _write_split(path, rows, columns)
        split_summaries[name] = _summary(rows, path, sha256)

    now = datetime.now(UTC).isoformat()
    ledger_entries: list[dict[str, object]] = []
    for name in TEST_SPLITS:
        summary = split_summaries.get(name)
        if summary is None:
            continue
        ledger_entries.append(
            {
                "timestamp": now,
                "action": "rewritten" if name in changed else "written",
                "dataset_id": dataset_id,
                "split": name,
                "sha256": summary["sha256"],
                "rows": summary["rows"],
                "env_tags": summary.get("env_tags", []),
                "builder_version": BUILDER_VERSION,
                "allow_test_rewrite": allow_test_rewrite,
            }
        )
    _append_ledger(ledger_path, ledger_entries)

    manifest: dict[str, object] = {
        "tool": "scripts/dataset/build_dataset.py",
        "builder_version": BUILDER_VERSION,
        "created_at": now,
        "dataset_id": dataset_id,
        "feature_schema_version": SCHEMA_VERSION,
        "feature_names": list(feature_names(SCHEMA_VERSION)),
        "env_tags": sorted(tags),
        "mixed_env": {
            "allowed": sorted(allowed),
            "used": mixed_allowed,
        },
        "policy": {
            "benign": {
                "train_fraction": 0.60,
                "validation_fraction": 0.15,
                "test_fraction": 0.25,
                "gap_hours": benign_gap_hours,
                "use": "fractions of span minus gap",
                "blocks": bounds,
                "dropped_crossing_connections": crossing,
            },
            "attacks": {
                "held_out_tool": held_out_tool,
                "parameter_holdout_suffix": parameter_holdout_suffix,
                "run_holdout_fraction": 0.20,
                "validation_stride": 4,
                **attack_policy,
            },
            "cap": {
                "max_rows_per_run": max_rows_per_run,
                "benign_rows_capped_away": sum(benign_capped.values()),
                "attack_rows_capped_away": sum(attack_capped.values()),
                "runs_capped": {
                    "benign": len(benign_capped),
                    "attack": len(attack_capped),
                },
            },
            "seed": seed,
            "assume_benign": assume_benign,
        },
        "inputs": [
            {
                "path": str(item.directory),
                "manifest_sha256": item.manifest_sha256,
                "env_tag": item.env_tag,
                "role": item.role,
                "labelled": item.labelled,
                "rows": len(item.rows),
            }
            for item in inputs
        ],
        "dropped_rows": dict(sorted(dropped.items())),
        "splits": split_summaries,
        "test_access_ledger": {
            "path": str(ledger_path),
            "sha256": _sha256_file(ledger_path),
            "entries": len(previous_ledger) + len(ledger_entries),
        },
    }
    (out_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def _parse_tags(text: str) -> list[str]:
    return [tag.strip() for tag in text.split(",") if tag.strip()]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("inputs", nargs="+", type=Path, help="pcap_to_flows output directories")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--allow-mixed-benign",
        type=_parse_tags,
        default=[],
        help="comma-separated env tags allowed to mix (benign only)",
    )
    parser.add_argument("--max-rows-per-run", type=int, default=5_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--benign-gap-hours", type=float, default=1.0)
    parser.add_argument("--held-out-tool", default="masscan")
    parser.add_argument("--parameter-holdout-suffix", default="random")
    parser.add_argument(
        "--assume-benign",
        action="store_true",
        help="accept inputs with no label column as benign (recorded in the manifest)",
    )
    parser.add_argument(
        "--allow-test-rewrite",
        action="store_true",
        help="permit replacing a previously recorded test set (recorded in the ledger)",
    )
    args = parser.parse_args(argv)
    try:
        manifest = build(
            args.inputs,
            out_dir=args.out,
            allow_mixed_benign=args.allow_mixed_benign,
            max_rows_per_run=args.max_rows_per_run,
            seed=args.seed,
            benign_gap_hours=args.benign_gap_hours,
            held_out_tool=args.held_out_tool,
            parameter_holdout_suffix=args.parameter_holdout_suffix,
            assume_benign=args.assume_benign,
            allow_test_rewrite=args.allow_test_rewrite,
        )
    except (DatasetError, OSError, ValueError) as exc:
        print(f"build_dataset: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "dataset_id": manifest["dataset_id"],
                "env_tags": manifest["env_tags"],
                "splits": {
                    name: {"rows": summary["rows"], "sha256": summary["sha256"]}
                    for name, summary in manifest["splits"].items()  # type: ignore[union-attr]
                },
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

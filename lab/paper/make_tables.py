"""Render the evaluation paper's tables from phase-19 reports and lab aggregates (phase 20).

    uv run python lab/paper/make_tables.py REPORT_DIR --aggregate AGG_DIR --out OUT [--regression]

Phase 20 turns the numbers phase 19 already wrote - the phase-19 report directory
(`metrics.json`, `table_v.csv`, the `fig*.csv` files) plus a lab aggregate
(`lab/aggregate.py` output: `aggregate-<env>-<phase>.json|.csv`) - into the evaluation
paper's tables (critique_ml.md §10, Tables I-VII).

* **Input.** Only those artifacts. Never raw logs, never a hand-typed number. The
  aggregate supplies the per-attack campaign medians; the phase-19 report supplies
  the ML numbers behind Table V and the dataset provenance behind every footnote.
* **Refusal.** The phase-19 report and the aggregate must share one env tag, and it
  must be a `pi-*` tag — unless `--regression` is passed, which watermarks every
  emitted table `REGRESSION EVIDENCE (env=<tag>) — NOT A PI RESULT`.
* **Output.** `paper_tables.json` (the tables) and `paper_tables.csv` (one row per
  table entry), written under `--out` (outside the tracked tree).
* **Purity.** The output is a pure function of the inputs: deterministic key order,
  no wall-clock, no host-specific values.

Exit codes: 0 when the tables were written, 2 on a refusal.
"""

import argparse
import csv
import json
import sys
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # `python lab/paper/make_tables.py`

from lab.common import PI_TAGS, LabError, check_output_location
from lab.manifest import ENV_TAGS, Json

TOOL: Final = "lab/paper/make_tables.py"
WATERMARK_FORMAT: Final = "REGRESSION EVIDENCE (env={env_tag}) — NOT A PI RESULT"
TABLE_V: Final = "V"
TABLE_V_TITLE: Final = "ML"

#: critique_ml.md §10. Every table the evaluation paper carries, in order.
TABLE_TITLES: Final = {
    "I": "Data",
    "II": "Detectors",
    "III": "Per-attack results",
    "IV": "Benign cost",
    "V": TABLE_V_TITLE,
    "VI": "Ablation",
    "VII": "Resources",
}

#: What a cell says when the run that would fill it has not happened yet. An empty
#: cell is never a zero and never an invented number (phase-20 prompt, non-goals).
NOT_YET_RUN: Final = "not yet run"


class ReportError(LabError):
    """The phase-19 report directory is missing, unreadable or not a phase-19 report."""


@dataclass(frozen=True, slots=True)
class PaperTable:
    """One rendered paper table: its entries, provenance and (regression) watermark."""

    number: str
    title: str
    source: str
    entries: tuple[dict[str, Json], ...]
    env_tag: str
    watermark: str | None = None

    def as_json(self) -> dict[str, Json]:
        """The on-disk shape of one table. Pure: no host state, no wall-clock."""
        return {
            "number": self.number,
            "title": self.title,
            "source": self.source,
            "env_tag": self.env_tag,
            "watermark": self.watermark,
            "entries": [dict(entry) for entry in self.entries],
        }


def load_phase19_metrics(path: Path) -> dict[str, Json]:
    """Read and validate a phase-19 `metrics.json`. Raises `ReportError` on any problem."""
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportError(f"{path}: {exc}") from exc
    except ValueError as exc:
        raise ReportError(f"{path}: not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ReportError(f"{path}: metrics.json must hold a JSON object")
    document = cast(dict[str, Json], raw)
    tags_value = document.get("env_tags")
    tags: list[str] = []
    if isinstance(tags_value, list):
        tags = [str(tag) for tag in tags_value if isinstance(tag, str) and tag]
    if not tags:
        raise ReportError(f"{path}: env_tags must be a non-empty list of strings")
    if len(set(tags)) != 1:
        raise ReportError(f"{path}: env tags {sorted(set(tags))} are mixed (ADDENDUM_4.md D7)")
    env_tag = tags[0]
    if env_tag not in ENV_TAGS:
        raise ReportError(f"{path}: env tag {env_tag!r} is not one of {', '.join(ENV_TAGS)}")
    return document


def read_aggregate(path: Path) -> dict[str, Json]:
    """Read a lab aggregate document. Raises `ReportError` if it is missing or has no env tag."""
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportError(f"{path}: {exc}") from exc
    except ValueError as exc:
        raise ReportError(f"{path}: not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ReportError(f"{path}: aggregate document must hold a JSON object")
    document = cast(dict[str, Json], raw)
    env_tag = document.get("env_tag")
    if not isinstance(env_tag, str) or not env_tag:
        raise ReportError(f"{path}: aggregate document has no env_tag")
    return document


def _number(value: object) -> float | None:
    """The number behind a report cell, or None when the report carries none there."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _block(metrics: Mapping[str, Json], key: str) -> dict[str, Json]:
    """The model block of a phase-19 metrics document; refused when absent."""
    block: object = metrics.get(key)
    if not isinstance(block, dict):
        raise ReportError(f"metrics.json: no {key} block")
    return cast(dict[str, Json], block)


def table_v_entries(metrics: Mapping[str, Json], env_tag: str) -> tuple[dict[str, Json], ...]:
    """One entry per number phase 19 computed for Table V, from the phase-19 report.

    The ML table's cells: operating threshold, benign FPR, attack recall, average
    precision, ROC-AUC, expected alerts per day, benign flow rate, and — per model —
    the recall at each operating FPR. The numbers live in the model block under
    `recall_at_fpr`, keyed by the target FPR.
    """
    entries: list[dict[str, Json]] = []
    for model in ("D2", "D3"):
        block = _block(metrics, f"{model.lower()}")
        entries.append(
            {
                "table": TABLE_V,
                "number": TABLE_V,
                "title": TABLE_V_TITLE,
                "model": model,
                "threshold": _number(block.get("operating_threshold")),
                "benign_fpr": _number(block.get("benign_false_positive_rate")),
                "attack_recall": _number(block.get("attack_recall")),
                "average_precision": _number(block.get("average_precision")),
                "roc_auc": _number(block.get("roc_auc")),
                "expected_alerts_per_day": _number(block.get("expected_alerts_per_day")),
                "benign_flows_per_day": _number(block.get("benign_flows_per_day")),
                "feature_schema_version": metrics.get("feature_schema_version"),
                "dataset_id": metrics.get("dataset_id"),
            }
        )
        recalls: object = block.get("recall_at_fpr")
        if isinstance(recalls, dict):
            for fpr_text, recall in sorted(recalls.items(), key=lambda item: str(item[0])):
                if not isinstance(recall, dict):
                    continue
                entries.append(
                    {
                        "table": TABLE_V,
                        "number": TABLE_V,
                        "title": TABLE_V_TITLE,
                        "model": model,
                        "metric": f"recall_at_fpr_{fpr_text}",
                        "target_fpr": _number(recall.get("target_fpr")),
                        "achieved_fpr": _number(recall.get("achieved_fpr")),
                        "resolution": _number(recall.get("resolution")),
                        "resolvable": bool(recall.get("resolvable")),
                        "recall": _number(recall.get("recall")),
                    }
                )
    return tuple(entries)


def _aggregate_rows(aggregate: Mapping[str, Json]) -> list[dict[str, Json]]:
    """The per-(attack, metric) rows of a `lab/aggregate.py` document."""
    rows: object = aggregate.get("rows")
    if not isinstance(rows, list):
        return []
    return [cast(dict[str, Json], row) for row in rows if isinstance(row, dict)]


def _by_attack(rows: Sequence[Mapping[str, Json]]) -> dict[str, dict[str, Mapping[str, Json]]]:
    """`{attack: {metric: row}}` — the shape every per-attack table reads."""
    grouped: dict[str, dict[str, Mapping[str, Json]]] = {}
    for row in rows:
        attack, metric = str(row.get("attack", "")), str(row.get("metric", ""))
        if attack and metric:
            grouped.setdefault(attack, {})[metric] = row
    return grouped


def table_i_entries(
    metrics: Mapping[str, Json], aggregate: Mapping[str, Json], env_tag: str
) -> tuple[dict[str, Json], ...]:
    """Table I (Data): what each source contributed, and how the splits were assigned.

    The dataset half comes from the phase-19 report's provenance; the campaign half
    counts the runs the aggregate actually summarised. Hours of benign traffic and the
    device count come from the capture manifests, which only a `pi-*` campaign has —
    until then those cells say `not yet run` rather than guessing.
    """
    entries: list[dict[str, Json]] = []
    splits: object = metrics.get("splits")
    if isinstance(splits, dict):
        for name, block in sorted(cast(dict[str, Json], splits).items()):
            if not isinstance(block, dict):
                continue
            cell = cast(dict[str, Json], block)
            entries.append(
                {
                    "source": "dataset split",
                    "split": name,
                    "rows": _number(cell.get("rows")),
                    "benign_rows": _number(cell.get("benign")),
                    "attack_rows": _number(cell.get("attack")),
                    "sha256": cell.get("sha256"),
                }
            )
    grouped = _by_attack(_aggregate_rows(aggregate))
    for attack, metrics_by_name in sorted(grouped.items()):
        ttd = metrics_by_name.get("ttd_seconds", {})
        entries.append(
            {
                "source": "campaign",
                "attack": attack,
                "runs": _number(ttd.get("n")),
                "misses": _number(ttd.get("misses")),
                "phase": aggregate.get("phase"),
            }
        )
    entries.append(
        {
            "source": "benign capture",
            "device_hours": NOT_YET_RUN,
            "devices": NOT_YET_RUN,
            "flows": NOT_YET_RUN,
            "note": "filled from the sealed pi-live capture manifests (RUNBOOK_PI step 5)",
        }
    )
    entries.append({"source": "provenance", "dataset_id": metrics.get("dataset_id"), "env_tag": env_tag})
    return tuple(entries)


def table_ii_entries(
    thresholds: Mapping[str, Json] | None, policy: Mapping[str, Json] | None
) -> tuple[dict[str, Json], ...]:
    """Table II (Detectors): each D1 detector's threshold, how it was set, and its ceiling.

    The thresholds file carries the value, its floor/ceiling clamp, the sample count
    behind it and whether it is frozen; the policy table says which action that tier of
    evidence is allowed to reach. Neither number is typed here.
    """
    entries: list[dict[str, Json]] = []
    if thresholds is None:
        return ({"detector": NOT_YET_RUN, "note": "pass --thresholds config/d1_thresholds.toml"},)
    provenance: object = thresholds.get("provenance")
    source = (
        str(cast(dict[str, Json], provenance).get("source", ""))
        if isinstance(provenance, dict)
        else ""
    )
    frozen = bool(thresholds.get("frozen"))
    tiers: dict[str, str] = {}
    if policy is not None:
        d1_block: object = policy.get("d1")
        if isinstance(d1_block, dict):
            for tier, names in cast(dict[str, Json], d1_block).items():
                if isinstance(names, list):
                    for name in names:
                        tiers[str(name)] = str(tier)
    rows: object = thresholds.get("threshold")
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            cell = cast(dict[str, Json], row)
            name = str(cell.get("name", ""))
            detector = name.split("/", 1)[0]
            entries.append(
                {
                    "tier": "D1",
                    "detector": detector,
                    "window": name,
                    "certainty": tiers.get(detector, "unclassified"),
                    "threshold": _number(cell.get("value")),
                    "floor": _number(cell.get("floor")),
                    "ceiling": _number(cell.get("ceiling")),
                    "samples": _number(cell.get("samples")),
                    "how_set": source or "floors",
                    "frozen": frozen,
                }
            )
    if policy is not None:
        policy_rows: object = policy.get("row")
        if isinstance(policy_rows, list):
            for row in policy_rows:
                if not isinstance(row, dict):
                    continue
                cell = cast(dict[str, Json], row)
                entries.append(
                    {
                        "tier": "policy",
                        "evidence": cell.get("evidence"),
                        "shadow": cell.get("shadow"),
                        "assisted": cell.get("assisted"),
                        "active": cell.get("active"),
                        "escalate": bool(cell.get("escalate", False)),
                    }
                )
    return tuple(entries)


def table_iii_entries(aggregate: Mapping[str, Json]) -> tuple[dict[str, Json], ...]:
    """Table III (Per-attack results): the campaign medians, one row per attack class.

    Time-to-detect, time-to-mitigate, mitigation effectiveness and collateral come
    straight from `lab/aggregate.py`'s medians. A miss is never a number: the `misses`
    column carries it instead (`lab/aggregate.py` keeps the two apart deliberately).
    """
    grouped = _by_attack(_aggregate_rows(aggregate))
    if not grouped:
        return ({"attack": NOT_YET_RUN, "note": "no campaign runs in the aggregate"},)
    entries: list[dict[str, Json]] = []
    for attack, metrics_by_name in sorted(grouped.items()):
        entry: dict[str, Json] = {"attack": attack}
        for metric in (
            "ttd_seconds",
            "ttm_seconds",
            "mitigation_effectiveness",
            "collateral_wired",
            "collateral_wifi",
            "actions_against_others",
        ):
            row = metrics_by_name.get(metric)
            if row is None:
                entry[metric] = NOT_YET_RUN
                continue
            entry[metric] = _number(row.get("median"))
            entry[f"{metric}_n"] = _number(row.get("n"))
        ttd = metrics_by_name.get("ttd_seconds", {})
        entry["misses"] = _number(ttd.get("misses"))
        entry["runs"] = ttd.get("runs")
        entries.append(entry)
    return tuple(entries)


def table_iv_entries(benign: Mapping[str, Json] | None) -> tuple[dict[str, Json], ...]:
    """Table IV (Benign cost): enforce actions per device-hour on clean devices, with CIs.

    Input is a `lab/benign_fp.py` report. Its rate intervals are already the rule of
    three (zero events) or an exact Poisson interval, so nothing is recomputed here.
    """
    if benign is None:
        return (
            {
                "action": NOT_YET_RUN,
                "note": "pass --benign-fp (lab/benign_fp.py output; RUNBOOK_PI step 24)",
            },
        )
    entries: list[dict[str, Json]] = []
    rates: object = benign.get("rates")
    if isinstance(rates, dict):
        for action, block in sorted(cast(dict[str, Json], rates).items()):
            if not isinstance(block, dict):
                continue
            cell = cast(dict[str, Json], block)
            entries.append(
                {
                    "action": action,
                    "count": _number(cell.get("count")),
                    "device_hours": _number(cell.get("exposure")),
                    "per_device_hour": _number(cell.get("rate")),
                    "ci95_lower": _number(cell.get("ci95_lower")),
                    "ci95_upper": _number(cell.get("ci95_upper")),
                    "method": cell.get("method"),
                }
            )
    entries.append(
        {
            "action": "verdict",
            "forward_guard_may_enforce": benign.get("forward_guard_may_enforce", NOT_YET_RUN),
            "reason": benign.get("reason"),
        }
    )
    return tuple(entries)


def table_vi_entries(ablation: Mapping[str, Json] | None) -> tuple[dict[str, Json], ...]:
    """Table VI (Ablation): kernel only / +D1 / +D2 / +D3.

    Each arm is a separate campaign with the later tiers disabled, so the inputs are
    four aggregates, not one. Until those runs exist every arm says so explicitly.
    """
    arms = ("kernel only", "+D1", "+D2", "+D3")
    if ablation is None:
        return tuple(
            {
                "arm": arm,
                "attacks_detected": NOT_YET_RUN,
                "benign_alerts_per_device_hour": NOT_YET_RUN,
                "note": "needs one campaign per arm (phase-20 prompt, deliverable 2)",
            }
            for arm in arms
        )
    entries: list[dict[str, Json]] = []
    for arm in arms:
        block: object = ablation.get(arm)
        cell = cast(dict[str, Json], block) if isinstance(block, dict) else {}
        entries.append(
            {
                "arm": arm,
                "attacks_detected": _number(cell.get("attacks_detected")) or NOT_YET_RUN,
                "benign_alerts_per_device_hour": _number(cell.get("benign_alerts_per_device_hour"))
                or NOT_YET_RUN,
            }
        )
    return tuple(entries)


def table_vii_entries(benchmark: Sequence[Mapping[str, Json]] | None) -> tuple[dict[str, Json], ...]:
    """Table VII (Resources): CPU, RSS and capture drop rate against offered pps.

    Input is `benchmarks/v2-native-pi/results-*.jsonl`, one JSON object per measured
    offered rate. v1 and v2 are separate records, distinguished by their `engine` field.
    """
    if not benchmark:
        return (
            {
                "pps": NOT_YET_RUN,
                "note": "pass --benchmark benchmarks/v2-native-pi/results-*-pi-scripted.jsonl",
            },
        )
    entries: list[dict[str, Json]] = []
    for record in benchmark:
        entries.append(
            {
                "engine": record.get("engine", "unknown"),
                "pps": _number(record.get("offered_pps")),
                "cpu_percent": _number(record.get("cpu_percent")),
                "rss_mb": _number(record.get("rss_mb")),
                "drop_percent": _number(record.get("drop_percent")),
                "env_tag": record.get("env_tag"),
            }
        )
    return tuple(entries)


@dataclass(frozen=True, slots=True)
class Extras:
    """The optional inputs behind Tables II, IV, VI and VII. Absent means `not yet run`."""

    thresholds: Mapping[str, Json] | None = None
    policy: Mapping[str, Json] | None = None
    benign: Mapping[str, Json] | None = None
    ablation: Mapping[str, Json] | None = None
    benchmark: tuple[Mapping[str, Json], ...] | None = None


def read_toml(path: Path) -> dict[str, Json]:
    """Read a reviewed TOML input (thresholds, policy table). Raises `ReportError`."""
    try:
        with path.open("rb") as stream:
            return cast(dict[str, Json], tomllib.load(stream))
    except OSError as exc:
        raise ReportError(f"{path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ReportError(f"{path}: not valid TOML: {exc}") from exc


def read_jsonl(path: Path) -> tuple[Mapping[str, Json], ...]:
    """Read a benchmark results file: one JSON object per line. Raises `ReportError`."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"{path}: {exc}") from exc
    records: list[Mapping[str, Json]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record: object = json.loads(line)
        except ValueError as exc:
            raise ReportError(f"{path}:{number}: not valid JSON: {exc}") from exc
        if isinstance(record, dict):
            records.append(cast(dict[str, Json], record))
    return tuple(records)


def build_tables(
    metrics: Mapping[str, Json], aggregate: Mapping[str, Json], extras: "Extras | None" = None
) -> list[PaperTable]:
    """Every paper table (critique_ml.md §10 I-VII), from the artifacts that exist.

    Each table reads only `lab/aggregate.py` output, the phase-19 report, and the
    reviewed configuration behind Table II. A table whose campaign has not run yet is
    still emitted, with its cells saying `not yet run` — an empty cell is never a zero
    and never an invented number.
    """
    tags_value: object = metrics.get("env_tags")
    tags: list[str] = []
    if isinstance(tags_value, list):
        tags = [str(tag) for tag in tags_value if isinstance(tag, str) and tag]
    env_tag = tags[0]
    extras = extras or Extras()
    plan: list[tuple[str, str, tuple[dict[str, Json], ...]]] = [
        (
            "I",
            "phase-19 metrics.json splits; lab/aggregate.py run counts",
            table_i_entries(metrics, aggregate, env_tag),
        ),
        (
            "II",
            "config/d1_thresholds.toml; pirewall/policy/table.toml",
            table_ii_entries(extras.thresholds, extras.policy),
        ),
        ("III", "lab/aggregate.py output", table_iii_entries(aggregate)),
        ("IV", "lab/benign_fp.py report", table_iv_entries(extras.benign)),
        ("V", "phase-19 metrics.json + table_v.csv", table_v_entries(metrics, env_tag)),
        ("VI", "one lab/aggregate.py output per ablation arm", table_vi_entries(extras.ablation)),
        ("VII", "benchmarks/v2-native-pi results", table_vii_entries(extras.benchmark)),
    ]
    return [
        PaperTable(
            number=number,
            title=TABLE_TITLES[number],
            source=source,
            entries=entries,
            env_tag=env_tag,
        )
        for number, source, entries in plan
    ]


def render(tables: Sequence[PaperTable], *, regression: bool, env_tag: str) -> list[PaperTable]:
    """Apply the D7 watermark. Regression evidence is never a Pi result."""
    watermark = None if not regression else WATERMARK_FORMAT.format(env_tag=env_tag)
    return [replace(table, watermark=watermark) for table in tables]


def write_outputs(
    out: Path, tables: Sequence[PaperTable], *, env_tag: str, regression: bool
) -> tuple[Path, Path]:
    """Write `paper_tables.json` and `paper_tables.csv` under `out`. Pure: same inputs, same bytes."""
    resolved = check_output_location(out)
    resolved.mkdir(parents=True, exist_ok=True)
    document = {
        "env_tag": env_tag,
        "regression": regression,
        "watermark": WATERMARK_FORMAT.format(env_tag=env_tag) if regression else None,
        "tables": [table.as_json() for table in tables],
    }
    json_path = resolved / "paper_tables.json"
    json_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    fieldnames: list[str] = ["table", "number", "title", "source", "model", "metric", "value"]
    for table in tables:
        for entry in table.entries:
            for key in entry:
                if str(key) not in fieldnames:
                    fieldnames.append(str(key))
    rows: list[dict[str, Json]] = []
    for table in tables:
        for entry in table.entries:
            flat: dict[str, Json] = {
                "table": table.number,
                "number": table.number,
                "title": table.title,
                "source": table.source,
            }
            for key, value in entry.items():
                flat[key] = value
            rows.append(flat)
    with (resolved / "paper_tables.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in fieldnames})
    return json_path, resolved / "paper_tables.csv"


def build_parser() -> argparse.ArgumentParser:
    """The CLI: phase-19 report + lab aggregate in, paper tables out."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("report", type=Path, help="phase-19 report directory (metrics.json, table_v.csv)")
    parser.add_argument(
        "--aggregate", type=Path, required=True, help="lab aggregate output (aggregate-<env>-<phase>.json)"
    )
    parser.add_argument("--out", type=Path, required=True, help="output directory (outside the tracked tree)")
    parser.add_argument("--thresholds", type=Path, help="config/d1_thresholds.toml (Table II)")
    parser.add_argument("--policy", type=Path, help="pirewall/policy/table.toml (Table II)")
    parser.add_argument("--benign-fp", type=Path, help="lab/benign_fp.py report JSON (Table IV)")
    parser.add_argument("--ablation", type=Path, help="ablation arms JSON (Table VI)")
    parser.add_argument("--benchmark", type=Path, help="benchmarks/v2-native-pi results-*.jsonl (Table VII)")
    parser.add_argument(
        "--regression",
        action="store_true",
        help="render regression evidence (env=mock|sandbox) instead of a pi-* result",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Exit 0 when the tables were written, 2 on a refusal."""
    args = build_parser().parse_args(argv)
    try:
        metrics = load_phase19_metrics(args.report / "metrics.json")
        aggregate = read_aggregate(args.aggregate)
        tags_value: object = metrics.get("env_tags")
        tags: list[str] = []
        if isinstance(tags_value, list):
            tags = [str(tag) for tag in tags_value if isinstance(tag, str) and tag]
        env_tag = tags[0]
        aggregate_tag = str(aggregate.get("env_tag", ""))
        if aggregate_tag != env_tag:
            raise LabError(
                f"{args.aggregate}: env tag {aggregate_tag or '(none)'} does not match the phase-19 "
                f"report tag {env_tag} (ADDENDUM_4.md D7: never mix)"
            )
        if env_tag not in PI_TAGS and not args.regression:
            raise LabError(
                f"env tag {env_tag!r} is not a pi-* result; pass --regression to render regression evidence"
            )
        extras = Extras(
            thresholds=read_toml(args.thresholds) if args.thresholds else None,
            policy=read_toml(args.policy) if args.policy else None,
            benign=read_aggregate(args.benign_fp) if args.benign_fp else None,
            ablation=read_aggregate(args.ablation) if args.ablation else None,
            benchmark=read_jsonl(args.benchmark) if args.benchmark else None,
        )
        tables = build_tables(metrics, aggregate, extras)
        rendered = render(tables, regression=args.regression, env_tag=env_tag)
        json_path, csv_path = write_outputs(args.out, rendered, env_tag=env_tag, regression=args.regression)
    except LabError as exc:
        print(f"make_tables: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {len(rendered)} paper table(s) from {args.report} and {args.aggregate}")
    print(f"  {json_path}")
    print(f"  {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

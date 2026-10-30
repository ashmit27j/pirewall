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


def build_tables(metrics: Mapping[str, Json], aggregate: Mapping[str, Json]) -> list[PaperTable]:
    """The paper tables phase 20 renders today, from the phase-19 report and the aggregate.

    Today this renders Table V, whose numbers phase 19 wrote into `metrics.json` /
    `table_v.csv`. The remaining Tables I-VII are added as their inputs become real on
    `pi-*` runs; none is invented here.
    """
    tags_value: object = metrics.get("env_tags")
    tags: list[str] = []
    if isinstance(tags_value, list):
        tags = [str(tag) for tag in tags_value if isinstance(tag, str) and tag]
    env_tag = tags[0]
    return [
        PaperTable(
            number=TABLE_V,
            title=TABLE_V_TITLE,
            source="phase-19 metrics.json + table_v.csv; lab/aggregate.py output",
            entries=table_v_entries(metrics, env_tag),
            env_tag=env_tag,
        ),
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
        tables = build_tables(metrics, aggregate)
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

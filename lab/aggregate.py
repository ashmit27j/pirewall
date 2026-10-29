"""Aggregate scored campaign runs into per-attack tables, one env tag and one phase at a time (G7, D7).

    uv run python lab/aggregate.py RUN_OR_CAMPAIGN_DIR [...] --out DIR [--no-verify]

Finds every run directory (manifest `kind = "run"`) under the arguments and
reads its `score/metrics.json` (`lab/score_run.py`). Then:

* **Refuses** (exit 2, naming the offending runs) to combine runs with
  different env tags (ADDENDUM_4.md D7), or `dev` runs with `eval` runs
  (critique_ml.md: campaign #1 tunes, campaign #2 is touched once).
* Verifies every manifest first (`lab/verify_manifest.py`); any failure
  stops it (exit 1). `--no-verify` exists for debugging only and is
  recorded in the output.
* Per attack and metric: n, the number of runs not detected (TTD is a miss
  count, never averaged in as a large number), median, mean, SD, min, max,
  and the order-statistic confidence interval of the median with its
  actual coverage (`lab/stats.py`).

Output, sealed by its own manifest: `aggregate-<env>-<phase>.json` and
`.csv`, the env tag in the file name and in every row. Phase 20 turns these
into the paper's tables; nothing else may.
"""

import argparse
import csv
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # `python lab/aggregate.py`

from lab.common import LabError, check_output_location
from lab.manifest import MANIFEST_NAME, Json, Manifest, ManifestError, read_manifest, write_manifest
from lab.stats import summarise
from lab.verify_manifest import Report, verify_tree

TOOL: Final = "lab/aggregate.py"
METRICS: Final = (
    "ttd_seconds",
    "ttm_seconds",
    "mitigation_effectiveness",
    "collateral_wired",
    "collateral_wifi",
    "admin_api_p95_ms",
    "actions_against_others",
)
CSV_COLUMNS: Final = (
    "env_tag",
    "phase",
    "attack",
    "metric",
    "n",
    "misses",
    "median",
    "mean",
    "sd",
    "min",
    "max",
    "median_ci_lower",
    "median_ci_upper",
    "median_ci_coverage",
    "runs",
)


class MixError(LabError):
    """Runs that must never share a table."""


@dataclass(frozen=True, slots=True)
class Run:
    """One scored run."""

    directory: Path
    env_tag: str
    phase: str | None
    attack: str
    metrics: dict[str, Json]


def find_runs(roots: Sequence[Path]) -> list[Run]:
    """Every `kind = "run"` directory under `roots`, with its metrics. Raises `LabError`."""
    runs: list[Run] = []
    for root in roots:
        candidates = [root, *sorted(path.parent for path in root.rglob(MANIFEST_NAME))]
        for directory in dict.fromkeys(candidates):
            if not (directory / MANIFEST_NAME).is_file():
                continue
            document = read_manifest(directory)
            if document.get("kind") != "run":
                continue
            extra = document.get("extra")
            attack = extra.get("attack") if isinstance(extra, dict) else None
            metrics_path = directory / "score" / "metrics.json"
            if not isinstance(attack, str):
                raise LabError(f"{directory}: run manifest has no extra.attack")
            if not metrics_path.is_file():
                raise LabError(f"{directory}: not scored yet (run lab/score_run.py {directory})")
            metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
            phase = document.get("phase")
            runs.append(
                Run(
                    directory,
                    str(document["env_tag"]),
                    phase if isinstance(phase, str) else None,
                    attack,
                    metrics,
                )
            )
    return runs


def check_mixing(runs: Sequence[Run]) -> tuple[str, str]:
    """(env tag, phase) shared by every run. Raises `MixError` naming the runs that differ."""
    if not runs:
        raise LabError("no scored runs found")
    for attribute, what in (("env_tag", "env tags (ADDENDUM_4.md D7)"), ("phase", "dev and eval runs")):
        groups: dict[str, list[str]] = {}
        for run in runs:
            groups.setdefault(str(getattr(run, attribute)), []).append(str(run.directory))
        if len(groups) > 1:
            detail = "; ".join(f"{key}: {', '.join(sorted(dirs))}" for key, dirs in sorted(groups.items()))
            raise MixError(f"refusing to combine {what}: {detail}")
    return runs[0].env_tag, str(runs[0].phase)


def _value(metrics: dict[str, Json], metric: str) -> float | None:
    if metric.startswith("collateral_"):
        collateral = metrics.get("collateral")
        value = collateral.get(metric.removeprefix("collateral_")) if isinstance(collateral, dict) else None
    else:
        value = metrics.get(metric)
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def aggregate(runs: Sequence[Run]) -> list[dict[str, Json]]:
    """One row per (attack, metric)."""
    env_tag, phase = check_mixing(runs)
    rows: list[dict[str, Json]] = []
    for attack in sorted({run.attack for run in runs}):
        group = sorted((run for run in runs if run.attack == attack), key=lambda run: str(run.directory))
        for metric in METRICS:
            values = [value for run in group if (value := _value(run.metrics, metric)) is not None]
            misses = (
                sum(1 for run in group if run.metrics.get("detected") is False)
                if metric == "ttd_seconds"
                else 0
            )
            summary = summarise(values).as_json()
            rows.append(
                {
                    "env_tag": env_tag,
                    "phase": phase,
                    "attack": attack,
                    "metric": metric,
                    **summary,
                    "n": len(values),
                    "misses": misses,
                    "runs": ";".join(run.directory.name for run in group),
                }
            )
    return rows


def write_outputs(
    out: Path, rows: list[dict[str, Json]], runs: Sequence[Run], verified: bool
) -> tuple[Path, Path]:
    """Write the JSON and CSV tables and seal the directory."""
    env_tag, phase = check_mixing(runs)
    out.mkdir(parents=True, exist_ok=False)
    stem = f"aggregate-{env_tag}-{phase}"
    json_path, csv_path = out / f"{stem}.json", out / f"{stem}.csv"
    json_path.write_text(
        json.dumps({"env_tag": env_tag, "phase": phase, "verified": verified, "rows": rows}, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column) for column in CSV_COLUMNS})
    write_manifest(
        out,
        Manifest(
            kind="evaluator",
            env_tag=env_tag,
            tool=TOOL,
            phase="eval" if phase == "eval" else "dev",
            extra={"runs": [str(run.directory) for run in runs], "verified": verified},
        ),
    )
    return json_path, csv_path


def main(argv: Sequence[str] | None = None) -> int:
    """0 on success, 1 when a manifest fails verification, 2 on a refusal (mixing)."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("roots", nargs="+", type=Path, help="run directories or campaign directories")
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    parser.add_argument("--no-verify", action="store_true", help="skip manifest verification (recorded)")
    args = parser.parse_args(argv)
    try:
        out = check_output_location(args.out)
        runs = find_runs(args.roots)
        check_mixing(runs)
        if not args.no_verify:
            report = Report()
            for run in runs:
                verify_tree(run.directory, report=report)
            if not report.ok:
                for problem in report.problems:
                    print(f"FAIL {problem}", file=sys.stderr)
                return 1
        rows = aggregate(runs)
        json_path, csv_path = write_outputs(out, rows, runs, verified=not args.no_verify)
    except (LabError, ManifestError) as exc:
        print(f"aggregate: {exc}", file=sys.stderr)
        return 2
    print(f"{len(runs)} runs -> {json_path} and {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

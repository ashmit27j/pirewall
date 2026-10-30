"""Render the evaluation paper's figures from phase-19 reports (phase 20).

    uv run python lab/paper/make_figures.py REPORT_DIR --out OUT [--regression]

Phase 20 turns the figure data phase 19 already wrote - `metrics.json` and the
`fig3_score_distributions.csv`, `fig4_reliability.csv`, `fig5_psi.csv` files of the
phase-19 report directory - into the evaluation paper's figures (critique_ml.md
section 10, Figs 1-5).

* **Input.** Only the phase-19 report artifacts. Never raw logs, never a hand-typed
  number.
* **Refusal.** The phase-19 report must carry a single env tag that is a `pi-*` tag -
  unless `--regression` is passed, which watermarks every emitted figure
  `REGRESSION EVIDENCE (env=<tag>) - NOT A PI RESULT`.
* **Output.** `paper_figures.json` (one entry per figure) and `paper_figures.csv`
  (one row per figure entry), written under `--out` (outside the tracked tree).
* **Purity.** The output is a pure function of the inputs: deterministic key order,
  no wall-clock, no host-specific values.

Exit codes: 0 when the figures were written, 2 on a refusal.
"""

import argparse
import csv
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # `python lab/paper/make_figures.py`

from lab.common import PI_TAGS, LabError, check_output_location
from lab.manifest import Json
from lab.paper.make_tables import WATERMARK_FORMAT, ReportError, load_phase19_metrics

TOOL: Final = "lab/paper/make_figures.py"
FIGURE_V_SCORE_DISTRIBUTIONS: Final = "3"
FIGURE_V_RELIABILITY: Final = "4"
FIGURE_V_PSI: Final = "5"


@dataclass(frozen=True, slots=True)
class PaperFigure:
    """One rendered paper figure: its entries, provenance and (regression) watermark."""

    number: str
    title: str
    source: str
    entries: tuple[dict[str, Json], ...]
    env_tag: str
    watermark: str | None = None

    def as_json(self) -> dict[str, Json]:
        """The on-disk shape of one figure. Pure: no host state, no wall-clock."""
        return {
            "number": self.number,
            "title": self.title,
            "source": self.source,
            "env_tag": self.env_tag,
            "watermark": self.watermark,
            "entries": [dict(entry) for entry in self.entries],
        }


def _score_summary(scores: object) -> dict[str, Json]:
    """A phase-19 score summary (rows/mean/std/min/p50/p90/p99/max) as figure entries."""
    if not isinstance(scores, dict):
        raise ReportError("metrics.json: a score summary must be a JSON object")
    summary = cast(dict[str, Json], scores)
    return {
        "rows": summary.get("rows"),
        "mean": summary.get("mean"),
        "std": summary.get("std"),
        "minimum": summary.get("minimum"),
        "p50": summary.get("p50"),
        "p90": summary.get("p90"),
        "p99": summary.get("p99"),
        "maximum": summary.get("maximum"),
    }


def figure_entries(metrics: Mapping[str, Json]) -> tuple[dict[str, Json], ...]:
    """One entry per plotted number, keyed by figure (critique_ml.md section 10, Figs 3-5)."""
    entries: list[dict[str, Json]] = []
    d2 = metrics.get("d2")
    d3 = metrics.get("d3")
    if isinstance(d2, dict) and isinstance(d3, dict):
        for model, block in (("D2", d2), ("D3", d3)):
            for kind, scores in (
                ("benign", block.get("benign_scores")),
                ("attack", block.get("attack_scores")),
            ):
                if isinstance(scores, dict):
                    entries.append(
                        {
                            "figure": FIGURE_V_SCORE_DISTRIBUTIONS,
                            "number": FIGURE_V_SCORE_DISTRIBUTIONS,
                            "title": "Score distributions",
                            "model": model,
                            "class": kind,
                            **_score_summary(scores),
                        }
                    )
        reliability = d3.get("reliability") if isinstance(d3, dict) else None
        if isinstance(reliability, list):
            for bin_ in reliability:
                if not isinstance(bin_, dict):
                    continue
                entries.append(
                    {
                        "figure": FIGURE_V_RELIABILITY,
                        "number": FIGURE_V_RELIABILITY,
                        "title": "Reliability",
                        "lower": bin_.get("lower"),
                        "upper": bin_.get("upper"),
                        "rows": bin_.get("rows"),
                        "positives": bin_.get("positives"),
                        "mean_score": bin_.get("mean_score"),
                        "observed_rate": bin_.get("observed_rate"),
                    }
                )
    psi = metrics.get("psi")
    if isinstance(psi, dict):
        for feature, shift in sorted(psi.items(), key=lambda item: str(item[0])):
            if not isinstance(shift, dict):
                continue
            entries.append(
                {
                    "figure": FIGURE_V_PSI,
                    "number": FIGURE_V_PSI,
                    "title": "PSI drift",
                    "feature": feature,
                    "psi": shift.get("psi"),
                    "major_shift": shift.get("major_shift"),
                }
            )
    return tuple(entries)


def build_figures(metrics: Mapping[str, Json], env_tag: str) -> list[PaperFigure]:
    """The paper figures phase 20 renders today, from the phase-19 report."""
    entries = figure_entries(metrics)
    plans: tuple[tuple[str, str, str], ...] = (
        (FIGURE_V_SCORE_DISTRIBUTIONS, "Score distributions", "phase-19 metrics.json"),
        (FIGURE_V_RELIABILITY, "Reliability", "phase-19 metrics.json"),
        (FIGURE_V_PSI, "PSI drift", "phase-19 metrics.json"),
    )
    return [
        PaperFigure(
            number=number,
            title=title,
            source=source,
            entries=tuple(entry for entry in entries if str(entry.get("figure")) == number),
            env_tag=env_tag,
        )
        for number, title, source in plans
    ]


def render(figures: Sequence[PaperFigure], *, regression: bool, env_tag: str) -> list[PaperFigure]:
    """Apply the D7 watermark. Regression evidence is never a Pi result."""
    watermark = None if not regression else WATERMARK_FORMAT.format(env_tag=env_tag)
    return [replace(figure, watermark=watermark) for figure in figures]


def write_outputs(
    out: Path, figures: Sequence[PaperFigure], *, env_tag: str, regression: bool
) -> tuple[Path, Path]:
    """Write `paper_figures.json` and `paper_figures.csv` under `out`. Pure: same inputs, same bytes."""
    resolved = check_output_location(out)
    resolved.mkdir(parents=True, exist_ok=True)
    document = {
        "env_tag": env_tag,
        "regression": regression,
        "watermark": WATERMARK_FORMAT.format(env_tag=env_tag) if regression else None,
        "figures": [figure.as_json() for figure in figures],
    }
    json_path = resolved / "paper_figures.json"
    json_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    fieldnames: list[str] = ["figure", "number", "title", "source", "model", "class", "feature", "value"]
    rows: list[dict[str, Json]] = []
    for figure in figures:
        for entry in figure.entries:
            flat: dict[str, Json] = {
                "figure": figure.number,
                "number": figure.number,
                "title": figure.title,
                "source": figure.source,
            }
            for key, value in entry.items():
                flat[key] = value
            rows.append(flat)
    with (resolved / "paper_figures.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in fieldnames})
    return json_path, resolved / "paper_figures.csv"


def build_parser() -> argparse.ArgumentParser:
    """The CLI: phase-19 report in, paper figures out."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("report", type=Path, help="phase-19 report directory (metrics.json, fig*.csv)")
    parser.add_argument("--out", type=Path, required=True, help="output directory (outside the tracked tree)")
    parser.add_argument(
        "--regression",
        action="store_true",
        help="render regression evidence (env=mock|sandbox) instead of a pi-* result",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Exit 0 when the figures were written, 2 on a refusal."""
    args = build_parser().parse_args(argv)
    try:
        metrics = load_phase19_metrics(args.report / "metrics.json")
        tags_value: object = metrics.get("env_tags")
        tags: list[str] = []
        if isinstance(tags_value, list):
            tags = [str(tag) for tag in tags_value if isinstance(tag, str) and tag]
        env_tag = tags[0]
        if env_tag not in PI_TAGS and not args.regression:
            raise LabError(
                f"env tag {env_tag!r} is not a pi-* result; pass --regression to render regression evidence"
            )
        figures = render(build_figures(metrics, env_tag), regression=args.regression, env_tag=env_tag)
        json_path, csv_path = write_outputs(args.out, figures, env_tag=env_tag, regression=args.regression)
    except LabError as exc:
        print(f"make_figures: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {len(figures)} paper figure(s) from {args.report}")
    print(f"  {json_path}")
    print(f"  {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Regression guard for `scripts.diagnostics.performance_smoke` (spec §40).

Does **not** assert on specific latency/throughput numbers — those are
machine-dependent and, per this script's own docstring, not representative
of real Raspberry Pi hardware. This only proves the smoke pass itself keeps
running end to end (every stage executes, produces a real measurement, and
the pipeline it drives doesn't silently break) so it doesn't bit-rot
unnoticed alongside the rest of the codebase.
"""

from scripts.diagnostics.performance_smoke import run

_EXPECTED_STAGES = {
    "packet capture+parse",
    "flow aggregation",
    "feature extraction",
    "lightgbm inference",
    "isolation-forest inference",
    "threat assessment",
    "rule deployment",
}


def test_performance_smoke_pass_runs_every_stage_and_reports_positive_throughput() -> None:
    # A small flow count here — this is a regression check that every stage
    # still runs, not the "meaningfully high rate" report itself (that's
    # `run()`'s own 2000-flow default, used when the script is run directly).
    stats = run(flow_count=100)

    labels = {stat.label for stat in stats}
    assert labels == _EXPECTED_STAGES

    for stat in stats:
        assert stat.count > 0, f"{stat.label} measured zero operations"
        assert stat.total_seconds >= 0.0
        assert stat.mean_ms >= 0.0
        assert stat.ops_per_second > 0.0

"""`lab/aggregate.py` and `lab/score_run.py` (phase 18): scoring a run, and never mixing tags or phases."""

import json
from pathlib import Path

import pytest

from lab.aggregate import MixError, aggregate, check_mixing, find_runs
from lab.aggregate import main as aggregate_main
from lab.manifest import Json, Manifest, Phase, write_manifest
from lab.score_run import RunFacts, time_to_detect, time_to_mitigate
from lab.score_run import main as score_main

ATTACKER_MAC = "02:00:00:00:a0:01"


def _run(
    root: Path, name: str, env_tag: str, phase: Phase, attack: str = "syn_flood_fixed", ttd: float = 1.5
) -> Path:
    directory = root / name
    directory.mkdir(parents=True)
    t0 = 1_800_000_000.0
    poll = {
        "t": t0 + 2.0,
        "events": [{"decision": "rate_limit", "mac": ATTACKER_MAC, "timestamp": _iso(t0 + ttd)}],
        "offenders": [{"mac": ATTACKER_MAC}],
        "rules": [],
        "api_latency_ms": 12.0,
    }
    (directory / "poll.jsonl").write_text(json.dumps(poll) + "\n", encoding="utf-8")
    extra: dict[str, Json] = {
        "attack": attack,
        "t_start": t0,
        "t_end": t0 + 10.0,
        "attacker_mac": ATTACKER_MAC,
        "attacker_ip": "192.0.2.100",
        "offered_rate_pps": 1000.0,
        "victim_filter": {},
    }
    write_manifest(directory, Manifest(kind="run", env_tag=env_tag, tool="test", phase=phase, extra=extra))
    return directory


def _iso(t: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(t, UTC).isoformat()


def _score(*runs: Path) -> None:
    assert score_main([str(run) for run in runs]) == 0


def test_scored_runs_aggregate_per_attack_with_the_env_tag_in_every_row(tmp_path: Path) -> None:
    runs = [_run(tmp_path, f"r{i}", "mock", "dev", ttd=float(i)) for i in range(1, 6)]
    _score(*runs)
    rows = aggregate(find_runs([tmp_path]))
    ttd = next(row for row in rows if row["metric"] == "ttd_seconds")
    assert ttd["median"] == 3.0 and ttd["n"] == 5 and ttd["misses"] == 0
    assert all(row["env_tag"] == "mock" and row["phase"] == "dev" for row in rows)
    out = tmp_path / "agg"
    assert aggregate_main([str(tmp_path / f"r{i}") for i in range(1, 6)] + ["--out", str(out)]) == 0
    assert (out / "aggregate-mock-dev.json").is_file() and (out / "aggregate-mock-dev.csv").is_file()


def test_mixed_env_tags_are_refused_naming_the_runs(tmp_path: Path) -> None:
    a = _run(tmp_path, "a", "mock", "dev")
    b = _run(tmp_path, "b", "sandbox", "dev")
    _score(a, b)
    with pytest.raises(MixError, match="env tags") as caught:
        check_mixing(find_runs([tmp_path]))
    assert str(a) in str(caught.value) and str(b) in str(caught.value)
    assert aggregate_main([str(a), str(b), "--out", str(tmp_path / "agg")]) == 2
    assert not (tmp_path / "agg").exists()


def test_dev_and_eval_runs_are_refused_in_one_table(tmp_path: Path) -> None:
    a = _run(tmp_path, "a", "mock", "dev")
    b = _run(tmp_path, "b", "mock", "eval")
    _score(a, b)
    with pytest.raises(MixError, match="dev and eval"):
        check_mixing(find_runs([tmp_path]))


def test_a_tampered_run_stops_aggregation(tmp_path: Path) -> None:
    run = _run(tmp_path, "a", "mock", "dev")
    _score(run)
    (run / "poll.jsonl").write_text("{}\n", encoding="utf-8")
    assert aggregate_main([str(run), "--out", str(tmp_path / "agg")]) == 1


def test_an_undetected_attack_is_a_miss_not_a_large_number() -> None:
    facts = RunFacts("x", 100.0, 110.0, ATTACKER_MAC, None, 1000.0, {})
    result = time_to_detect(facts, [{"t": 105.0, "events": [], "offenders": [], "rules": []}], grace=30.0)
    assert result["detected"] is False and result["ttd_seconds"] is None


def test_ttm_is_when_the_victim_rate_stays_below_the_fraction() -> None:
    facts = RunFacts("x", 0.0, 10.0, None, "192.0.2.100", 1000.0, {})
    # 1000 pps for 3 s, then 10 pps (below 10% of offered) to the end.
    arrivals = [i / 1000.0 for i in range(3000)] + [3.0 + i / 10.0 for i in range(70)]
    result = time_to_mitigate(facts, arrivals, fraction=0.1, hold=2.0, bin_seconds=0.1)
    assert result["ttm_seconds"] == pytest.approx(3.0)
    effectiveness = result["mitigation_effectiveness"]
    assert isinstance(effectiveness, float) and effectiveness > 0.98

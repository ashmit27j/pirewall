"""Score a campaign run: TTD, TTM, mitigation effectiveness, collateral, admin API p95 (PLAN_FINAL §5).

    uv run python lab/score_run.py RUN_DIR [RUN_DIR ...] [--grace 30] [--ttm-fraction 0.1] [--ttm-hold 2.0]

Reads what `lab/run_campaign.py` sealed into the run directory and writes
`RUN_DIR/score/metrics.json`, sealed by its own `score/manifest.json` (the
run's manifest is never rewritten). Definitions, verbatim from
critique_safety_eval.md "Metric definitions", with the constants as flags:

* **TTD** = first pirewall event at MONITOR or above attributed to the
  attacker (its MAC, or its IP) minus `t_start`. None by `t_end + grace` is a
  *miss* (`detected = false`); it is never averaged in as a large number.
  Secondary: the first poll showing the attacker in `@offenders`
  (`first_offender_seconds`) and the first poll showing an active
  RATE_LIMIT/BLOCK on it (`first_enforcement_seconds`), at the 1 s poll
  resolution.
* **TTM** = the first instant after `t_start` from which the attack's
  packet rate *at the victim* stays below `--ttm-fraction` of the offered
  rate for `--ttm-hold` seconds, minus `t_start`, from the victim-side capture
  (`victim.pcap`, `lab/victim_pcap.py`), never from pirewall's own claims.
  None when that never happens before `t_end`.
* **Mitigation effectiveness** = 1 - attack packets reaching the victim in
  `[t_start + TTM, t_end]` / packets offered in that interval (offered =
  the campaign's `offered_rate_pps` x duration). Without a TTM, over the
  whole attack.
* **Collateral damage**: legitimate-client throughput during the attack
  over the pre-attack baseline, wired and Wi-Fi separately (`probe.jsonl`
  from `lab/benign/background.py --profile probe`), and the number of
  RATE_LIMIT/BLOCK rules created against anything but the attacker.
* **Admin API p95** (G1): of the `api_latency_ms` the poller measured
  during the attack; failed probes are counted, not dropped.

Attack packets at the victim are those matching the run's `victim_filter`
(source IP, protocol, destination port; `extra.victim_filter` in the run
manifest), so random-source floods are still counted by protocol and port.
"""

import argparse
import json
import math
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # `python lab/score_run.py`

from lab.manifest import Json, Manifest, ManifestError, read_manifest, write_manifest
from lab.victim_pcap import VictimPacket, read_victim_pcap

TOOL: Final = "lab/score_run.py"
_ACTING: Final = frozenset({"monitor", "rate_limit", "block"})
_ENFORCING: Final = frozenset({"rate_limit", "block"})
_LIVE: Final = frozenset({"active", "pending_approval"})


class ScoreError(Exception):
    """The run directory lacks what scoring needs."""


@dataclass(frozen=True, slots=True)
class RunFacts:
    """What the run recorded about itself."""

    attack: str
    t_start: float
    t_end: float
    attacker_mac: str | None
    attacker_ip: str | None
    offered_rate_pps: float | None
    victim_filter: dict[str, Json]


def _facts(directory: Path, document: dict[str, Json]) -> RunFacts:
    extra = document.get("extra")
    if not isinstance(extra, dict):
        raise ScoreError(f"{directory}: run manifest has no extra")

    def number(key: str) -> float | None:
        value = extra.get(key)
        return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None

    t_start, t_end = number("t_start"), number("t_end")
    if t_start is None or t_end is None:
        raise ScoreError(f"{directory}: run manifest lacks t_start/t_end")
    victim_filter = extra.get("victim_filter")
    mac, ip = extra.get("attacker_mac"), extra.get("attacker_ip")
    return RunFacts(
        attack=str(extra.get("attack")),
        t_start=t_start,
        t_end=t_end,
        attacker_mac=str(mac).lower() if isinstance(mac, str) else None,
        attacker_ip=str(ip) if isinstance(ip, str) else None,
        offered_rate_pps=number("offered_rate_pps"),
        victim_filter=victim_filter if isinstance(victim_filter, dict) else {},
    )


def _polls(directory: Path) -> list[dict[str, Json]]:
    path = directory / "poll.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _event_time(event: dict[str, Json]) -> float | None:
    from datetime import datetime

    stamp = event.get("timestamp")
    if not isinstance(stamp, str):
        return None
    try:
        return datetime.fromisoformat(stamp).timestamp()
    except ValueError:
        return None


def _is_attacker(facts: RunFacts, mac: Json, ip: Json) -> bool:
    return (
        facts.attacker_mac is not None and isinstance(mac, str) and mac.lower() == facts.attacker_mac
    ) or (facts.attacker_ip is not None and ip == facts.attacker_ip)


def time_to_detect(facts: RunFacts, polls: Sequence[dict[str, Json]], grace: float) -> dict[str, Json]:
    """TTD and its secondary, poll-resolution figures."""
    deadline = facts.t_end + grace
    first_event: float | None = None
    first_offender: float | None = None
    first_enforcement: float | None = None
    for poll in polls:
        at = poll.get("t")
        if not isinstance(at, int | float):
            continue
        events = poll.get("events")
        for event in events if isinstance(events, list) else []:
            if not isinstance(event, dict) or event.get("decision") not in _ACTING:
                continue
            when = _event_time(event)
            if when is None or not facts.t_start <= when <= deadline:
                continue
            if _is_attacker(facts, event.get("mac"), event.get("source")):
                first_event = when if first_event is None else min(first_event, when)
        if not facts.t_start <= at <= deadline:
            continue
        offenders = poll.get("offenders")
        if (
            first_offender is None
            and isinstance(offenders, list)
            and any(
                isinstance(entry, dict) and _is_attacker(facts, entry.get("mac"), None) for entry in offenders
            )
        ):
            first_offender = float(at)
        rules = poll.get("rules")
        if (
            first_enforcement is None
            and isinstance(rules, list)
            and any(
                isinstance(rule, dict)
                and rule.get("action") in _ENFORCING
                and rule.get("status") in _LIVE
                and _is_attacker(facts, rule.get("mac"), rule.get("ip"))
                for rule in rules
            )
        ):
            first_enforcement = float(at)

    def since(value: float | None) -> float | None:
        return None if value is None else value - facts.t_start

    return {
        "detected": first_event is not None,
        "ttd_seconds": since(first_event),
        "first_offender_seconds": since(first_offender),
        "first_enforcement_seconds": since(first_enforcement),
    }


def _matches(packet: VictimPacket, wanted: dict[str, Json]) -> bool:
    src, proto, dport = wanted.get("src"), wanted.get("proto"), wanted.get("dport")
    return (
        (src is None or str(packet.src) == src)
        and (proto is None or packet.proto == proto)
        and (dport is None or packet.dport == dport)
    )


def time_to_mitigate(
    facts: RunFacts, arrivals: Sequence[float], fraction: float, hold: float, bin_seconds: float
) -> dict[str, Json]:
    """TTM and effectiveness from attack-packet arrival times at the victim."""
    if facts.offered_rate_pps is None or facts.offered_rate_pps <= 0:
        return {
            "ttm_seconds": None,
            "mitigation_effectiveness": None,
            "victim_packets": len(arrivals),
            "ttm_note": "no offered rate recorded for this attack",
        }
    duration = facts.t_end - facts.t_start
    bins = max(math.ceil(duration / bin_seconds), 1)
    counts = [0] * bins
    for at in arrivals:
        index = math.floor((at - facts.t_start) / bin_seconds)
        if 0 <= index < bins:
            counts[index] += 1
    limit = fraction * facts.offered_rate_pps * bin_seconds
    need = max(math.ceil(hold / bin_seconds), 1)
    ttm: float | None = None
    run = 0
    for index, count in enumerate(counts):
        run = run + 1 if count < limit else 0
        if run >= need:
            ttm = (index - need + 1) * bin_seconds
            break
    start = facts.t_start + (ttm or 0.0)
    window = facts.t_end - start
    delivered = sum(1 for at in arrivals if start <= at <= facts.t_end)
    offered = facts.offered_rate_pps * window
    effectiveness = None if offered <= 0 else max(0.0, 1.0 - delivered / offered)
    return {
        "ttm_seconds": ttm,
        "mitigation_effectiveness": effectiveness,
        "victim_packets": len(arrivals),
        "delivered_after_ttm": delivered,
        "offered_after_ttm": offered,
    }


def _mean(values: Sequence[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _p95(values: Sequence[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1)]


def collateral(facts: RunFacts, directory: Path) -> dict[str, Json]:
    """Throughput during the attack / before it, per client class; None when not measured."""
    path = directory / "probe.jsonl"
    out: dict[str, Json] = {
        "wired": None,
        "wifi": None,
        "wired_http_p95_ratio": None,
        "wifi_http_p95_ratio": None,
    }
    if not path.is_file():
        return out
    samples = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for client in ("wired", "wifi"):
        for kind, key, statistic in (
            ("throughput_mbps", client, _mean),
            ("http_ms", f"{client}_http_p95_ratio", _p95),
        ):
            before = [
                float(s["value"])
                for s in samples
                if s.get("client") == client and s.get("kind") == kind and float(s["t"]) < facts.t_start
            ]
            during = [
                float(s["value"])
                for s in samples
                if s.get("client") == client
                and s.get("kind") == kind
                and facts.t_start <= float(s["t"]) <= facts.t_end
            ]
            base, now = statistic(before), statistic(during)
            out[key] = None if base is None or now is None or base == 0 else now / base
    return out


def actions_against_others(facts: RunFacts, polls: Sequence[dict[str, Json]], grace: float) -> int:
    """Distinct RATE_LIMIT/BLOCK rules created in the attack (+ grace) against anyone but the attacker."""
    seen: set[str] = set()
    for poll in polls:
        rules = poll.get("rules")
        for rule in rules if isinstance(rules, list) else []:
            if not isinstance(rule, dict) or rule.get("action") not in _ENFORCING:
                continue
            if _is_attacker(facts, rule.get("mac"), rule.get("ip")):
                continue
            created = _event_time({"timestamp": rule.get("created_at")})
            if created is not None and facts.t_start <= created <= facts.t_end + grace:
                seen.add(str(rule.get("id")))
    return len(seen)


def score(directory: Path, grace: float, fraction: float, hold: float, bin_seconds: float) -> dict[str, Json]:
    """Every metric for one run."""
    document = read_manifest(directory)
    if document.get("kind") != "run":
        raise ScoreError(f"{directory}: not a run directory")
    facts = _facts(directory, document)
    polls = _polls(directory)
    metrics: dict[str, Json] = {
        "attack": facts.attack,
        "run": directory.name,
        "env_tag": document["env_tag"],
        "phase": document.get("phase"),
    }
    metrics.update(time_to_detect(facts, polls, grace))
    victim = directory / "victim.pcap"
    if victim.is_file():
        arrivals = [packet.at for packet in read_victim_pcap(victim) if _matches(packet, facts.victim_filter)]
        metrics.update(time_to_mitigate(facts, arrivals, fraction, hold, bin_seconds))
    else:
        metrics.update({"ttm_seconds": None, "mitigation_effectiveness": None, "ttm_note": "no victim.pcap"})
    metrics["collateral"] = collateral(facts, directory)
    metrics["actions_against_others"] = actions_against_others(facts, polls, grace)
    latencies: list[float] = []
    failures = 0
    for poll in polls:
        at = poll.get("t")
        if not isinstance(at, int | float) or not facts.t_start <= at <= facts.t_end:
            continue
        latency = poll.get("api_latency_ms")
        if isinstance(latency, int | float):
            latencies.append(float(latency))
        else:
            failures += 1
    metrics["admin_api_p95_ms"] = _p95(latencies)
    metrics["admin_api_failures"] = failures
    metrics["parameters"] = {
        "grace": grace,
        "ttm_fraction": fraction,
        "ttm_hold": hold,
        "bin_seconds": bin_seconds,
    }
    return metrics


def write_score(directory: Path, metrics: dict[str, Json]) -> Path:
    """Write and seal `directory/score/`."""
    out = directory / "score"
    out.mkdir(exist_ok=False)
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8", newline="\n")
    phase = metrics.get("phase")
    write_manifest(
        out,
        Manifest(
            kind="score",
            env_tag=str(metrics["env_tag"]),
            tool=TOOL,
            phase="eval" if phase == "eval" else "dev" if phase == "dev" else None,
        ),
    )
    return out / "metrics.json"


def main(argv: Sequence[str] | None = None) -> int:
    """Exit 0 when every run scored, 2 otherwise."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("runs", nargs="+", type=Path)
    parser.add_argument(
        "--grace", type=float, default=30.0, help="seconds after t_end a detection still counts"
    )
    parser.add_argument("--ttm-fraction", type=float, default=0.1, help="fraction of the offered rate (TTM)")
    parser.add_argument(
        "--ttm-hold", type=float, default=2.0, help="seconds the rate must stay below it (TTM)"
    )
    parser.add_argument("--bin", type=float, default=0.1, help="victim-rate bin width, seconds")
    args = parser.parse_args(argv)
    failed = 0
    for run in args.runs:
        try:
            path = write_score(run, score(run, args.grace, args.ttm_fraction, args.ttm_hold, args.bin))
        except (ScoreError, ManifestError, OSError, ValueError) as exc:
            print(f"score_run: {exc}", file=sys.stderr)
            failed += 1
            continue
        print(f"scored {run} -> {path}")
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

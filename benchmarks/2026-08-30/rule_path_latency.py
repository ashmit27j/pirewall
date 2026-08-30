"""Rule-path latency (spec §40 "rule-deployment latency") on the real Pi, without mutating anything.

Spec §40 asks for rule-deployment latency. Measuring the *real* deployment
end to end would mean inserting rules into the live nftables ruleset, which
this benchmark is explicitly not allowed to do. So the path is measured in
the two pieces it is actually made of, each honestly labelled:

1. **Validation chain + deploy call, real code, Fake backend.** A real
   `FirewallManager` built from the deployed `local_config.toml`, wired to
   `FakeFirewallBackend`. Every one of the ten validation stages (schema ->
   network -> allowlist -> safety -> conflict -> duplicate -> rate cap ->
   priority -> expiration -> authorization) runs for real; only the final
   `nft` call is faked. This is the same measurement shape as the Phase 9
   dev-machine number, so the two are directly comparable.

2. **Real `nft` round-trip, read-only.** The exact commands
   `NftablesBackend` issues against the live ruleset that do not change it:
   `nft -j list chain inet pirewall adaptive` (`_list_ruleset`, which every
   apply/remove performs for handle lookup) and `nft -j list tables`
   (`health_check`). Nothing is inserted, deleted, or flushed.

Real deployment latency is therefore (1) + one or two of (2), which the
report states as a bound rather than a measurement.

Candidates use TEST-NET-3 (203.0.113.0/24, RFC 5737) sources so they cannot
collide with the Pi, the Admin PC, the protected LAN or the upstream
gateway -- i.e. they pass safety validation rather than short-circuiting it.

    sudo .venv/bin/python3.12 benchmarks/<date>/rule_path_latency.py --outdir benchmarks/<date>/data
"""

import argparse
import json
import statistics
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pirewall.config.loader import load_config
from pirewall.core.enums import FirewallAction, Protocol, RuleDirection, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.rule import CandidateRule
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.manager import FirewallManager


def percentiles(values: list[float]) -> dict[str, float]:
    if not values:
        return {}
    ordered = sorted(values)

    def pct(p: float) -> float:
        idx = min(len(ordered) - 1, max(0, round(p / 100.0 * (len(ordered) - 1))))
        return ordered[idx]

    return {
        "count": len(ordered),
        "mean_ms": statistics.fmean(ordered),
        "p50_ms": pct(50), "p95_ms": pct(95), "p99_ms": pct(99),
        "min_ms": ordered[0], "max_ms": ordered[-1],
        "ops_per_second": 1000.0 / statistics.fmean(ordered),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", required=True)
    parser.add_argument("--config", default="config/local_config.toml")
    parser.add_argument("--candidates", type=int, default=200)
    parser.add_argument("--nft-samples", type=int, default=50)
    args = parser.parse_args()

    config = load_config(Path(args.config))
    batch = config.firewall.max_adaptive_rules_per_window

    accepted_ms: list[float] = []
    rejected_ms: list[float] = []
    rejections: dict[str, int] = {}
    now = datetime.now(UTC)

    manager = FirewallManager(config, FakeFirewallBackend())
    for index in range(args.candidates):
        if index % batch == 0:
            # A fresh manager every `max_adaptive_rules_per_window` candidates,
            # so each candidate is measured on the accepted path rather than
            # being short-circuited by the A3 rate cap. Documented in REPORT.md.
            manager = FirewallManager(config, FakeFirewallBackend())
        decision = FirewallDecision(
            id=str(uuid4()),
            threat_assessment_id=str(uuid4()),
            flow_id=str(uuid4()),
            action=FirewallAction.MONITOR,
            threat_score=60.0,
            threat_level=ThreatLevel.MEDIUM,
            reason="benchmark candidate (never reaches a real backend)",
            evidence=["benchmark"],
            decided_at=now,
        )
        candidate = CandidateRule(
            decision_id=decision.id,
            action=FirewallAction.MONITOR,
            direction=RuleDirection.INBOUND,
            source=IPv4Network(f"203.0.113.{index % 254 + 1}/32"),
            destination=IPv4Network("192.168.100.50/32"),
            protocol=Protocol.TCP,
            destination_port=8000 + index,
            created_at=now,
            expires_at=now + timedelta(seconds=config.firewall.default_rule_ttl_seconds),
            threat_score=60.0,
            reason="benchmark candidate",
        )
        start = time.perf_counter()
        manager.register_decision(decision)
        result = manager.submit_candidate(candidate, now)
        elapsed = (time.perf_counter() - start) * 1000.0
        if result.rule is None:
            rejected_ms.append(elapsed)
            reason = str(result.event.reason)
            rejections[reason] = rejections.get(reason, 0) + 1
        else:
            accepted_ms.append(elapsed)

    def time_nft(command: list[str]) -> list[float]:
        samples: list[float] = []
        for _ in range(args.nft_samples):
            start = time.perf_counter()
            proc = subprocess.run(["nft", *command], capture_output=True, text=True)
            samples.append((time.perf_counter() - start) * 1000.0)
            if proc.returncode != 0:
                return []
        return samples

    list_chain = time_nft(["-j", "list", "chain", "inet", "pirewall", "adaptive"])
    list_tables = time_nft(["-j", "list", "tables"])

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "candidates": args.candidates,
        "rate_cap_batch_size": batch,
        "validation_chain_fake_backend": {
            "accepted": percentiles(accepted_ms),
            "rejected": percentiles(rejected_ms),
            "rejection_reasons": rejections,
        },
        "real_nft_read_only": {
            "list_chain_inet_pirewall_adaptive": percentiles(list_chain),
            "list_tables_health_check": percentiles(list_tables),
        },
    }
    out = Path(args.outdir) / "rule_path_latency.json"
    out.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

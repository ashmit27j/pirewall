# Phase 17: D1 detectors (MAC-keyed, learned thresholds), the kernel offender poller, and the policy engine

**Read first:**
- `CLAUDE.md` (v2 section)
- `docs/ADDENDUM_4.md` D4
- `docs/V2_CONTRACTS.md` (Evidence variants, PolicyDecision, connection-start)
- `docs/v2/PLAN_FINAL.md` §4.5–4.6
- `docs/v2/critique_round2.md` items 6, 9, 11 and 12
- `docs/v2/critique_redteam.md` items 8, 10, 11 and 12
- `pirewall/detection/behavior.py`, as rewritten by the overhaul
- `pirewall/engine/`
- `pirewall/runtime/core.py` (fast path ~L979–1012)

**Depends on:** phase 16. Phase 18 may run in parallel. **Integrator duty:** owns `runtime/core.py`, `runtime/pipeline.py` and `engine/**`. Create `pirewall/policy/**` and `pirewall/detection_v2/**`.

## Goal
`pipeline.engine = "v2"`:
- The kernel tier and the deterministic per-device detectors are the only evidence that can trigger enforcement. Their thresholds are learned from benign traffic and frozen.
- Actions come from an explicit policy table.
- Scores remain only for explanation and the UI.
- v1 stays selectable for the baseline.

## Deliverables
1. **K poller** (`detection_v2/kernel.py`). A thread that, every second:
   - reads `@offenders`, the per-guard drop counters, set fill levels and table existence;
   - tracks `sustained_polls` per (code, MAC);
   - emits `KernelGuardEvidence` carrying the guard's **current mode**.

   It raises CRITICAL if a table disappears and WARNING if a set is above 80% full. Meter-set membership is never treated as evidence.
2. **D1 detectors** (`detection_v2/d1.py`). These are pure functions over a per-MAC sliding state built from `NewFlowRecord`/`FlowRecord` streams, counting **connection starts**. Windows are 10 s and 60 s (1 h is optional and cuttable). Detectors:
   - vertical scan (distinct dst ports per dst host)
   - horizontal scan (distinct dst hosts per port)
   - failed-handshake ratio
   - brute force (many short, similar-size connections to one dst:port in {22, 80, 443, 8080, portal})
   - slow-rate DoS (ported from v1 `SLOW_RATE_DOS`)
   - fan-in per destination (many MACs to one destination)
   - new-MAC and new-lease rate, from `BindingTable`
   - portal auth failures per account and global, from portal events

   Each detector emits `D1Evidence{detector, window, value, threshold, mac}`. State is bounded (LRU per MAC, with sizes in config) and has eviction counters.
3. **Thresholds** (`detection_v2/thresholds.py` + `scripts/train/fit_d1_thresholds.py`).
   - The script reads the benign *training block* from `pcap_to_flows` output and computes per-detector benign P99.9.
   - It writes `config/d1_thresholds.toml` with `clamp(P99.9 × margin, floor, ceiling)`, using the documented floors and ceilings (e.g. a vertical scan over 100 ports/60 s is never benign), plus a hash and the provenance (input manifest hashes, block boundaries).
   - Core loads thresholds from that file and refuses to start `engine=v2` in ASSISTED/ACTIVE without it.
   - A `--freeze` flag writes `frozen=true`, which the harness checks before campaign #2.
4. **Policy engine** (`pirewall/policy/`). The table from PLAN_FINAL §4.6 is **data** (`policy/table.toml`), so it can be reviewed. The engine:
   - maps an evidence bundle per MAC to a `PolicyDecision`;
   - applies TTL escalation only on **new independent evidence**;
   - caps TTL at `max_ttl`;
   - sends BLOCK to approval in ASSISTED;
   - turns observe-mode K evidence into MONITOR only;
   - requires enforce-mode K evidence to have `sustained_polls ≥ 2`.

   Decisions then go through validator v2 and FirewallManager, which is the existing single deploy path.
5. **Scoring → UI only.** `PolicyDecision.threat_level` drives the dashboard and API fields. Keep `engine/scoring.py` for explanation strings. Under `engine=v2`, nothing reads a score to choose an action. Add a test that proves this by mutating the scores and checking that the actions are unchanged.
6. **ML evidence (D2/D3) is optional input**, accepted as MONITOR or corroboration only. It is wired through the existing coordinator when models are loaded.
7. **Pipeline switch.** `engine=v1` is the merged-main behaviour, deploying through the v2 backend adapter. `engine=v2` is the new path. The source fast path is reused for D1 timing.
8. **Events and metrics.** New event types/fields for policy decisions. The Netdata gauges are re-sourced (engine stats, guard drops, offenders, set fill). The Wazuh JSON gains the documented fields, plus `deploy/wazuh/pirewall_decoder.xml` with rules matching the v2 JSON.

## Tests
- **Policy matrix:** the exhaustive cross-product of {K observe/enforce × sustained} × {D1 none/single/repeat-new/repeat-same} × {D2} × {D3} × {SHADOW/ASSISTED/ACTIVE} → expected max action. The invariants ML-only ≤ MONITOR, anomaly-only ≤ MONITOR and allowlisted ⇒ none are asserted separately.
- **D1 unit tests** with synthetic connection-start streams: nmap-like, masscan-like, hydra-like, slowloris-like, a busy page load, a phone waking up, an OS update, P2P. Benign cases must stay under the default floors.
- **Threshold fitting** is deterministic and its provenance is recorded.
- **Mock end to end** (`--data-mode mock` with the phase-18 mock pcaps if present, otherwise inline fixtures): the attack MACs get the expected actions and the benign MACs get none.

## Non-goals
No ML training (phase 19). No harness (phase 18). Thresholds are fitted only when real benign data exists; until then, ship the floors with `frozen=false`.

## Definition of done
- All suites green, and the policy matrix is complete.
- PROGRESS marks **v2.1 (engine)**.
- v1 #6/#7/#10/#11 and audit #10's new risk are fixed in code.
- Environment-dependent: threshold fitting on real `pi-live` data (RUNBOOK H20).

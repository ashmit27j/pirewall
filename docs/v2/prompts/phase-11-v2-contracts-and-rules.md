# Phase 11: v2 contracts, project rules and additive config

**Setup before you start.** The v2 design folder must already be in the repo at `docs/v2/`. It contains `PLAN_v3.md`, `PLAN_FINAL.md`, `critique_*.md`, `audit_new_main.md`, `RUNBOOK_PI.md`, `prompts/` and `v2/`, where `v2/` holds the tested nft templates, the netns testbed and `RESULTS.md`.
- If `docs/v2/` is missing, stop and ask the human to copy it in.

**Read before writing anything:**
- `CLAUDE.md`
- `docs/ADDENDUM.md`, `ADDENDUM_2.md`, `ADDENDUM_3.md`
- `docs/v2/PLAN_v3.md` (authoritative), then `docs/v2/PLAN_FINAL.md` §4–§5, which PLAN_v3 refers to for unchanged details
- `docs/v2/audit_new_main.md`
- `docs/v2/v2/RESULTS.md`
- `docs/KNOWN_ISSUES.md`, `docs/PROGRESS.md`
- `pirewall/config/models.py`, `pirewall/core/models/`

Inspect the existing code before changing it (spec §49).

## Goal
Freeze the v2 rules and interfaces **before** any v2 implementation, so that later phases, possibly run in parallel git worktrees, cannot diverge. This phase writes documents, typed stubs and additive config. It changes no runtime behaviour.

## Deliverables
1. **`docs/ADDENDUM_4.md`.** The v2 additions, in the same style as ADDENDUM_3. ADDENDUM_4 wins over every earlier document. It has these items:
   - **D1 Two kernel tables.**
     - `pirewall_static` is template-only. The single permitted runtime write is replacing the contents of the `guard_verdict_*` chains, via `FirewallManager.set_guard_mode`. The only other change allowed is panic.
     - `pirewall_adaptive` sets are written only by `FirewallManager`.
   - **D2 Static guards are reviewed static policy, not adaptive rules.** State the per-guard defaults (input enforce, raw enforce-if-seeded, forward observe) and how this reconciles with A1 SHADOW-by-default.
   - **D3 MAC identity.** Covers `RuleTarget{ip, mac}`, `BindingTable`, the lease file as the binding source, and anti-spoof ordering.
   - **D4 Policy table replaces score-driven actions.** Scores remain for explanation and UI only. ML-only and anomaly-only evidence ⇒ at most MONITOR.
   - **D5 Kill switch and panic semantics.** Fail-open revert flushes **adaptive sets only**.
   - **D6 Native engine in core.** Hardening requirements: `catch_unwind`, a fuzz target, ring-offset clamps. The sensor split is deferred and says so.
   - **D7 Data modes and env tags** (`pi-live`, `pi-scripted`, `sandbox`, `mock`), and the no-mixing rule.
   - **D8 Scope statement**, verbatim from PLAN_v3 §1.
   - **D9 v1 features dropped or ported.** Heartbleed/JA3 dropped. TEMPORAL_PATTERN/PERSISTENCE become MONITOR or are dropped. SLOW_RATE_DOS is ported. Netdata gauges are re-sourced.
2. **`docs/V2_CONTRACTS.md` plus typed stubs.** Stubs are Pydantic models or Protocols with docstrings. They raise `NotImplementedError` wherever logic would go. Cover:
   - **`RuleTarget`** (`ip: IPv4Address`, `mac: MacAddress | None`). Define `MacAddress` as a constrained, normalised lowercase `aa:bb:cc:dd:ee:ff` type in `pirewall/core/models/common.py`.
   - **`Binding`** (ip, mac, expires_at, source: lease|static) and the **`BindingTable`** Protocol: `resolve_mac`, `resolve_ip`, `snapshot`, `apply_leases`.
   - **Evidence variants** in `pirewall/core/models/evidence_v2.py`: `KernelGuardEvidence{code, mac, guard, guard_mode, sustained_polls}`, `D1Evidence{detector, window_seconds, value, threshold, mac}`, `AnomalyEvidence` (reuse the existing one), `ClassifierEvidence`.
   - **`PolicyDecision`**: action, target, ttl, reasons, `evidence_ids`, `requires_approval`, and a `threat_level` mapping for the UI.
   - **Offender code table.** Use the integers and names from `docs/v2/v2/pirewall_static.nft.template`.
   - **Set and chain names**, copied exactly from the templates.
   - **New RPC methods**, as signatures only: `get_guard_modes`, `set_guard_mode`, `panic`, `list_offenders`, `list_bindings`, `get_engine_stats`.
   - **Native `FlowRecord`/`NewFlowRecord` additions:** `src_mac`, `dst_mac`.
   - **Connection-start definition:** a record whose initiator sent a SYN and that has no earlier record for the same 5-tuple.
   - **File-ownership map for later phases.** Only the integrator phase that owns a file may edit `runtime/core.py`, `firewall/manager.py` or `ipc/dispatcher.py`. Name that phase per file.
3. **`CLAUDE.md` v2 section** (append; don't rewrite the existing rules). Add:
   - ADDENDUM_4 precedence and the reading checklist.
   - The new invariants: two tables, the single static-table write, ML ⇒ ≤ MONITOR, MAC identity, env tags.
   - The dependency additions, each with a reason:
     - `python3-nftables` from Debian, reached through a `.pth` file. It is ctypes over libnftables, so it works from the 3.12 venv.
     - `scapy` as a **dev/lab-only** extra.
     - The existing Rust `native/`.
   - The honesty rule that `mock`/`sandbox` numbers can never be reported as Pi results.
4. **Additive config sections** in `pirewall/config/models.py` and `config/default_config.toml`. Every new field has a default. No existing key is renamed or removed (models are `extra="forbid"`). New sections:
   - `[pipeline] engine = "v1"` (the default stays v1 until phase 17).
   - `[guards]`: modes per guard, and every meter rate and burst. Use the template values; rate and burst are calibrated together.
   - `[antispoof]`: `lease_file`, `static = []`, `grace_seconds`.
   - `[policy]`: TTLs, `max_ttl_seconds = 3600`, `sustained_polls = 2`.
   - `[lab]`: `env_tag`, victim netns settings.
   - `capture.backend` gains a `"replay"` option. Validation only for now; the implementation is phase 15.
5. **`scripts/deployment/migrate_config.py`.** Upgrades a 1.x or 2.0 `local_config.toml` to the v2 schema, keeping comments where feasible. It has `--check`, which exits non-zero when migration is needed, and `--write`, which makes a backup first. Tests cover a 1.x sample, a 2.0 sample and an already-migrated file.
6. **`docs/PROGRESS.md`.** Add a "v2" section with phases 11–20 listed and labelled.

## Tests
- Models round-trip and validate: MAC normalisation, plus rejection of bad MACs and of multicast or broadcast MACs as identity.
- The default config loads, and a config without any v2 section still loads, which proves the changes are additive.
- The `migrate_config` cases above.
- A test asserting that the set and chain name constants in the contracts match the names in `docs/v2/v2/*.nft.template`. Parse the templates as text.

## Non-goals
No behaviour change, no new runtime wiring, no template loading. Don't edit `runtime/core.py`, `firewall/manager.py` or `ipc/dispatcher.py` in this phase.

## Definition of done
- `ruff check .` clean.
- `pyright --strict` clean.
- `pytest` green: everything that passed before still passes.
- ADDENDUM_4 and V2_CONTRACTS are complete.
- `PROGRESS.md` is updated with honest labels.
- The summary lists any point where PLAN_v3 was ambiguous and the choice made.

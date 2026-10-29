# Phase 20: evaluation support, documentation reconciliation and paper tables

**Read first:**
- `CLAUDE.md`, `docs/HANDOFF.md`, `docs/PROGRESS.md` (v2 section)
- `docs/ADDENDUM_4.md` D7 (env tags), D8 (scope statement, verbatim), D9
- `docs/v2/PLAN_v3.md` §1, §2, §5; `docs/v2/PLAN_FINAL.md` §5
- `docs/v2/critique_ml.md` §10 (Tables I–VII, Figs 1–5, threats to validity mapped to Arp P1–P10)
- `docs/v2/RUNBOOK_PI.md` (what the human ran, and in which order)
- `lab/README.md`, `lab/aggregate.py`, `lab/verify_manifest.py` (phase 18)
- Every doc listed under "Docs to reconcile" below

**Depends on:** all earlier phases. Paper tables need the human's `pi-*` campaign runs (RUNBOOK_PI H24–H41); without them, build the generators and test them on `mock` aggregates, labelled `mock`, and leave every Pi cell empty with "not yet run".

**Owns:** `lab/paper/**`, every file under `docs/` except the frozen ones (`MASTER_SPEC.md`, `ADDENDUM*.md`, `V2_CONTRACTS.md` beyond §12/§13 bookkeeping, `docs/v2/PLAN_*.md`, `docs/v2/critique_*.md`), `README.md`, `setup-new-network.md`, and fixes to `lab/**` that campaigns exposed (record each). No runtime code changes, except a bug fix the human asked for, recorded as a deviation.

## Goal
Anyone can reproduce every reported number from manifests, the docs describe the system that actually exists, and the human has a short, honest list of what was and was not verified on the Pi.

## Deliverables
1. **Evaluation support.** Walk RUNBOOK_PI's campaign steps against the real harness. Fix the harness where a campaign exposed a defect (with a regression test), and correct the runbook where it drifted from the CLI.
2. **Paper tables and figures** (`lab/paper/make_tables.py`, `lab/paper/make_figures.py`, stdlib + matplotlib only if already a dependency, otherwise CSV/LaTeX/markdown tables and data files the human plots).
   - Input is **only** `lab/aggregate.py` output plus phase 19's report data; never raw logs, never a hand-typed number.
   - Refuses non-`pi-*` input unless `--regression`, which watermarks every table "REGRESSION EVIDENCE (env=mock|sandbox) — NOT A PI RESULT".
   - Tables I–VII and Figs 1–5 exactly as critique_ml.md §10 lists them; v1 vs v2 columns from the G8 baseline runs; the ablation (kernel only / +D1 / +D2 / +D3); every table carries its manifest hashes in a footnote.
   - `benchmarks/2026-10-15-native-capture/LIVE_AB.md` (the 2026-10-15 overhaul A/B) are labelled **"development replay"**, never evaluation.
   - Threats to validity, mapped to Arp P1–P10: single home network, hours of benign traffic actually captured (from Table I, not the plan's estimate), lab tools, domain shift, partially tested adaptive attacker, shared CPU with `labvictim`.
3. **Docs to reconcile** (each one read against the code, not against the plan):
   - `README.md`: the D8 scope statement verbatim, the v2 architecture line (kernel guards → adaptive sets ← policy ← K/D1 (+D2/D3 evidence)), status, doc map.
   - `docs/KNOWN_ISSUES.md`: close or re-label every v1 item against v2; merge the "v2 open items" table into the numbered list; refresh "Last reviewed".
   - `docs/PROGRESS.md`: row 20, a "v2 final state" section, every Pi claim backed by a `pi-*` artifact or labelled Environment-dependent.
   - `docs/SETUP.md` and `setup-new-network.md`: the v2 path end to end, including `--engine v2`, fitting and freezing thresholds, flipping the forward guard after the G5 verdict, and panic recovery.
   - `docs/ARCHITECTURE.md`, `docs/FIREWALL.md` (two tables, guards, sets, validator v2), `docs/API.md` (v2 routes), `docs/TESTING.md` (netns tier, mock mode, WSL `pw` vs root), `docs/SECURITY.md`, `docs/DEPLOYMENT.md`, `docs/DEPLOYMENT_COMPLETE.md`.
   - `docs/HANDOFF.md`: final state; the file map still matches `git ls-files`.
4. **Human decisions, presented not taken:** flipping `pipeline.engine` default to `"v2"`; forward guard to enforce (only if `lab/benign_fp.py` says yes on `pi-live`); enforcement mode beyond SHADOW. Each with the evidence for and against.

## Tests
- `make_tables.py` refuses mixed tags and non-`pi-*` input without `--regression`; the regression watermark appears on every table; output is a pure function of the aggregate input (hash-stable).
- A docs check (`tests/unit/test_docs_consistency.py`): every file path in `docs/HANDOFF.md`'s file map exists; every `pirewall-start` flag in `docs/SETUP.md` exists in the script's usage.

## Non-goals
No new detection, policy, guard or ML behaviour. No inventing results: an empty cell says "not yet run".

## Definition of done
- Gates green (ruff, pyright strict, pytest as `pw`, netns as root).
- Every number in README/PROGRESS/paper tables traces to a manifest via `verify_manifest.py`.
- PROGRESS row 20 complete with labels; KNOWN_ISSUES current.
- Commit, merge to `main`, push.

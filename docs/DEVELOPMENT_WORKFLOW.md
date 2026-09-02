# pirewall — Development Workflow (spec §47)

## Session start checklist

Every session, before writing code (this is `CLAUDE.md`'s own checklist —
repeated here as the spec §47-facing summary):

1. Read `CLAUDE.md` in full — it overrides any default behavior.
2. Read `docs/ADDENDUM.md` in full — where it conflicts with
   `docs/MASTER_SPEC.md`, the addendum wins.
3. Read `docs/PROGRESS.md` — the source of truth for what phase you're on
   and what's already done.
4. If code already exists for the area you're about to touch, inspect it
   first (spec §49) — preserve correct existing work, don't blindly
   rewrite.

## Per-subsystem loop (spec §47)

For each subsystem you touch:

1. **Inspect existing code.**
2. **Identify its contract** — what does it promise callers, what
   invariants does it maintain (bounded state, determinism, no side
   effects in the wrong layer)?
3. **Implement or fix it.**
4. **Add tests** — pick the right tier (`docs/TESTING.md`).
5. **Run tests**: `uv run pytest`.
6. **Run Ruff**: `uv run ruff check .`.
7. **Run strict type checking**: `uv run pyright`.
8. **Fix issues** — zero-tolerance: a phase isn't done with any of the
   above red (`CLAUDE.md` "Definition of done").
9. **Update documentation** — the relevant `docs/*.md` file, plus
   `docs/PROGRESS.md`'s phase row and honesty labels.
10. **Run integration tests** — confirm the subsystem's change didn't
    break a cross-module pipeline (`tests/integration/`).

## Avoid (spec §47)

- Giant files/classes — split along `docs/MASTER_SPEC.md` §35's module
  boundaries if a file is growing unwieldy.
- Circular dependencies — `core` -> `capture`/`flow`/`features` ->
  `detection` -> `engine` -> `firewall` -> `api`/`web` flows one direction
  only (`CLAUDE.md`).
- Hidden global state.
- Duplicated logic — especially feature-extraction math (one canonical
  extractor, `CLAUDE.md`) and dataset-label -> attack/benign mapping
  (`pirewall.ml.labels.is_attack_label`, shared by training-time
  evaluation and runtime scoring).
- Magic constants — every threshold lives in
  `config/default_config.toml`, loaded through `pirewall.config.models`.
- Arbitrary dictionaries crossing a module boundary — Pydantic v2 models
  for everything listed in spec §9.
- Scattered shell commands — the only subprocess call in the entire
  codebase is `NftablesBackend`'s `nft` invocation, and it's always
  `shell=False` with an argument list built from validated typed fields.

## Labeling honesty (`CLAUDE.md`, spec §46)

Every non-trivial deliverable gets one of five labels, in every phase's
`docs/PROGRESS.md` entry and in any summary of the work:

- **Implemented** — code exists and matches the spec.
- **Tested** — implemented + covered by a passing automated test.
- **Mocked** — behind a Fake implementation for testability; the real
  backend hasn't been exercised.
- **Environment-dependent** — cannot be verified outside real Pi hardware
  / a real network / real datasets; state exactly what a human needs to do
  to verify it.
- **Not yet validated** — written but not run/tested this session.

Never fabricate metrics, never claim a rule was deployed to nftables if it
wasn't, never report fake ML detection accuracy — see
`docs/ML_PIPELINE.md`'s and `scripts/diagnostics/performance_smoke.py`'s
own explicit "this is not real hardware" callouts as the pattern to follow.

## Implementation order (spec §48)

Phases build on each other in a specific order for a reason — don't
implement a later phase's scope early:

- Rule validation before adaptive enforcement (Phase 6 before Phase 6's
  own deployment step, concretely: the validation chain exists and is
  tested before `FirewallManager` ever calls `apply_rule`).
- A stable, versioned feature schema before runtime ML inference (Phase 3
  before Phase 5) — `pirewall.features.schema.SCHEMA_VERSION` is the pin
  point; Phase 5's loader refuses to run inference against a mismatched
  model rather than silently proceeding.
- Detection -> Decision -> Enforcement stay separate layers throughout —
  never collapsed into one function/module, in any phase.

## Repository/doc map

| Need to know... | Read |
|---|---|
| What pirewall does, architecture overview | `README.md`, `docs/ARCHITECTURE.md` |
| Full original spec | `docs/MASTER_SPEC.md` (frozen, verbatim) |
| Safety-oriented additions on top of the spec | `docs/ADDENDUM.md` (A1-A8, wins on conflict with `MASTER_SPEC.md`) |
| Second-wave additions (B1-B6 behavioral detection, batched anomaly scoring) | `docs/ADDENDUM_2.md` (wins on conflict with `MASTER_SPEC.md`/`ADDENDUM.md`) |
| Current phase status, honest labels, open questions | `docs/PROGRESS.md` |
| The canonical feature list | `docs/FEATURE_SCHEMA.md` |
| Dataset adapters, training, runtime inference | `docs/ML_PIPELINE.md` |
| ML training dataset/artifact provenance and honesty audit | `docs/ML_DATA_AUDIT.md` |
| Decision -> candidate -> validation -> deploy -> lifecycle | `docs/FIREWALL.md` |
| API endpoints, auth model | `docs/API.md` |
| How to run/extend tests, what's Fake vs. real | `docs/TESTING.md` |
| Coding conventions beyond `CLAUDE.md`'s non-negotiables | `docs/CODING_STANDARDS.md` |
| Hardening, threat model, resource-exhaustion protections | `docs/SECURITY.md` |
| Real-Pi deployment steps | `docs/DEPLOYMENT.md` |
| Entry-point/runtime build record (`pirewall/runtime/`, both processes run for real) | `docs/DEPLOYMENT_COMPLETE.md` |
| Dependency decisions beyond the base allowed list | `docs/ARCHITECTURE.md` |

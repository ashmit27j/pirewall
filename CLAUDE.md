# CLAUDE.md — pirewall project rules (read this every session)

This file is the persistent contract for working on **pirewall**. It applies to
every phase, every session, regardless of what the phase prompt asks for.
If anything here conflicts with a phase prompt, this file wins.

## What this project is

An AI-assisted adaptive network firewall for a Raspberry Pi 4. Full spec is in
`docs/MASTER_SPEC.md` — read the relevant numbered sections before touching a
subsystem (the phase prompt tells you which sections apply). `docs/MASTER_SPEC.md`
is frozen and stays verbatim.

**`docs/ADDENDUM.md` is a set of agreed additions on top of that spec — read
it too, every session.** Where it conflicts with `MASTER_SPEC.md`, the
addendum wins (it's newer and more specific). It covers: shadow/dry-run
enforcement mode (A1), a static allowlist that outranks adaptive rules (A2),
a rate cap on rule creation (A3), the privileged/unprivileged process split
(A4), the IPv4-only-for-v1 scope decision (A5), fail-open-by-default with a
systemd watchdog (A6), an approval queue for high-confidence BLOCK actions
(A7), and an emergency kill-switch (A8).

Current status of every phase is tracked in `docs/PROGRESS.md`.

## Session start checklist

At the start of every session, before writing code:

1. Read `docs/PROGRESS.md` to see what's already done and what phase you're on.
2. Read the phase prompt you were given (`prompts/phase-XX-*.md`).
3. Read the `docs/MASTER_SPEC.md` sections that prompt references.
4. If code already exists for this area, inspect it first (spec §49) —
   preserve correct existing work, don't blindly rewrite.

## Non-negotiable architecture rules

- **ML produces evidence, never commands.** LightGBM and Isolation Forest
  output feeds `ThreatAssessment`. Nothing in the ML layer may construct a
  firewall rule, call the firewall backend, or run a shell command
  (spec §5, §14, §22, §51).
- **Detection → Decision → Enforcement are separate layers.** Never collapse
  them into one function/module (spec §19).
- **Every candidate rule passes the full validation chain in order**: schema →
  network → safety → conflict → duplicate → priority → expiration →
  authorization. No shortcuts, no "trusted" callers that skip validation
  (spec §22, §24).
- **Safety validation is mandatory and specific**: a rule must never be able to
  lock out pirewall itself, the Admin PC, management access, the whole
  protected LAN, or the whole internet, and must never be broader than the
  evidence that generated it (spec §24).
- **Exactly one authorized code path may deploy to the firewall backend.**
  Nothing else calls into `firewall/backend/`.
- **No shell commands built from ML output or user input.** Firewall backend
  calls use structured, validated data only — never string-interpolated
  shell/nft commands (spec §20).
- **Hardware-dependent components get a Protocol/interface + a Fake test
  implementation**: `PacketCapture` (AF_PACKET + Fake) and `FirewallBackend`
  (nftables + Fake). All core logic must be testable without root, without a
  real NIC, and without touching a real nftables ruleset (spec §6, §20, §39).
- **One canonical feature-extraction module.** Training-time and runtime
  inference call the *same* extractor — never reimplement feature math twice
  (spec §11).
- **Never auto-modify network configuration.** Deployment templates are
  generated/documented, not silently applied (spec §21).
- **The allowlist (A2) outranks every adaptive rule, unconditionally.** No
  threat score, no evidence, no enforcement mode overrides it.
- **The API/control-panel process (`pirewall-api`) never imports or calls
  `FirewallBackend` or `PacketCapture` directly (A4).** It only talks to
  `pirewall-core` over the defined local socket. This must be true at the
  import-graph level — if you find yourself importing `firewall.backend` or
  `capture` into anything under `pirewall/api/` or `pirewall/web/`, stop and
  re-read A4.
- **Default enforcement mode is `SHADOW` (A1) and default failure mode is
  `fail_open` (A6).** Don't quietly change these defaults in config
  templates — they're deliberate safety choices for a first deployment.
- **v1 is IPv4-only for the adaptive pipeline (A5).** IPv6 parsing can exist;
  IPv6 flows/features/rules should not.
- **The kill-switch (A8) and rule approval (A7) both go through the normal
  `RuleStatus` lifecycle in `firewall/manager.py` — never a special-cased
  code path that bypasses validation or authorization.**

## Type safety rules

- Python 3.12+, full annotations on every function signature and class
  attribute.
- Pydantic v2 models for everything that crosses a boundary (config, API,
  domain objects listed in spec §9). No raw untyped dicts flowing through
  core code.
- `Any` requires an inline comment explaining why it's unavoidable.
- Enums/`Literal` for anything with a finite set of values (actions, threat
  levels, rule status, event types, protocols).
- Type checker: **pyright in strict mode** (`pyright --strict`), configured in
  `pyproject.toml`. Run it before considering any phase done.

## Coding hygiene

- No file should try to do more than one subsystem's job. If a file is
  getting large, split it along the module boundaries in `docs/MASTER_SPEC.md`
  §35.
- No magic numbers for thresholds — they live in `config/default_config.toml`
  and are loaded through the config models (spec §18, §37).
- No circular imports between `core` → `capture`/`flow`/`features` →
  `detection` → `engine` → `firewall` → `api`/`web`. Dependencies flow one
  direction; `core.models` has no dependents that flow backward.

## Dependencies

Only add: Python 3.12+, `uv`, Pydantic v2, FastAPI, Pytest, Ruff, pyright,
LightGBM, scikit-learn, and stdlib. Anything else — ask first, and say why in
`docs/ARCHITECTURE.md`.

## Labeling honesty (spec §46)

Never claim something works if it hasn't been run and verified. Every
non-trivial deliverable gets one of these labels in your summary and in
`docs/PROGRESS.md`:

- **Implemented** — code exists and matches the spec.
- **Tested** — implemented + covered by a passing automated test.
- **Mocked** — behind a Fake implementation for testability; the real backend
  (AF_PACKET, nftables, actual Pi hardware) has not been exercised.
- **Environment-dependent** — cannot be verified outside real Pi hardware /
  real network / real datasets; describe exactly what a human needs to do to
  verify it.
- **Not yet validated** — written but not run/tested this session.

Never fabricate metrics, never claim a rule was deployed to nftables if it
wasn't, never report fake ML scores.

## Definition of done for a phase

A phase is not done until:

1. `ruff check .` is clean.
2. `pyright --strict` is clean (or has zero *new* errors if the phase
   explicitly says pre-existing errors are out of scope).
3. `pytest` passes, including new tests for everything in that phase's scope.
4. `docs/PROGRESS.md` is updated: phase marked complete, each acceptance-item
   labeled per the honesty rules above, any deviations from the phase prompt
   explained.
5. Any new public module/class/function has a docstring explaining its
   contract.
6. You have **not** implemented anything from a later phase's scope (see
   spec §48 — implementation order matters, especially: rule validation
   before adaptive enforcement, stable feature schema before runtime
   inference).

## Do not

- Do not implement adaptive rule deployment before rule validation exists.
- Do not implement runtime ML inference before the feature schema is frozen
  and versioned.
- Do not fabricate metrics, mock a firewall deploy and report it as real, or
  silently skip the honesty labels.
- Do not modify the host's real network configuration, systemd state, or
  nftables ruleset during a Claude Code session unless the phase prompt
  explicitly says this is a real-hardware deployment step and you've
  confirmed that with the user first.
- Do not commit secrets, private keys, certificates, or raw dataset files.
- Do not add a dependency, database, message broker, or frontend framework
  not listed above without asking.

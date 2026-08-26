# pirewall — Claude Code prompt kit

This folder is everything you need to build **pirewall** with Claude Code as
9 sequential, checkable phases instead of one giant unbounded prompt.

## What's in here

```
CLAUDE.md                          ← put this in your repo ROOT (auto-read by Claude Code every session)
docs/
  MASTER_SPEC.md                   ← your full original spec, verbatim — put in repo docs/
  ADDENDUM.md                      ← 8 agreed additions on top of the spec — put in repo docs/
  PROGRESS.md                      ← phase + addendum checklist — put in repo docs/, Claude Code updates it
prompts/
  phase-01-foundation.md           ← paste the CONTENTS of each into Claude Code, one per session
  phase-02-capture-parsing.md
  phase-03-flow-features.md
  phase-04-dataset-ml-training.md
  phase-05-inference-behavior-threat.md
  phase-06-firewall-decision-rules-backend.md
  phase-07-api-auth-events-controlpanel.md
  phase-08-hardening-deployment-integration.md
  phase-09-testing-docs-validation.md
```

## How to actually run this

1. Create your empty repo, e.g. `mkdir pirewall && cd pirewall && git init`.
2. Copy `CLAUDE.md` into the repo root.
3. Copy `docs/MASTER_SPEC.md`, `docs/ADDENDUM.md`, and `docs/PROGRESS.md`
   into `docs/` in the repo (the `docs/` folder itself gets created properly
   by Phase 1 — it's fine if these files exist before that).
4. Open Claude Code in that repo directory.
5. For each phase, in order: paste the **contents** of the corresponding
   `prompts/phase-0N-*.md` file as your message to Claude Code. Let it finish
   (it will run tests/lint/type-check itself per `CLAUDE.md`'s definition of
   done). Review the diff. Commit.
6. Before starting a new phase, skim `docs/PROGRESS.md` — Claude Code should
   have updated it. If a phase reports something as "Not yet validated" or
   lists an open question, resolve that before moving on if it blocks the
   next phase.
7. Repeat through phase 9.

You do not need to re-paste `docs/MASTER_SPEC.md` or `CLAUDE.md` every time —
Claude Code reads `CLAUDE.md` automatically each session, and each phase
prompt tells it exactly which sections of `MASTER_SPEC.md` to (re)read.

## Why phases instead of one mega-prompt

- Each phase has a narrow, checkable "definition of done" — you can actually
  verify Phase 3 is solid before Phase 4 builds on it.
- `docs/MASTER_SPEC.md` §48 has a hard ordering constraint (don't build
  adaptive rule deployment before rule validation exists, don't build runtime
  inference before the feature schema is frozen) — the phase split enforces
  this instead of relying on the model to self-sequence a 51-section spec.
- `CLAUDE.md` carries the non-negotiable architecture/safety rules
  (ML-never-touches-firewall, full validation chain, no fabricated metrics)
  as a persistent contract, so they don't get diluted or forgotten by phase
  7 the way they might in one huge prompt.
- `docs/PROGRESS.md` gives you an honest, running record instead of taking
  Claude Code's word for it that everything upstream still works.

## What the addendum changes about the architecture

`docs/ADDENDUM.md` adds eight things on top of the original spec — most
importantly:

- **Two processes, not one.** `pirewall-core` (capture/flow/ML/detection/
  firewall) and `pirewall-api` (FastAPI + control panel) are separate
  systemd services talking over a local Unix socket. `pirewall-api` never
  gets firewall or raw-capture capabilities, even if it's compromised.
- **Three enforcement modes**, not just "on": `SHADOW` (log what would
  happen, deploy nothing — the recommended starting point), `ASSISTED`
  (auto-deploy MONITOR/RATE_LIMIT, hold high-confidence BLOCKs for your
  approval), `ACTIVE` (full auto-enforcement, the original spec's behavior).
- **A kill-switch** and a **static allowlist** that outrank the adaptive
  system entirely.
- **IPv4-only for v1** — an explicit scope cut, not an oversight.
- **Fail-open by default** if the core process crashes, with a systemd
  watchdog to detect and report crash-loops rather than silently degrading.

Every phase prompt tells you exactly which addendum items apply and where.

## Things you'll need to supply yourself along the way

- **Phase 4** needs real CICIDS2017 and UNSW-NB15 dataset files on your dev
  machine. The prompt tells Claude Code to fail clearly (not fabricate
  results) if they're missing — go download them before that session and
  point the config at their path.
- **Phase 1's `config/default_config.toml`** ships with placeholder values
  (`"eth0"`, `"CHANGE_ME"`, etc.) — you'll fill in your real WAN/LAN
  interface names, protected LAN CIDR, upstream gateway, and Admin PC IP
  once you know your actual network layout. Don't let Claude Code guess
  real values for these.
- **Phase 8 and real hardware**: everything from Phase 8 onward produces
  *templates and documentation* for deploying to a real Pi — it deliberately
  does not touch your actual network config, systemd, or nftables state.
  You (or a follow-up, explicitly-scoped session) apply those by hand on the
  real Raspberry Pi.
- **Phase 9's final checklist** in `docs/PROGRESS.md` will end up with some
  items honestly marked "Environment-dependent" — that's expected. It's your
  punch list for what to verify on real hardware before calling this
  production-ready.

## If you want to adjust the phase split later

The phase boundaries follow `docs/MASTER_SPEC.md` §48's implementation
order, grouped into 9 chunks. If you want more granularity on any phase
(e.g. splitting Phase 6 into "decision + generation" and "validation +
backend" separately, since it's the highest-risk phase), just split that one
markdown file into two and adjust the "confirm phase N complete" line in the
next file accordingly — the rest of the kit doesn't need to change.

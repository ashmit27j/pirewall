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

**`docs/ADDENDUM_2.md` is a second-wave set of additions on top of both —
read it too, every session.** Where it conflicts with `MASTER_SPEC.md` or
`docs/ADDENDUM.md`, `ADDENDUM_2.md` wins (it's the newest and most
specific). It covers: decoupling fast/volumetric behavioral detection from
flow completion (B1), a slow-rate aggregate DoS signal (B2), an
evidence-maturity gate that caps BLOCK/RATE_LIMIT without mature evidence
(B3), a Heartbleed record-length detector (B4), TLS ClientHello (JA3)
fingerprinting for known attack tooling (B5), and the batched-anomaly-
scoring follow-up pass (a dedicated `pirewall-anomaly-inference` thread and
its own bounded queue).

**`docs/ADDENDUM_3.md` is a third-wave set of additions on top of all
three — read it too, every session.** Where it conflicts with any earlier
document, `ADDENDUM_3.md` wins (it is the newest and most specific). It
covers: the LAN captive portal as a third process behind a second,
restricted RPC socket (C1), portal sessions as kernel-expiring nftables set
elements rather than rules (C2), the LAN user store and its single writer
(C3), the channel that tells a blocked client why (C4), the portal's
plaintext-HTTP limitation (C5), and loopback-only local console access to
the control panel (C6).

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
- **The same rule applies to `pirewall/portal/`, for a stronger reason
  (C1)** — that process is the one untrusted LAN clients talk to. Core-side
  portal logic that needs `FirewallManager` lives in
  `pirewall/ipc/portal_service.py`, outside that tree, so the rule can hold.
- **`pirewall-portal` reaches only the portal RPC socket, never
  `core.sock` (C1).** It is a member of `pirewall-portal-ipc` and never of
  `pirewall-ipc`. `PortalRpcDispatcher` is a separate class with its own
  handler table — never a filtered view over `CoreRpcDispatcher`, which
  would be one missing branch away from handing the kill switch to the
  most exposed process on the box.
- **A portal session is an nft set element, not a `FirewallRule` (C2).** It
  never enters the `RuleStatus` lifecycle and never consumes the A3 rate
  cap — but it still goes through `FirewallManager`, which remains the only
  holder of a backend reference.
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

## v2 (phases 11–20)

### Precedence and reading checklist

**`docs/ADDENDUM_4.md` is the v2 rulebook (D1–D9) and wins over every
earlier document**: `MASTER_SPEC.md`, `ADDENDUM.md`, `ADDENDUM_2.md`,
`ADDENDUM_3.md`, and this file's v1 rules above, wherever they conflict.
**`docs/V2_CONTRACTS.md`** freezes the exact types, nft names, RPC
signatures and **file ownership** that ADDENDUM_4 relies on. Behind them,
`docs/v2/PLAN_v3.md` is the authoritative design, and `docs/v2/PLAN_FINAL.md`
fills in what PLAN_v3 leaves unchanged.

For any v2 phase, in addition to the session checklist above:

1. Read `docs/ADDENDUM_4.md` and `docs/V2_CONTRACTS.md` in full.
2. Check the ownership table in `docs/V2_CONTRACTS.md` §12. Edit only the
   files your phase owns. `pirewall/runtime/core.py`,
   `pirewall/firewall/manager.py` and `pirewall/ipc/dispatcher.py` belong to
   the integrator phase named there and to no other.
3. Import the contract types (`pirewall/core/nft_names.py`,
   `pirewall/core/models/{identity,evidence_v2,policy}.py`,
   `pirewall/core/binding_table.py`, `pirewall/ipc/protocol_v2.py`). Never
   redefine them or spell an nft name inline. You may *add* to a contract,
   with its doc and pinning test in the same commit. Changing or removing
   one is the human's call: stop and ask.
4. Treat files named in a prompt that do not exist yet (later phases'
   prompts, `docs/v2/RUNBOOK_PI.md`, `lab/` outputs) as not yet written.
   Skip those steps and list them in the summary; never invent their
   contents.

### v2 invariants (non-negotiable, in addition to the rules above)

- **Two kernel tables (D1).** `inet pirewall_static` (+ `arp
  pirewall_static_arp`) is template-only reviewed policy, loaded by
  `pirewall-start`. `inet pirewall_adaptive`'s enforcement sets are written
  **only by `FirewallManager`**, after the full validator chain, as elements
  with a timeout ≤ 3600 s, never as rules. Every set has exactly one writer.
  Reloads flush chains and never delete a table.
- **The single static-table write (D1).** The only runtime change core may
  make to `pirewall_static`'s ruleset is replacing a `guard_verdict_*`
  chain's contents (`drop` or empty), through
  `FirewallManager.set_guard_mode`, in one atomic batch. The only other
  change is panic. A ruleset-diff test enforces this.
- **Guards are static policy (D2).** Their modes are separate from
  `enforcement_mode`. The defaults are input enforce, raw enforce-if-seeded
  and forward observe; don't quietly change them, any more than the A1/A6
  defaults. The kill switch sets SHADOW **and** every guard to observe.
  Fail-open shutdown flushes the adaptive sets only.
- **ML ⇒ at most MONITOR (D4).** Under `pipeline.engine = "v2"`, a policy
  table picks the action and scores are for explanation and the UI only.
  Evidence that is ML-only or anomaly-only (Isolation Forest and/or
  LightGBM) can never cause more than MONITOR. Neither can an observe-mode
  guard's offender. Only D1 and enforce-mode kernel evidence may act.
- **MAC identity (D3).** Device identity is `RuleTarget{ip, mac | None}`.
  MACs are normalised `UnicastMacAddress` values, and multicast, broadcast
  or all-zero MACs never identify a device. Bindings come only from the
  lease file and `[[antispoof.static]]`, written through
  `FirewallManager.sync_bindings`, deleting the old pair before adding the
  new one. Lease hostnames and client-ids are never parsed or logged. MAC is
  never a model feature.
- **Env tags (D7).** Every measurement artifact carries exactly one tag:
  `pi-live`, `pi-scripted`, `sandbox` or `mock`. Aggregation never mixes
  tags, and `lab.env_tag` never defaults to a `pi-*` tag.
- **v1 stays runnable.** `pipeline.engine = "v1"` is the evaluation
  baseline, and the v1 test suite stays green throughout.

### v2 dependency additions

Approved as part of the v2 plan. Each is recorded here with its reason;
nothing else is added without asking.

- **`python3-nftables`** (Debian package). The uv 3.12 venv reaches it
  through a `.pth` file, installed by phase 16's
  `scripts/deployment/install_nftables_pth.sh`. It is ctypes over the
  system `libnftables`, so it works from the venv. Set updates take a median
  of about 0.36 ms, against about 10 ms through an `nft` subprocess
  (`docs/v2/v2/RESULTS.md`; sandbox numbers, not Pi numbers). The
  `nft -j -f -` subprocess stays as the batched fallback, and preflight
  reports which transport is in use. Structured JSON commands only, never
  string-built nft commands (spec §20).
- **`scapy`**, as a **dev/lab-only** extra, for the mock pcap generator and
  lab traffic. It is never imported by anything under `pirewall/`, and never
  installed on the Pi's runtime path.
- **The existing Rust `native/` extension** (PyO3, TPACKET_V3). v2 makes it
  the only flow and feature producer for both live capture and training
  (pcap replay through `FlowEngine.feed`), hardened per ADDENDUM_4 D6.

### v2 honesty rule

**`mock` and `sandbox` numbers are never Pi results.** The netns testbed,
any x86 or WSL/Docker run, and synthetic pcaps are regression evidence.
Label them with their env tag wherever they appear, and never report them
as, average them with, or substitute them for Pi measurements. Only `pi-*`
tagged numbers, from the real Pi, may fill a Pi result in `docs/PROGRESS.md`,
the README or the paper. A v2 deliverable that has not run on the Pi is
**Environment-dependent**, whatever the sandbox showed.

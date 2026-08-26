# Phase 9 — Security/integration testing, documentation & final validation

Read `CLAUDE.md` and `docs/MASTER_SPEC.md` sections 39, 40, 41, 46, 47, 50
before starting, and re-read `docs/ADDENDUM.md` in full — this phase's
reconciliation must cover the addendum items (A1–A8), not just spec §50's
original acceptance criteria. Confirm Phase 8 is marked complete in
`docs/PROGRESS.md`.
This is the closing phase — its job is to fill gaps and reconcile against
the spec honestly, not to add new subsystems.

## Goal

Close out remaining test coverage, produce complete documentation, run a
performance smoke pass using the Fake implementations, and do a full,
honest reconciliation of the entire project against spec §50's acceptance
criteria in `docs/PROGRESS.md`.

## Deliverables

1. **Security tests (`tests/security/`)** — fill any gaps not already
   covered in earlier phases: malformed/truncated packets (if not already
   exhaustive from Phase 2), invalid configuration (Phase 1), certificate
   failures (Phase 7), rule injection and command injection attempts (Phase
   6), overly broad / duplicate / conflicting rules (Phase 6), Admin PC
   lockout prevention (Phase 6/7), firewall backend failure handling
   (`FakeFirewallBackend` configured to raise/fail and confirming pirewall
   degrades safely rather than crashing or deploying unsafely), and resource
   exhaustion (flow-table flood, event-queue flood, excessive rule-creation
   attempts, API abuse) using `FakePacketCapture` and fixture-driven load —
   assert bounded memory/state throughout, not just "it didn't crash."

2. **Integration tests (`tests/integration/`)** — the two full pipelines
   from spec §39, end-to-end, using Fake implementations throughout:
   - `Packet → Flow → FeatureVector → ML Evidence → Behavior →
     ThreatAssessment → FirewallDecision`
   - `ThreatAssessment → CandidateRule → Validation → FirewallBackend`
   Use realistic scripted traffic (e.g. a simulated port scan, a simulated
   SYN flood, and a clearly benign session) and assert the pipeline produces
   sensible decisions end to end.

3. **Performance smoke pass (`tests/system/` or a `scripts/diagnostics/`
   script)** — measure packet throughput, flow latency, feature-extraction
   latency, inference latency, threat-assessment latency, and rule-
   deployment latency using `FakePacketCapture`/`FakeFirewallBackend` at a
   meaningfully high synthetic rate. Report the numbers; do not claim these
   represent real Raspberry Pi hardware performance — label them as
   dev-machine/Fake-backend numbers only (spec §40, §46).

4. **Documentation** — complete the remaining files from spec §35's `docs/`
   list that earlier phases didn't already produce in full:
   `docs/ARCHITECTURE.md` (the pipeline diagram from spec §51 plus a
   description of each module boundary), `docs/FEATURE_SCHEMA.md` (Phase 3's
   schema, documented feature-by-feature), `docs/ML_PIPELINE.md` (Phase 4/5,
   including how to (re)train and how runtime schema-compatibility checking
   works), `docs/FIREWALL.md` (Phase 6's decision→candidate→validation→
   deploy→lifecycle flow), `docs/API.md` (Phase 7's endpoints, auth model),
   `docs/TESTING.md` (how to run each test tier, what's covered by Fakes vs.
   what needs real hardware), `docs/DEVELOPMENT_WORKFLOW.md` (spec §47's
   loop). Update root `README.md` to be a real project overview (what it
   does, architecture summary, how to run tests, pointer to
   `docs/DEPLOYMENT.md` for real deployment).

5. **Final acceptance reconciliation** — go through every bullet in spec §50
   **and every item in `docs/ADDENDUM.md`'s Addendum items table** and fill
   in `docs/PROGRESS.md`'s checklists with an honest label (Implemented /
   Tested / Mocked / Environment-dependent / Not yet validated) and a
   one-line note per item. Do not mark anything Implemented/Tested that
   isn't backed by actual passing code/tests in the repo. List every
   "Environment-dependent" item's exact remaining human step in the "Open
   questions for the human" section — this should explicitly include: real
   hardware verification of the fail-open crash behavior (A6), real
   multi-week observation in SHADOW mode before recommending ACTIVE (A1),
   and confirming socket permissions actually restrict access on the real
   Pi filesystem (A4).

## Explicit non-goals for this phase

Do not add new subsystems or features not already scoped in Phases 1–8. If
you find a real gap that requires new subsystem work (not just tests/docs),
stop and report it in `docs/PROGRESS.md` → "Open questions for the human"
rather than improvising new architecture here.

## Definition of done

Full test suite green (`pytest`), `ruff check .` clean, `pyright --strict`
clean, all documentation files present and accurate to what's actually in
the repo, `docs/PROGRESS.md` acceptance checklist fully reconciled with
honest labels and no blank items, and a clear, itemized list of what a human
still needs to do on real Pi hardware to go from "code complete" to
"deployed and validated."

# Phase 6 — Firewall decision engine, candidate rules, validation & nftables backend

This is the most security-critical phase in the project. Read `CLAUDE.md`
(especially the architecture rules and the safety-validation rule) and
`docs/MASTER_SPEC.md` sections 19, 20, 22, 23, 24, 25 before starting. Then
read **all of `docs/ADDENDUM.md`** — items A1, A2, A3, A5, A7, A8 all land in
this phase and change the validator chain and the rule lifecycle from what
the base spec describes. Confirm Phase 5 is marked complete in
`docs/PROGRESS.md`.

## Goal

Turn a `ThreatAssessment` into an explicit `FirewallDecision`, generate a
`CandidateRule`, run it through the **full** validation chain, and only then
allow deployment to nftables — with a complete audit trail at every step.

## Deliverables

1. **`pirewall/engine/decision.py`** — `ThreatAssessment → FirewallDecision`.
   Actions: `ALLOW`, `MONITOR`, `RATE_LIMIT`, `BLOCK` — only implement actions
   the backend in this phase actually supports; don't stub actions with no
   real effect. `FirewallDecision` (Phase 1's model) carries: action, threat
   score, threat level, reason, evidence, timestamp, flow ID where
   applicable.

2. **`pirewall/firewall/generator.py`** — `FirewallDecision → CandidateRule`
   (Phase 1's model, fields per spec §23: id, action, direction, source,
   destination, protocol, source_port, destination_port, priority,
   created_at, expires_at, reason, threat_score, evidence, status,
   metadata). Generated rules must be as narrow as the evidence supports —
   never wider than necessary.

3. **`pirewall/firewall/validator.py`** — implements the **full chain in
   order** (updated per `docs/ADDENDUM.md`), each stage a separate
   function/method so it's independently testable:
   - **Schema**: all `CandidateRule` fields valid (leans on Pydantic from
     Phase 1, plus any cross-field checks).
   - **Network**: valid IPs/CIDRs/ports/protocols/direction. Also reject any
     candidate rule targeting an IPv6 address/CIDR (addendum A5 — v1
     generates IPv4 rules only; this is a belt-and-suspenders check even
     though the generator shouldn't produce one).
   - **Allowlist** *(addendum A2 — new stage, runs before safety)*: hard
     reject any `BLOCK`/`RATE_LIMIT` candidate whose target matches an
     `AllowlistEntry`. This outranks everything, including threat score.
   - **Safety**: reject/narrow any rule that would block pirewall itself, the
     configured Admin PC IP, configured management access, the entire
     protected LAN CIDR, or the entire internet (`0.0.0.0/0` / `::/0` as a
     BLOCK target), and reject any rule broader than the evidence that
     produced it (e.g. blocking a /8 in response to a single-flow anomaly).
   - **Conflict detection**: check against existing active rules.
   - **Duplicate detection**: don't approve an equivalent rule that's already
     active.
   - **Rate cap** *(addendum A3 — new stage)*: track adaptive-rule creation
     count in a bounded, config-driven sliding/fixed window
     (`firewall.max_adaptive_rules_per_window`,
     `firewall.rate_window_seconds`). Once the window's budget is spent,
     reject new candidates with reason `rate_limited` — but do **not**
     suppress the underlying `SecurityEvent`/`ThreatAssessment` visibility;
     detection stays fully logged even when rule creation is capped.
   - **Priority/shadowing**: detect a new rule being fully shadowed by an
     existing higher-priority rule.
   - **Expiration**: temporary/adaptive rules must have `expires_at` set;
     reject ones that don't when they're supposed to.
   - **Authorization**: only the designated caller (the rule manager below)
     may invoke deployment — validator + backend should not be reachable from
     arbitrary code paths.
   A rejected rule is recorded (not silently dropped) with the specific
   reason it failed.

4. **`pirewall/firewall/interface.py`** — `FirewallBackend` `Protocol`:
   apply rule, remove rule, list active rules, health check. No shell-command
   construction in this file — contract only.

5. **`pirewall/firewall/backend/nftables.py`** — real implementation.
   Structured, validated `FirewallRule` objects map to nftables operations
   through a small, centralized translation layer — no string-interpolated
   shell commands built from rule fields directly; use parameterized
   calls/subprocess argument lists, never `shell=True` with interpolated
   rule data.

6. **`FakeFirewallBackend`** — test double implementing the same `Protocol`
   in-memory, so the full CANDIDATE→...→ACTIVE lifecycle is testable without
   root or a real nftables ruleset.

7. **`pirewall/firewall/manager.py`** — the single authorized orchestrator:
   drives the **updated** lifecycle from `docs/ADDENDUM.md` — not just
   `CANDIDATE → VALIDATING → REJECTED/APPROVED → DEPLOYED → ACTIVE →
   EXPIRED/DISABLED/REMOVED`, but also:
   - `EnforcementMode.SHADOW` (addendum A1): an otherwise-approved candidate
     transitions to `RuleStatus.SHADOWED` (terminal) instead of deploying,
     and a `SecurityEvent` records what *would* have happened.
   - `EnforcementMode.ASSISTED` (addendum A7): a `BLOCK` candidate at/above
     `firewall.assisted_review_threshold` transitions to
     `RuleStatus.PENDING_APPROVAL` instead of auto-deploying; a human
     approval (via the API in Phase 7) moves it to `APPROVED → DEPLOYED`
     through the *same* path as everything else, a rejection moves it to
     `REJECTED`. Everything else (MONITOR/RATE_LIMIT, below-threshold BLOCK)
     auto-deploys as normal even in `ASSISTED` mode.
   - `revert_to_base()` (addendum A8, the kill-switch): sets
     `EnforcementMode` to `SHADOW` and transitions every currently-`ACTIVE`
     adaptive rule to `REMOVED` via the normal lifecycle transition (not a
     special-cased shortcut), leaving the static base ruleset and the
     allowlist untouched, and records one summary `SecurityEvent` plus a
     per-rule audit entry. This method — not a new bypass path — is what
     Phase 7's kill-switch endpoint calls.
   Records every transition. Is the *only* module that calls into
   `firewall/backend/`. Enforce this at the code level (e.g. backend
   instances are private to the manager, not importable/callable from
   elsewhere in a way that bypasses validation).

## Explicit non-goals for this phase

No API, no control panel, no Wazuh/Netdata. This phase ends at "rule is
ACTIVE (or REJECTED) in the Fake/real backend, with an audit trail."

## Tests (`tests/unit/`, `tests/integration/`, `tests/security/` — this phase
needs real security tests, not just unit tests)

- Each validation stage rejects the specific bad input it's meant to catch
  (invalid IP, invalid CIDR, invalid port, missing expiration on a temporary
  rule).
- **Safety validation**, explicitly: a candidate rule targeting the
  configured Admin PC IP is rejected; a candidate rule targeting pirewall's
  own management interface/IP is rejected; a candidate rule that would BLOCK
  the entire protected LAN CIDR is rejected; a candidate rule that would
  BLOCK `0.0.0.0/0`/`::/0` is rejected; a rule broader than its evidence
  (e.g. a /8 block from single-flow evidence) is rejected or narrowed.
- Duplicate and conflicting rules are correctly detected against a
  pre-populated `FakeFirewallBackend` state.
- Attempted "injection" style candidate rules (garbage/oversized strings in
  fields that end up passed toward `nftables.py`) are rejected at schema/
  network validation, and separately, confirm `nftables.py` never constructs
  a shell string from raw field values (code-level check + a test asserting
  subprocess calls use argument lists, not shell strings).
- Full end-to-end lifecycle test using `FakeFirewallBackend`:
  ThreatAssessment → Decision → CandidateRule → validation → ACTIVE, and a
  second case ending in REJECTED, both with correct recorded history.
- An attempt to call `firewall/backend/` bypassing `manager.py` is either
  impossible by construction or explicitly tested as rejected.
- **Addendum tests:**
  - `SHADOW` mode: an otherwise-valid `BLOCK` candidate ends in `SHADOWED`,
    never reaches `FakeFirewallBackend`, and produces the expected
    would-have-blocked event.
  - `ASSISTED` mode: a high-score `BLOCK` candidate stops at
    `PENDING_APPROVAL`; approving it deploys through the normal path;
    rejecting it ends in `REJECTED`; a low-score `BLOCK` and any
    `MONITOR`/`RATE_LIMIT` candidate still auto-deploy in this mode.
  - Allowlist: a candidate targeting an `AllowlistEntry` is rejected even
    with a `CRITICAL` threat score.
  - Rate cap: candidates beyond the configured window budget are rejected
    with reason `rate_limited`, while `SecurityEvent`/`ThreatAssessment`
    generation for those same flows is unaffected.
  - IPv4-only: a candidate rule with an IPv6 target/CIDR is rejected at
    network validation.
  - Kill-switch: populate several `ACTIVE` rules (and one allowlist entry
    and one static-base assumption) via `FakeFirewallBackend`, call
    `revert_to_base()`, assert all adaptive rules are `REMOVED`, allowlist
    is untouched, and `EnforcementMode` is now `SHADOW`.

## Definition of done

Everything in `CLAUDE.md` → "Definition of done for a phase". Update
`docs/PROGRESS.md` row for Phase 6. Label `nftables.py` against a real
ruleset as **Environment-dependent**; the lifecycle/validation logic via
`FakeFirewallBackend` should be **Tested**.

# pirewall — ADDENDUM (v1 additions beyond MASTER_SPEC.md)

`docs/MASTER_SPEC.md` is frozen and stays verbatim. This file is a delta on
top of it, agreed after the original spec was written. Where anything here
conflicts with `MASTER_SPEC.md`, **this file wins** — it's more recent and
more specific. Every phase prompt tells you when to read this file.

Each item below: what it is, why it exists, which phase(s) implement it,
and exactly what it changes in the original spec's models/flows.

---

## A1. Shadow / dry-run mode for adaptive enforcement

**What:** A config-driven `EnforcementMode` enum: `SHADOW`, `ASSISTED`,
`ACTIVE`.

- `SHADOW` — the full pipeline runs (decision → candidate rule → all
  validation stages) but the approved result is never sent to
  `FirewallBackend`. Instead it's recorded with `RuleStatus.SHADOWED` and a
  `SecurityEvent` so you can see exactly what pirewall *would* have blocked.
- `ASSISTED` — `MONITOR` and `RATE_LIMIT` actions auto-deploy as normal;
  `BLOCK` actions above a configurable threat-score threshold go to
  `RuleStatus.PENDING_APPROVAL` instead of auto-deploying (see **A7**).
- `ACTIVE` — full automatic enforcement, exactly as the original spec
  describes.

**Default:** `SHADOW`, for a first deployment. Recommended path: run in
`SHADOW` for 1–2 weeks against real traffic, review the shadow log, move to
`ASSISTED`, then `ACTIVE` once you trust it.

**Why:** flow-only detection (no payload inspection) has real false-positive
risk on real home traffic — §34 already admits this. This lets you observe
before you can get locked out of your own network.

**Touches:** Phase 1 (config field + `RuleStatus.SHADOWED`), Phase 6
(manager branches on mode), Phase 7 (control panel shows the shadow log),
Phase 9 (mode-specific tests).

---

## A2. Static admin-defined allowlist

**What:** A new `AllowlistEntry` domain model (target IP/CIDR, optional
port/protocol, reason, created_at, created_by) that adaptive rules can
**never** target with `BLOCK`/`RATE_LIMIT`, regardless of threat score. This
is distinct from the existing §24 "safety" validation stage — safety
validation catches *accidental* self/Admin-PC/LAN/internet lockout; the
allowlist is *deliberate* user-declared exceptions ("never touch my phone,
192.168.1.50").

**Validator ordering change:** the chain in §24 becomes:

```
schema → network → allowlist → safety → conflict → duplicate
       → rate-cap (A3) → priority → expiration → authorization
```

Allowlist check is a hard reject, same severity as safety.

**Storage:** same lightweight store the rules already use — no new database
(keeps spec §3's "no unnecessary database" intact).

**API/UI:** admin-only, authenticated, Admin-PC-restricted like everything
else in §29. `GET/POST/DELETE /api/v1/allowlist`.

**Touches:** Phase 1 (model + seed config), Phase 6 (validator stage +
storage), Phase 7 (API + control panel section).

---

## A3. Rate cap on adaptive rule creation

**What:** `firewall.max_adaptive_rules_per_window` +
`firewall.rate_window_seconds` in config. A new validator stage rejects new
candidate rules once the current window's budget is spent, emitting a
`RULE_REJECTED` event with reason `rate_limited`. This does **not** silence
detection — `ThreatAssessment`/`SecurityEvent` generation keeps happening at
full fidelity even while rule *creation* is capped, so a real coordinated
attack that's tripping the cap stays fully visible in events/logs, it just
can't spawn unbounded rules.

**Touches:** Phase 6 (validator stage + bounded counter state), Phase 8
(new Netdata metric: rule-creation rate), Phase 9 (extends the resource-
exhaustion security tests).

---

## A4. Privileged / unprivileged process split

**What:** Two systemd services instead of one:

- **`pirewall-core.service`** — capture, flow, features, detection, engine,
  firewall manager + backend. Dedicated non-root user, minimal capabilities
  (packet capture + nftables ops only).
- **`pirewall-api.service`** — FastAPI + control panel. A *different*,
  more restricted non-root user. **No raw-socket or firewall capabilities at
  all** — not restricted-by-systemd-flag, actually absent.

**Comms:** `pirewall-core` exposes a local-only Unix domain socket
(filesystem-permissioned to just these two service users) that
`pirewall-api` uses to read state (flows/detections/threats/rules/events)
and submit only the already-authorized actions: disable/remove rule,
approve/reject pending `BLOCK` (A7), allowlist changes (A2), kill-switch
(A8). The API process never imports or calls `FirewallBackend` or
`PacketCapture` — this must be true at the code/dependency level, not just
by convention.

**Why:** this is what makes spec §45's "a compromised control panel must not
automatically provide unrestricted root access" concretely true, instead of
relying on systemd hardening flags on a single shared process.

**Touches:** Phase 7 (define the socket protocol + client/server halves —
this replaces "API calls into `firewall/manager.py` directly" with "API
calls the socket, which is served by a thin RPC layer inside
`pirewall-core` that itself calls `firewall/manager.py`"), Phase 8 (two
systemd units, socket file permissions).

---

## A5. IPv6 scope decision: IPv4-only for v1

**Decision:** v1 targets **IPv4 only** for flows, features, ML, threat
scoring, and firewall rule generation. IPv6 packet *parsing* is still
implemented at the parser level (spec §7 lists it and it's cheap), and
IPv6 traffic is still counted in capture statistics — but IPv6 flows are
never fed into feature extraction/ML/adaptive rule generation in v1. No
`CandidateRule` may target an IPv6 address/CIDR in v1.

**Why:** avoids silently under-testing a "supported" dual-stack feature;
cuts real scope for a first working version. Document this prominently
(control panel + `docs/ARCHITECTURE.md`) so it isn't mistaken for full
coverage. Revisit as v2 scope.

**Touches:** Phase 2 (parser still handles IPv6, `PacketMetadata` carries
address family), Phase 3 (flow/feature schema documented as IPv4-scope;
IPv6 packets are parsed but not aggregated into adaptive-pipeline flows),
Phase 6 (validator hard-rejects any IPv6 target in a candidate rule as a
belt-and-suspenders check even though generation shouldn't produce one).

---

## A6. Fail-open vs. fail-closed on crash, with a watchdog

**Decision:** default is **fail-open**. If `pirewall-core` crashes (not a
graceful shutdown — an actual crash/restart loop), IP forwarding and the
static, deny-by-default `deploy/firewall/` base ruleset stay exactly as
configured; normal internet access for the household is **not** silently
cut. This is explicit and changeable: `failure.mode = "fail_open" |
"fail_closed"` in config, defaulting to `fail_open` for home use.

**Watchdog:** `pirewall-core.service` uses `Type=notify` + `WatchdogSec=`;
the process sends `sd_notify` heartbeats; a missed heartbeat triggers a
systemd restart. A crash-loop (N restarts within M seconds, both
configurable) raises a `SYSTEM_WARNING`-severity `SecurityEvent` forwarded
to Wazuh. Because of **A4**, `pirewall-api.service` is a separate process
and stays up independently, so the control panel can still show "core is
down" even when core itself is crash-looping.

**Touches:** Phase 1 (config field), Phase 8 (watchdog directives on the
split units from A4), Phase 9 (test crash-loop *detection logic* against a
Fake — don't actually crash a real process in tests).

---

## A7. Assisted mode: approval queue for BLOCK

**What:** Part of `EnforcementMode.ASSISTED` (A1). Candidate `BLOCK` rules
whose threat score is at/above `firewall.assisted_review_threshold`, after
passing every other validation stage, go to `RuleStatus.PENDING_APPROVAL`
instead of auto-deploying. Visible in the control panel's Firewall section
with one-click Approve/Reject. Approving deploys through the *same* manager
path as everything else (still fully authorized/audited) — never a
shortcut. Rejecting records the decision, does not deploy. `MONITOR`/
`RATE_LIMIT` and below-threshold `BLOCK`s still auto-deploy even in
`ASSISTED` mode.

**API:** `POST /api/v1/rules/{id}/approve` (new, alongside the existing
disable/remove) — same auth/Admin-PC restriction as everything in §29.

**Touches:** Phase 6 (new status + manager branch), Phase 7 (API endpoint +
control panel approve/reject UI).

---

## A8. Emergency rollback / kill-switch

**What:** One destructive, easy-to-reach action —
`POST /api/v1/firewall/kill-switch` + a prominent control-panel button —
that:

1. immediately sets `EnforcementMode` to `SHADOW` (stops new
   auto-deployment),
2. transitions every currently-`ACTIVE` **adaptive** rule to `REMOVED`
   (the static base ruleset from `deploy/firewall/` and the allowlist from
   **A2** are untouched),
3. records one summary `SecurityEvent` plus a per-rule audit entry,
4. requires the same authentication/Admin-PC restriction as everything
   else — no lower-security bypass path.

Built on the existing `RuleStatus` lifecycle (drives rules to `REMOVED`
through the normal manager transition, not a special-cased shortcut).

**Touches:** Phase 6 (`manager.py` gets `revert_to_base()`), Phase 7 (API +
control panel), Phase 9 (test against `FakeFirewallBackend`: populate
several `ACTIVE` rules, hit kill-switch, assert all removed, base +
allowlist untouched, mode is `SHADOW`).

---

## Summary — what changes in which phase

| Item | Phase 1 | Phase 2 | Phase 3 | Phase 6 | Phase 7 | Phase 8 | Phase 9 |
|------|---------|---------|---------|---------|---------|---------|---------|
| A1 Shadow mode | config + enum | | | manager | control panel | | tests |
| A2 Allowlist | model + config | | | validator stage | API + panel | | |
| A3 Rate cap | | | | validator stage | | Netdata metric | tests |
| A4 Process split | | | | | socket protocol | 2 systemd units | |
| A5 IPv4-only | | parser scope | schema scope | reject IPv6 target | | | |
| A6 Fail-open + watchdog | config | | | | | watchdog units | tests |
| A7 Assisted/approval | | | | status + logic | API + panel | | |
| A8 Kill-switch | | | | manager method | API + panel | | tests |

## RuleStatus lifecycle, updated

```text
CANDIDATE
    |
    v
VALIDATING
    |
    +--> REJECTED
    |
    +--> SHADOWED            (terminal; mode == SHADOW, logged only)   [A1]
    |
    +--> PENDING_APPROVAL --> APPROVED --> DEPLOYED --> ACTIVE          [A7]
    |         |
    |         +--> REJECTED  (human rejects)
    |
    v
  APPROVED (mode == ACTIVE, or ASSISTED below threshold, or non-BLOCK)
    |
    v
  DEPLOYED
    |
    v
  ACTIVE
    |
    +--> EXPIRED
    +--> DISABLED
    +--> REMOVED             (includes kill-switch, A8)
```

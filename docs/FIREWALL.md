# pirewall — Firewall Subsystem (spec §19-26, ADDENDUM.md)

Covers: the decision engine, candidate rule generation, the full validation
chain, deployment, and the rule lifecycle. See `docs/ARCHITECTURE.md` for
how this fits into the whole pipeline and `docs/SECURITY.md` for the
safety guarantees this subsystem exists to enforce.

## Pipeline (spec §22)

```text
ThreatAssessment
       |
       v
pirewall.engine.decision.decide          -> FirewallDecision
       |    (ThreatLevel -> FirewallAction, a fixed documented ladder —
       |     see "Decision engine" below)
       v
pirewall.firewall.generator.generate_candidate_rule  -> CandidateRule | None
       |    (None for ALLOW — nothing to enforce)
       v
pirewall.firewall.manager.FirewallManager.submit_candidate
       |
       v
pirewall.firewall.validator.validate_candidate_rule   <-- the full chain, see below
       |
   +---+---+
   |       |
 rejected  approved
   |       |
   v       v
RULE_REJECTED   mode-dependent branch (SHADOW / ASSISTED / ACTIVE, see below)
  event               |
                       v
              pirewall.firewall.backend.FirewallBackend.apply_rule
                       |
                       v
                 nftables (or FakeFirewallBackend in tests)
```

CLAUDE.md's "never": ML output never reaches a shell command or the
backend directly — every arrow above is a typed Python object, and
`pirewall.firewall.backend.nftables.NftablesBackend` builds its `nft`
payload from validated `FirewallRule` fields only, never from
`reason`/`evidence`/free-text.

## Decision engine (spec §19)

`pirewall.engine.decision.decide` maps a `ThreatAssessment`'s already-final
`threat_level` to exactly one `FirewallAction` — a deliberate, documented
design choice (`docs/PROGRESS.md` "Known deviations"), not derived from
spec text or tuned against real data:

| ThreatLevel | FirewallAction |
|---|---|
| LOW | ALLOW |
| MEDIUM | MONITOR |
| HIGH | RATE_LIMIT |
| CRITICAL | BLOCK |

This module never re-scores or re-interprets evidence itself — detection/
scoring and decision-making stay separate layers (CLAUDE.md).

**This ladder is necessary but not sufficient for `BLOCK`/`RATE_LIMIT`
(ADDENDUM_2.md B3).** `decide` applies the table above, then downgrades a
`BLOCK`/`RATE_LIMIT` result to `MONITOR` unless the assessment carries
"mature" evidence — a known-attack classification, a behavioral pattern
(which already requires multiple observations by construction), or the
same weak reading recurring for `evidence_maturity_consistency_windows`
consecutive assessments from the same source (`EvidenceMaturityTracker`).
So a raw `HIGH`/`CRITICAL` `threat_level` alone does not guarantee
`RATE_LIMIT`/`BLOCK` — see `docs/ADDENDUM_2.md` §B3 for the full invariant
and why it lives here rather than in the validator.

## Candidate rule generation (spec §22, §23)

`pirewall.firewall.generator.generate_candidate_rule` produces the
*narrowest possible* candidate: v1's adaptive pipeline only ever has
single-flow evidence, so every candidate targets the exact
source/destination `/32` pair the triggering flow used — never a wider
network. `source_port` is left unset (matches any — an attacker's source
port is normally ephemeral); `destination_port` is narrowed to the flow's
actual port. `ALLOW` decisions produce no candidate at all.

## Validation chain (spec §24, ADDENDUM.md)

Every candidate passes through `pirewall.firewall.validator.validate_candidate_rule`,
**in this order** (the addendum's update to spec §24's base order),
short-circuiting on the first rejection:

```text
schema -> network -> allowlist -> safety -> conflict -> duplicate
        -> rate-cap (A3) -> priority -> expiration -> authorization
```

| Stage | Rejects when... |
|---|---|
| `schema` | field-level validity beyond what Pydantic already guarantees (currently: a missing `threat_score`) |
| `network` | source/destination aren't valid `IPv4Network`s (belt-and-suspenders — the type system already prevents this) |
| `allowlist` | a `BLOCK`/`RATE_LIMIT` candidate targets a static `AllowlistEntry` (ADDENDUM.md A2) — **outranks everything below**, unconditionally |
| `safety` | a `BLOCK`/`RATE_LIMIT` candidate would touch any of five protected things — see below |
| `conflict` | an active rule already covers the same target with a *different* action |
| `duplicate` | an active rule already covers the exact same target *and* action |
| `rate_cap` | the adaptive rule-creation budget for the current window is spent (ADDENDUM.md A3) — detection/`SecurityEvent` generation is untouched by this, only rule *creation* is capped |
| `priority` | an active rule with the same action already fully covers (shadows) this candidate's scope |
| `expiration` | the candidate has no `expires_at` (temporary rules must expire, spec §24) |
| `authorization` | the candidate's `decision_id` wasn't registered via `FirewallManager.register_decision` — only the real decision engine's output may deploy a rule |

A rejected candidate is never silently dropped: `FirewallManager` records
which stage rejected it and why, and emits a `RULE_REJECTED` `SecurityEvent`.

### What the safety stage protects (spec §24)

Five independent checks, each keyed to a concrete config value, so a
failure of any one is individually attributable:

| Protected | Config field | Why |
|---|---|---|
| The Admin PC | `admin.admin_pc_ip` | The client end of every management connection. |
| pirewall itself | `network.pirewall_lan_ip` | The *server* end of management, and every LAN client's default gateway. Protecting the Admin PC does not cover this — they are different addresses. |
| Internet reachability | `network.upstream_gateway` | Every outbound packet transits it, so a `/32` here is "blocking the entire internet" without ever matching `0.0.0.0/0`. |
| The protected LAN as a whole | `network.protected_network` | The LAN itself or any supernet of it. Blocking a single host *inside* it is still allowed — that's the point of the system. |
| Anything broader than the evidence | `firewall.min_rule_prefix_length` | v1 only ever has single-flow evidence, so nothing wider should be needed; also catches the literal `0.0.0.0/0`. |

The `pirewall_lan_ip` and `upstream_gateway` checks were added by a
post-Phase-9 audit that found candidate rules targeting both were being
approved. See `docs/PROGRESS.md` "Known deviations from spec".

## Enforcement mode branching (ADDENDUM.md A1, A7)

Once a candidate passes the full chain, `FirewallManager.submit_candidate`
branches on `EnforcementMode`:

- **SHADOW** (default) — never reaches the backend. Becomes
  `RuleStatus.SHADOWED` plus a `"[shadow mode] would have ..."`
  `SecurityEvent`, so an operator can see exactly what pirewall *would*
  have done.
- **ASSISTED** — `MONITOR`/`RATE_LIMIT` and below-threshold `BLOCK`
  candidates auto-deploy as normal; `BLOCK` candidates at/above
  `firewall.assisted_review_threshold` go to `RuleStatus.PENDING_APPROVAL`
  instead (ADDENDUM.md A7) — visible in the control panel with one-click
  Approve/Reject. Approving deploys through the *same* manager path as
  everything else, never a shortcut.
- **ACTIVE** — full automatic enforcement: deploy immediately via
  `FirewallBackend.apply_rule`.

## Rule lifecycle (spec §25, ADDENDUM.md)

```text
CANDIDATE -> VALIDATING -> REJECTED
                        -> SHADOWED            (A1, terminal)
                        -> PENDING_APPROVAL -> APPROVED -> DEPLOYED -> ACTIVE
                                             -> REJECTED  (human rejects)
                        -> APPROVED -> DEPLOYED -> ACTIVE
ACTIVE -> EXPIRED | DISABLED | REMOVED (includes kill-switch, A8)
```

Every transition is recorded (`FirewallManager.transitions`, a
`RuleTransition` list) — the audit trail spec §22/§25 both ask for.
`DISABLED` and `REMOVED` are distinct terminal states: disabling is the
reversible-in-spirit "turn this off" action; removal is permanent.

## Priority (spec §23)

`priority = round(100 - threat_score)` — higher threat score -> lower
priority number -> evaluated first by the backend. A simple, explainable
scheme (`docs/PROGRESS.md` "Known deviations"), not tuned against real
conflicting-rule scenarios.

## Fail-safe behavior (ADDENDUM.md A6)

`FirewallManager.disable_rule`/`remove_rule`/`revert_to_base` all swallow a
`FirewallError` from the backend (`contextlib.suppress`) and still update
pirewall's own authoritative rule state — fail-open by default
(`config.failure.mode`). A backend that's temporarily unreachable can never
leave the control panel showing a stale "still active" rule, and can never
crash the manager itself. See `tests/security/test_firewall_failure_handling.py`
(Phase 9).

## Kill-switch (ADDENDUM.md A8)

`FirewallManager.revert_to_base`: sets `EnforcementMode.SHADOW`, transitions
every currently-`ACTIVE` adaptive rule to `REMOVED` (the static base
ruleset and the allowlist are untouched), and records one summary
`SecurityEvent` plus a per-rule audit entry. Built on the normal
`RuleStatus` lifecycle — never a special-cased bypass. `POST
/api/v1/firewall/kill-switch` (see `docs/API.md`) requires the same
authentication/Admin-PC restriction as every other write endpoint.

## Backends (spec §20)

`pirewall.firewall.interface.FirewallBackend` is a `Protocol`; exactly two
implementations exist:

- `pirewall.firewall.backend.nftables.NftablesBackend` — the real backend.
  Builds nft's documented JSON schema and hands it to `nft -j -f -` over
  stdin, `subprocess.run([...], shell=False)` always an argument list,
  never a hand-built nft-syntax string. Bootstraps its own `inet pirewall`
  table / `adaptive` chain (hook `forward`, priority `0`) on first use.
  Linux-only, requires `CAP_NET_ADMIN` and a real `nft` binary —
  **Environment-dependent**.
- `pirewall.firewall.backend.fake.FakeFirewallBackend` — in-memory, used by
  every test in this repository that needs a `FirewallBackend`.

`pirewall.firewall.manager.FirewallManager` is the **only** module allowed
to call into `pirewall.firewall.backend` — enforced by
`tests/security/test_backend_isolation.py` at the import-graph level, not
just by convention.

## Base ruleset vs. adaptive rules

`deploy/firewall/base.nft.template` (see `docs/DEPLOYMENT.md`,
`docs/SECURITY.md`) establishes deny-by-default forwarding/management
access in a *separate* nftables table (`inet pirewall_base`), evaluated
*after* the adaptive table's `forward` chain (priority `10` vs. the
adaptive chain's `0`) — so a narrow, evidence-driven adaptive block always
gets first say over the broader static policy.

## v2: the set-based kernel data plane (ADDENDUM_4.md D1, D2, D4, D5; phase 13)

Everything above describes the v1 path, which is still what
`pirewall-core` runs until phase 16 wires the set backend in. Phase 13
built the v2 path beside it. `FirewallManager` takes it when it is
constructed with a `set_backend`; without one, nothing above changes.

### Two kernel tables, loaded by `pirewall-start`

| Table | Hook / priority | Holds | Written at runtime by |
|---|---|---|---|
| `inet pirewall_static` (+ `arp pirewall_static_arp`) | prerouting -450 / -300, input and forward -5 | anti-spoof, per-MAC flood meters, the three `guard_verdict_*` chains | core changes only the verdict chains' contents (`set_guard_mode`), plus panic |
| `inet pirewall_adaptive` | prerouting -299 (before conntrack) | `block_mac`, `block4`, `ratelimit_mac`, `ratelimit4`, `allow_bound`, `infra4` | `FirewallManager` writes set **elements** only, never rules |
| `inet pirewall_base` | input 0, forward 10 | static posture, `policy drop` | nothing in v2 |
| `inet pirewall_portal` | forward -10 | C2 portal sessions | the existing C2 path only |

Core never creates or deletes a table, except panic. The templates live in
`deploy/firewall/`; see `deploy/firewall/README.md` for the load order.

Because `pirewall_adaptive` hooks prerouting, it sees traffic **to** the Pi
as well as traffic **through** it (audit flaw #13: v1's adaptive chain sat
on `forward` only). It returns DHCP, DNS and the portal toward the Pi
before any block rule, so a blocked device still renews its lease and can
read the C4 block notice.

### From a validated rule to a set element

```text
CandidateRule
   |  pirewall.firewall.sets.device_target   (the rule's LAN /32 source; MAC from the resolver)
   v
pirewall.firewall.validator.validate_set_candidate   <-- v2 chain, per device
   |
   v
FirewallManager: SHADOW -> nothing written | ASSISTED BLOCK >= threshold -> PENDING_APPROVAL
   |
   v
SetBackend.apply([SetOp(...)])   one atomic batch, element timeout = min(TTL, policy.max_ttl_seconds, 3600 s)
```

| Action | MAC known | IP only (all targets until phase 14) |
|---|---|---|
| BLOCK | `block_mac` | `block4` |
| RATE_LIMIT | `ratelimit_mac` | `ratelimit4` |
| MONITOR / ALLOW | no element | no element |

* **One device, one element.** A port scan is one `block4` element, not one
  rule per destination port (audit flaw #14). Duplicate and conflict checks
  key on the device, not the port tuple.
* **Upgrades are atomic.** A BLOCK on a device with an active RATE_LIMIT
  deletes the rate-limit element and adds the block element in one batch.
  The RATE_LIMIT rule goes to REMOVED. It needs evidence the active rule did
  not already carry.
* **Batched writes, no per-rule subprocess** (audit flaw #15).
  `NftablesSetBackend` sends one nft JSON document per operation through
  libnftables (`python3-nftables`), or through one `nft -j -f -` call when
  libnftables cannot be imported. `transport` and `metrics()` say which one
  is in use.
* **A3 counts element insertions.** The rule lifecycle, A7 approval and A1
  SHADOW work as on the v1 path.
* **A refused add is CRITICAL.** The rule goes to REJECTED with a
  `FIREWALL_ERROR` event. The usual cause is a full set.

### v2 validator chain (`validate_set_candidate`)

```text
schema -> network -> allowlist -> safety -> conflict -> duplicate
       -> rate-cap -> escalation -> expiration -> authorization
```

| Stage | Rejects when... |
|---|---|
| `network` | there is no single LAN device to key on (source not a `/32` inside `network.protected_network`): `UNENFORCEABLE` |
| `allowlist` | any allowlist entry covers the device's IP, whatever port it names (an element acts on the whole device) |
| `safety` | the IP is one of this host's addresses, the Pi's LAN address, the gateway, the Admin PC, or the network/broadcast address, or the MAC is the Admin PC's. Multicast, broadcast and zero MACs cannot be a `RuleTarget` at all |
| `conflict` | a RATE_LIMIT on a device that is already blocked (block outranks rate limit) |
| `duplicate` | the device already has an element for the same action |
| `rate_cap` | A3's budget is spent |
| `escalation` | an upgrade to BLOCK repeats only evidence the active RATE_LIMIT already had: `NO_NEW_EVIDENCE` |
| `expiration` | no `expires_at`, or one more than `policy.max_ttl_seconds` away: `EXPIRATION_TOO_LONG` |
| `authorization` | the decision was not registered (as v1) |

Every backend also runs `pirewall.firewall.sets.validate_element` before
writing. It refuses any set outside `MANAGER_WRITABLE_SETS` (D1's
single-writer table), an enforcement element without a timeout or with one
over 3600 s, and any key that is not a normalised IPv4 address or unicast
MAC.

### Guard modes, kill switch, fail-open and panic

| Operation | Adaptive sets | Guards | Tables | Mode |
|---|---|---|---|---|
| `set_guard_mode(guard, mode)` | unchanged | that guard's verdict chain flipped in one batch (`flush chain` + counter, + `drop` to enforce) | unchanged | unchanged |
| `revert_to_base` (kill switch, A8 + D5) | flushed, rules -> REMOVED | **all three set to observe** | both stay loaded | SHADOW |
| `fail_open_shutdown` (A6 narrowed) | flushed, rules -> REMOVED | **left as they were** | unchanged | unchanged |
| `panic(actor)` | gone with the table | gone with the table | `pirewall_static`, `pirewall_static_arp`, `pirewall_adaptive` deleted; `pirewall_base`, `pirewall_portal` kept | SHADOW |
| `reconcile` (startup) | read; unknown IP-keyed elements adopted as ACTIVE rules, vanished ones -> REMOVED, unattributable MAC elements reported | unchanged | never recreated; missing ones reported | unchanged |

Fail-open shutdown leaves the static guards protecting while core is down,
so a crash loop is no longer an off switch (audit flaw #17). Core still
calls `revert_to_base` when it fails open until phase 16 moves it onto
`fail_open_shutdown`. Panic restores with `sudo pirewall-start`. Its RPC and
`--panic` wiring is phase 16's.

### Verification

* **Tested** with `FakeSetBackend`: `tests/unit/test_firewall_sets.py`,
  `tests/unit/test_manager_sets.py`, `tests/unit/test_v2_template_invariants.py`.
  This includes the ruleset-diff invariant (`tests/helpers/ruleset_diff.py`).
* **Sandbox** (env=sandbox, never Pi results): `tests/netns/` runs the
  templates and `FirewallManager` + `NftablesSetBackend` against real nft
  in network namespaces. Run it as root on a Linux host with `nft`,
  `hping3`, `curl`, `conntrack` and a system `python3` with scapy:
  `sudo -E uv run pytest tests/netns`.
* **Environment-dependent**: nft 1.0.6 on the Pi, libnftables through the
  phase 16 `.pth`, and `ether saddr` on `wlan0` in AP mode.

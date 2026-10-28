# ADDENDUM_4 — v2: kernel guards, device identity and the policy table

A fourth set of agreed additions, on top of `MASTER_SPEC.md`, `ADDENDUM.md`
(A1–A8), `ADDENDUM_2.md` (B1–B6) and `ADDENDUM_3.md` (C1–C6). Where this
file conflicts with any of those, **this file wins**: it is the newest and
the most specific.

It is the rulebook for the v2 phases (11–20). Its sources are
`docs/v2/PLAN_v3.md` (authoritative), `docs/v2/PLAN_FINAL.md` for the
details PLAN_v3 leaves unchanged, and the nft templates tested in
`docs/v2/v2/` (`RESULTS.md`). Those tests ran in a **sandbox** (netns on
x86, nft 1.0.9 and 1.0.2). None of them ran on the Pi, and none of their
numbers are Pi numbers (D7).

The exact types, names and signatures behind these rules are frozen in
`docs/V2_CONTRACTS.md`, with typed stubs under `pirewall/`.

## Why this exists

The audit of `main` @ 8b91b5f (`docs/v2/audit_new_main.md`) found the
overhaul fixed detection timing and capture loss, but left the enforcement
model as it was, and made one risk worse:

* Enforcement sat only on the `forward` hook. Floods aimed at the Pi's own
  services were never enforceable.
* Rules were per-port tuples, applied one at a time through a subprocess. A
  port scan became one rule per port, up to the A3 cap.
* There was no anti-spoofing, and behaviour alone could now RATE_LIMIT. A
  client spoofing a neighbour's IP got the **neighbour** rate-limited.
* Behaviour plus a spurious Isolation Forest flag reached 95, a BLOCK. The
  forest flags about 10% of benign flows.
* Fail-open plus a crash loop was an off-switch, and the native engine's
  `panic = "abort"` added a new way to crash.

D1–D9 answer these. They move enforcement into kernel sets on both paths,
key it on the device (MAC), and take the choice of action away from the
score.

---

## D1 — Two kernel tables, each with a fixed set of writers

v2 adds two nftables tables beside `pirewall_base` and `pirewall_portal`,
which stay as they are.

**`table inet pirewall_static`** (plus its companion
**`table arp pirewall_static_arp`**) is reviewed static policy. It is
rendered from `deploy/firewall/pirewall_static.nft.template` and loaded by
`pirewall-start`, never by core. A reload declares everything and then
flushes **chains**; it never runs `delete table`, because that would wipe
the bindings and the offender state.

* **Its rules and chains are template-only.** The **single** permitted
  runtime write to its ruleset is replacing the contents of the
  `guard_verdict_raw`, `guard_verdict_input` and `guard_verdict_forward`
  chains, with either `drop` or nothing. Only
  `FirewallManager.set_guard_mode` does this (the kill switch calls it for
  all three), and every flip is one atomic batch (`flush chain` +
  `add rule`).
* **The only other change allowed is panic** (D5).
* **Set elements are data, not ruleset, and each set has exactly one
  writer:**

  | Sets | Writer |
  |---|---|
  | `bound4`, `macbind` (in both static tables) | `FirewallManager.sync_bindings` (D3) |
  | `allow_bound` | `FirewallManager`, from the A2 allowlist |
  | every `*_meter`, `portal_conc`, `offenders`, `unbound_seen` | the kernel itself (dynamic sets) |

  The template header still names a separate `pirewall-leases` process as
  the bindings writer. PLAN_v3 §3 folded that into a core thread, so the
  writer is `FirewallManager`, the only holder of a backend reference. A
  second privileged writer would break the single-deploy-path rule.

**`table inet pirewall_adaptive`** holds the adaptive enforcement sets. It is
hooked at prerouting priority −299: after anti-spoof (−300), before
conntrack (−200), so one chain covers the input path and the forward path,
and a blocked device costs no conntrack entries.

* `block_mac`, `block4` and `ratelimit_mac` are written **only by
  `FirewallManager`, after the full validator chain**. Core adds and
  removes elements; it never edits a rule.
* Every element carries a timeout of at most 3600 s, so a block orphaned by
  a crash expires on its own.
* `infra4` is rendered from config at load time. `rl_meter` belongs to the
  kernel. `allow_bound` is the allowlist copy, written in the same batch as
  the static one.

**Hook order.** A drop in any table is final; an accept only ends its own
chain.

```
pirewall_static    prerouting_frag     -450   before nf_defrag (-400)
pirewall_static    prerouting_raw      -300   anti-spoof + stateless per-MAC meters
pirewall_adaptive  prerouting_adaptive -299   adaptive block / ratelimit sets
pirewall_portal    forward              -10   portal gate (C2, unchanged)
pirewall_static    input/forward_guard   -5   stateful guards
pirewall_base      input 0 / forward 10       static posture, policy drop
```

**Invariants, each enforced by a test in the phase that builds it:**

* A ruleset diff before and after every core operation shows only allowed
  changes: guard-verdict chain contents, and elements of sets core writes.
* No verdict rule reads `@offenders`. The drop happens in the meter rule
  itself, which is static policy; `@offenders` is evidence only.
* Every LAN-facing chain is guarded by `iifname "<LAN>"`. Traffic arriving
  on the WAN or admin interface is never touched.
* Nothing in v2 writes `pirewall_base` or `pirewall_portal`, except the
  existing C2 portal path.
* `pirewall-start` refuses to run while `nftables.service` is enabled with a
  `flush ruleset` config, which would silently wipe every table.

## D2 — Static guards are reviewed static policy, not adaptive rules

The meters in `pirewall_static` drop packets on a fixed per-MAC rate,
decided by a reviewed template and a config value. They do not follow from
any detection, score or model. That puts them in the same category as
`pirewall_base`'s `policy drop`, not in the category A1 governs.

**How this reconciles with A1 (SHADOW by default).** A1 governs *adaptive*
enforcement: decisions that become rules or set elements through the
validator and `FirewallManager`. It still does, unchanged. `SHADOW` keeps
every adaptive set empty. It does not switch off the static guards, in the
same way it has never switched off `pirewall_base`. Guard modes are a
separate, explicit control:

| Guard | Default mode | Why |
|---|---|---|
| `input` (traffic to the Pi) | **enforce** | Protects the Pi's own services (DNS, portal concurrency, closed-port scans). The closed-port drops duplicate `pirewall_base`'s policy drop; enforce adds only the evidence. |
| `raw` (anti-spoof + per-MAC flood meters) | **enforce if seeded** | Enforces only once bindings were seeded at startup. If seeding fails, the raw guard is forced to **observe** and a SYSTEM_WARNING is raised, whatever the config says. |
| `forward` (traffic through the Pi) | **observe** | Household Internet traffic. Stays observe until the offline benign false-positive check (G5) has passed on real `pi-live` data. |

* An **observe-mode** guard drops nothing. Its hits are still counted and
  still recorded in `@offenders`, and the policy can turn them into at most
  **MONITOR** (D4).
* The **kill switch** sets every guard to observe as well as setting SHADOW
  (D5). So "pirewall enforces nothing it decided" is still one action away,
  as A8 promised.
* Switching a guard to **enforce** from the control panel needs the admin
  password again, and every flip is an audit event.
* In the tested template, the raw source-validation drops (out-of-subnet
  source, the Pi's own address, reverse-path failure, bound-IP/MAC
  mismatch) are bare `drop`s, as are the IPv6 and fragment drops. Those
  stay in force in observe mode. With no bindings seeded, the mismatch rule
  cannot match, so an unseeded raw guard drops only true martians.
  PLAN_FINAL §4.2 describes those steps as jumping to `guard_verdict_raw`
  instead; that variant was not what was tested. Phase 13 keeps the tested
  behaviour unless a test forces a change, and records the outcome.

## D3 — Device identity: MAC addresses and bindings

v2 keys enforcement on the device, not only its IP. A MAC survives a change
of address, and once anti-spoof enforces, a spoofed source IP can no longer
frame a neighbour.

* **`RuleTarget{ip, mac | None}`** names the device an action is about. The
  IP is always present. When a binding resolves the MAC, enforcement
  prefers the MAC-keyed sets (`block_mac`, `ratelimit_mac`); otherwise it
  falls back to the IP-keyed ones (`block4`). Rule models gain an optional
  `target`, so v1 callers keep working.
* **MAC values** are normalised to lowercase `aa:bb:cc:dd:ee:ff`. Anything
  that *identifies a device* (a target, a binding, an allowlist MAC, kernel
  evidence) must be unicast and non-zero. A multicast or broadcast MAC
  names every listener at once. Locally administered (randomised) MACs are
  accepted, because that is what phones use.
* **The binding source is the lease file.** `BindingTable` merges the
  NetworkManager dnsmasq lease file with `[[antispoof.static]]`, and a
  static entry always wins.
  * The lease file is read-only to pirewall: inotify plus a poll every
    `antispoof.poll_seconds`. Only the expiry, MAC and IP fields are
    parsed. Hostnames and client-ids are client-controlled text, so they
    are never parsed and never logged.
  * There is no `dhcp-script`. It would hand dnsmasq core's socket, which
    includes the kill switch (critique_safety_eval.md A7).
  * Lease sync is a core thread. It writes through
    `FirewallManager.sync_bindings` in one nft batch per sync, deleting an
    old pair **before** adding its replacement. Each element's timeout is
    the lease expiry plus `antispoof.grace_seconds`, so bindings survive a
    core crash and expire on their own.
* **Anti-spoof ordering**, as tested, in `prerouting_raw` (LAN ingress
  only):
  1. Drop IPv6 (stronger than A5: IPv6 is dropped on the LAN, and preflight
     requires `disable_ipv6=1` there).
  2. DHCP from unconfigured clients: per-MAC brake, then allowed.
  3. Link-local multicast and broadcast: exempt from anti-spoof.
  4. Source outside the protected network, or the Pi's own address: drop.
  5. Reverse-path failure: drop.
  6. A bound IP from the wrong MAC: drop.
  7. A source with no binding: the tightly metered `unbound` class,
     recorded in `@unbound_seen`. Static-IP devices without an entry keep a
     working but metered path, rather than an outage.
  8. Allowlisted MAC+IP: return. This comes **after** anti-spoof, so an
     allowlisted IP cannot be borrowed.
  9. Per-MAC flood meters.

  The ARP companion table drops ARP that claims the Pi's address, or a
  bound IP from the wrong MAC. An `inet` table never sees ARP, so without
  it a client could poison the Pi's neighbour cache.
* **The allowlist still outranks every adaptive rule (A2).** Entries gain an
  optional MAC. The validator refuses any target whose IP *or* MAC is
  allowlisted, and `allow_bound` holds the entries that have both. The
  trade-off, stated once: an allowlisted device gets no flood protection.
* **Portal sessions become `(ip, mac)`.** The `authed` set becomes
  `ipv4_addr . ether_addr`. The portal learns a client's MAC from core's
  binding view, never from the HTTP request.
* **MAC is never a model feature.** It is carried on `Flow` for keying and
  excluded from every feature vector.
* **Limits:**
  * MAC cloning or injection by someone who holds the Wi-Fi PSK is out of
    scope (D8).
  * That `ether saddr` on `wlan0` (brcmfmac in AP mode) is the station's
    MAC is reasoned, not verified. It is the first Pi check
    (Environment-dependent). If it fails, every MAC-keyed rule is wrong.

## D4 — The policy table replaces score-driven actions

Under `pipeline.engine = "v2"`, a reviewable policy table chooses the
action. It is data (`pirewall/policy/table.toml`, phase 17), not code. Its
input is the evidence bundle for one device; its output is a
`PolicyDecision`. That decision goes through the validator chain and
`FirewallManager` like any other. **Scores are still computed, for
explanation and the UI only.** Nothing reads a score to choose an action,
and a test proves it by mutating scores and checking that the actions do
not change. `PolicyDecision.threat_level` is derived from the action, so
the dashboard and API keep working.

**Ceilings, enforced by an exhaustive policy-matrix test:**

* **ML-only or anomaly-only evidence ⇒ at most MONITOR.** That covers D2
  (Isolation Forest) alone, D3 (LightGBM) alone, and D2 + D3 together.
  Anomaly evidence never raises an action.
* **An observe-mode guard's offender ⇒ at most MONITOR**, in every
  enforcement mode.
* **An enforce-mode guard's offender** may cause RATE_LIMIT only once it has
  persisted `policy.sustained_polls` (≥ 2) consecutive 1 s polls.
* **D1 (deterministic detectors) is the only non-kernel tier that may act.**
* **Escalation needs new, independent evidence.** Repeating the same
  evidence never lengthens or upgrades an action. A TTL multiplies by
  `policy.escalation_ttl_multiplier`, capped at `policy.max_ttl_seconds`
  (≤ 3600).
* **Allowlisted and infrastructure targets are never acted on.**

The table (PLAN_FINAL §4.6). "log" means A1: the decision is computed and
recorded SHADOWED, and nothing is written.

| Evidence | SHADOW | ASSISTED | ACTIVE |
|---|---|---|---|
| K offender from an *observe* guard | log | MONITOR | MONITOR |
| K offender from an *enforce* guard, sustained ≥ 2 polls | log | RATE_LIMIT mac 5 min | RATE_LIMIT mac 5 min |
| D1 high-certainty (fast scan, brute force) | log | RATE_LIMIT; BLOCK goes to the approval queue | BLOCK mac 5 min |
| D1 + K, or D1 repeated with **new independent** evidence | log | BLOCK goes to approval | BLOCK, TTL ×2 (cap 1 h) |
| D2 or D3 alone, or D2 + D3 | log | MONITOR | MONITOR |
| D2/D3 + D1 | log | RATE_LIMIT | RATE_LIMIT |

**Validator order for set elements**, replacing the A2 order for v2 targets:

```
schema → network → allowlist → safety → conflict → duplicate
       → rate-cap → escalation → expiration → authorization
```

* **Safety** checks the IP *and* the MAC against the infrastructure set
  (Pi addresses, gateway, Admin PC IP and MAC) and refuses non-unicast
  MACs.
* **Conflict** applies block-over-ratelimit precedence; an upgrade is one
  atomic delete+add.
* **Duplicate** works per target, not per port tuple.
* **Rate-cap (A3)** counts element insertions.
* **Escalation** replaces priority.
* **Expiration** is mandatory: there are no elements without a timeout.

**`engine = "v1"` stays selectable** as the evaluation baseline (G8). It is
the merged-main pipeline, deploying through the same set backend via an
adapter: `RuleTarget(ip=src)`, with the MAC resolved through
`BindingTable`. v1 keeps its own semantics, including the score-to-BLOCK
risk above; that is why it is a baseline. The default stays `"v1"` until
phase 17 ships the policy engine.

## D5 — Kill switch, panic and failure

* **Kill switch (A8, extended).** One action, through the normal
  `RuleStatus` lifecycle:
  1. Set `EnforcementMode` to SHADOW.
  2. Flush `block_mac`, `block4` and `ratelimit_mac`, driving their rules to
     REMOVED.
  3. Set **all three** guards to observe. Flipping only `raw` is not enough:
     a still-enforcing `input` guard kept dropping in the sandbox
     (RESULTS.md finding 4).
  4. Write an audit entry.

  Both v2 tables stay loaded. Bindings, the allowlist and
  `pirewall_base` are untouched.
* **Panic.** Deletes `inet pirewall_adaptive`, `inet pirewall_static` and
  `arp pirewall_static_arp`, and nothing else. `pirewall_base`,
  `pirewall_portal` and NetworkManager's own tables stay. Panic is
  available over RPC (admin only), as `pirewall-start --panic`, and as a
  documented console one-liner. It also drives every adaptive rule to
  REMOVED and sets SHADOW, so core's state matches the kernel. The restore
  path is re-running `pirewall-start`.

  The template comment lists only the two `inet` tables. The ARP companion
  is included here on purpose. Once core is gone, nothing keeps that
  table's bindings current, so a stale entry could drop the ARP of a device
  whose lease has moved to a new MAC. Panic means pirewall is out of the
  data path entirely, not mostly.
* **Clean fail-open shutdown (A6, narrowed).** Flushes the adaptive
  enforcement sets **only**. Guards keep their modes, and bindings expire by
  their own timeouts. A crash loop therefore no longer turns pirewall off:
  the static guards keep protecting while core is down (G6). A crash loop
  raises CRITICAL to Wazuh.
* **Crash.** Adaptive elements expire by their TTL.
* **Restart.** Core reconciles with the live set contents and never
  recreates a table.
* **Table loss.** Core checks every second that both tables exist. On loss
  it raises CRITICAL. Reloading the reviewed templates is `pirewall-start`'s
  job, not core's, because core never writes static rules (D1).

## D6 — The native engine runs inside core, hardened

The Rust TPACKET_V3 engine (`native/`) stays **in-process in
`pirewall-core`**, which holds CAP_NET_RAW and CAP_NET_ADMIN. NFStream and
the separate `pirewall-sensor` process from PLAN_FINAL are dropped.
**Splitting the engine into its own process is deferred, and is future
work.** It is acceptable now because the kernel guards keep protecting
while core is down (D5), so an engine crash costs visibility, not
enforcement.

Hardening is required before v2.0 (phase 15):

* `panic = "unwind"`, and `std::panic::catch_unwind` around every PyO3
  entry point (`feed`, poll/drain, `sweep`). A panic becomes a Python
  `NativeEngineError`. Core counts it, drops that frame or batch, emits a
  `CAPTURE_ERROR` event and carries on. After N panics in a minute it
  falls back to the Python capture path, with a CRITICAL event.
* A fuzz target for `parse::parse` (cargo-fuzz, or `proptest` if cargo-fuzz
  cannot run), run for at least 10 minutes, with the result recorded.
* TPACKET_V3 ring offsets and `snaplen` clamped to `block_size`. The kernel
  is trusted, but the clamp costs almost nothing.

The engine also becomes the only producer of training data. Pcaps are
replayed through `FlowEngine.feed`, so live features and training features
come from the same code, byte for byte (spec §11). It also gains
`src_mac`/`dst_mac` (D3).

## D7 — Data modes and env tags

| Mode | What it is | Where |
|---|---|---|
| `live` | real household devices on the LAN, with consent | the Pi |
| `scripted` | scripted benign profiles from our own devices | the Pi |
| `mock` | synthetic pcaps with ground truth, replayed offline (`capture.backend = "replay"`, no root, no nft) | anywhere |

Every artifact carries exactly one **env tag**: run outputs, manifests,
datasets, threshold files and model metadata. The tags are:

* `pi-live`: live mode on the Pi.
* `pi-scripted`: scripted mode on the Pi.
* `sandbox`: the netns testbed or any non-Pi Linux box with real nft.
* `mock`: synthetic data.

**The no-mixing rule.**

* Aggregation (`lab/aggregate.py`) refuses to combine artifacts with
  different tags.
* **Only `pi-*` numbers are Pi results.** Only they may appear as results in
  the paper, the README or `docs/PROGRESS.md`.
* `mock` and `sandbox` numbers are regression evidence and are always
  labelled as such. They are never reported as Pi results, never averaged
  with them, and never used to fill a Pi table.
* `pi-live` and `pi-scripted` benign figures are reported separately.

`lab.env_tag` defaults to `sandbox`, never to a `pi-*` tag. A Pi result has
to be claimed explicitly (`pirewall-start --data-mode`), so a forgotten
setting can only under-claim. `--data-mode mock` never writes a `pi-*` tag.

## D8 — Scope statement

Verbatim from `docs/v2/PLAN_v3.md` §1, for the README and the paper:

> Pirewall v2 is a host-level adaptive defence for a single Raspberry Pi 4 acting as a Wi-Fi access point for a small LAN. It mitigates volumetric floods, port scans and brute-force attempts originating from LAN clients toward the Internet or the Pi, and blocks IP and ARP spoofing of other LAN clients. It uses static in-kernel nftables guards plus adaptive per-device (MAC) sets, driven by deterministic detectors whose thresholds are learned from benign traffic, with ML anomaly and classification as supporting evidence.
>
> **Out of scope:**
> - client↔client traffic on the onboard radio, which is bridged in firmware;
> - payload and encrypted content;
> - ML evasion beyond MONITOR;
> - RF attacks (deauthentication, jamming, evil twin), which PMF only mitigates;
> - MAC cloning or injection by a PSK holder;
> - IPv6 (dropped on the LAN);
> - Wi-Fi airtime exhaustion;
> - upstream DNS integrity.
>
> The ML components were trained on one network's short capture. All reported numbers come from scripted, repeated runs on the real Pi, with hashed manifests.

## D9 — What happens to v1 features

| v1 feature | Under `engine = "v2"` | Under `engine = "v1"` |
|---|---|---|
| Heartbleed detector (B4) | **Dropped.** Stated in the paper. | Unchanged (baseline) |
| JA3 tool fingerprints (B5) | **Dropped.** Stated in the paper. | Unchanged (baseline) |
| `SLOW_RATE_DOS` (B2) | **Ported** into D1 as `slow_rate_dos`, keyed by MAC | Unchanged |
| `TEMPORAL_PATTERN`, `PERSISTENCE` | MONITOR-only if time allows, otherwise dropped (phase 17 decides and records it) | Unchanged |
| Other behaviour patterns | Replaced by the D1 detectors | Unchanged |
| Source-level fast path (B1) | Reused for D1 timing | Unchanged |
| Evidence-maturity gate (B3) | Superseded by the policy table and `sustained_polls` | Unchanged |
| Netdata gauges | **Re-sourced** from engine stats and nft counters (offenders, guard counters, set fill), or they go flat | Unchanged |
| Wazuh events | v2 event JSON, with a decoder written for it | Unchanged |

---

## What this addendum changes elsewhere

* **ADDENDUM_3 C2, forward-hook ordering.** v1's adaptive chain (`pirewall` /
  `adaptive`, forward priority 0) is replaced by `pirewall_adaptive` at
  prerouting −299. The portal's position in the `forward` order is
  unchanged.
* **ADDENDUM_3 C4, "this works because adaptive rules live on forward".**
  No longer true: the adaptive table now sees input traffic too. So it must
  exempt DHCP, DNS and the portal ports, toward the Pi, **before** any
  block rule, so that a blocked device still renews its lease and sees the
  notice. The tested `pirewall_adaptive` template does **not** yet do this.
  Phase 13 adds it, with a netns test that a blocked MAC still reaches the
  notice page.
* **ADDENDUM A2.** Allowlist entries gain an optional MAC. The validator
  checks both keys.
* **ADDENDUM A3.** The rate cap counts set-element insertions.
* **ADDENDUM A6.** Fail-open revert flushes adaptive sets only (D5).
* **ADDENDUM A8.** The kill switch also sets every guard to observe (D5).
* **ADDENDUM_2 B4/B5.** Dropped under `engine = "v2"` (D9).
* **`deploy/firewall/base.nft.template`** (phase 13). The admin rule is
  pinned to the admin interface + admin MAC + admin IP, and the DNS accepts
  are pinned to the LAN interface (`docs/v2/v2/base_and_portal.diff`).
* **The `infra4` source `return` in the tested adaptive template.** PLAN_FINAL
  §4.2 and critique_round2.md item 1 forbid an infrastructure *source*
  accept on LAN chains, because it is a spoofing bypass. In the template it
  is harmless in practice, because `prerouting_raw` drops those sources
  first, but it contradicts the plan. Phase 13 resolves it, and records the
  outcome.

## Phase map

| Item | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 |
|---|---|---|---|---|---|---|---|---|---|---|
| D1 Two tables | names, contracts | | templates, set backend, guard modes, diff test | `sync_bindings` | | load order, preflight | K poller reads | | | docs |
| D2 Guard defaults | config | | `set_guard_mode` | seed → raw observe | | flags, defaults | observe ⇒ MONITOR | | | |
| D3 MAC identity | types | | | end to end | | `configure.py` MACs | MAC-keyed D1 | | | |
| D4 Policy table | `PolicyDecision` | | validator v2 | validator MAC | | | engine + matrix | | ML ≤ MONITOR | |
| D5 Kill switch / panic | names | | manager + backend | | | `--panic`, RPC | | | | runbook |
| D6 Native engine | | | | MAC fields | hardening, replay | | | | | |
| D7 Env tags | config, rule | | | | | per data mode | | aggregate refuses mixing | dataset tags | paper tables |
| D8 Scope | text | | | | | | | | | README, paper |
| D9 v1 features | table | | | | | | port, drop, re-source | | | docs |

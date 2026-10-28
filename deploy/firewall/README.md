# `deploy/firewall/` — nftables ruleset templates

Spec §24/§27, ADDENDUM.md, ADDENDUM_3.md C2, ADDENDUM_4.md D1/D2/D5.
**Not applied automatically.** A human reviews, renders and loads these by
hand, or through `pirewall-start`. `scripts/deployment/render_templates.py`
writes substituted copies to `deploy/rendered/` and touches nothing else.
It renders everything or nothing: if a template needs a value the config
leaves unset (for example `network.admin_interface` or `admin.admin_pc_mac`
on a 1.x config), it lists every missing name and writes no file.

| Template | Table(s) | Who changes it at runtime |
|---|---|---|
| `base.nft.template` | `inet pirewall_base`: deny-by-default `input`/`forward` | nothing |
| `portal.nft.template` | `inet pirewall_portal`: the C2 captive-portal gate | the C2 portal path (`authed` set elements) |
| `pirewall_static.nft.template` (v2) | `inet pirewall_static` + `arp pirewall_static_arp`: anti-spoof, per-MAC flood meters, guard verdict chains | core replaces only the contents of the three `guard_verdict_*` chains (`FirewallManager.set_guard_mode`), and writes binding/allowlist set elements; panic deletes it |
| `pirewall_adaptive.nft.template` (v2) | `inet pirewall_adaptive`: adaptive block / rate-limit sets | core writes set **elements** only (`FirewallManager`), each with a timeout of at most 3600 s; panic deletes it |

Nothing in `pirewall/` writes these files, and nothing writes
`pirewall_base`. The v1 `NftablesBackend` still bootstraps its own
`inet pirewall` table (`adaptive` chain, hook `forward`, priority 0) until
phase 16 moves core onto `NftablesSetBackend`.

## Hook order

A drop in any table is final. An accept only ends its own chain.

```
pirewall_static    prerouting_frag     -450   before nf_defrag (-400)
pirewall_static    prerouting_raw      -300   anti-spoof + stateless per-MAC meters
pirewall_adaptive  prerouting_adaptive -299   adaptive block / ratelimit sets
pirewall_portal    forward              -10   portal gate (C2)
pirewall_static    input/forward_guard   -5   stateful guards
pirewall_base      input 0 / forward 10       static posture, policy drop
```

## Load order on the real Pi

1. `../network/60-pirewall-forwarding.conf.template` (sysctl: IP
   forwarding must be on before any of this does anything).
2. `base.nft`.
3. `../network/nat-masquerade.nft`.
4. `pirewall_static.nft`, then `pirewall_adaptive.nft`. The adaptive table
   jumps nowhere into the static one, but its exemptions and the guards are
   reviewed as a pair, so load both or neither.
5. `portal.nft`, if the portal is enabled.
6. Start `pirewall-core.service` (`../systemd/README.md`). It reconciles
   with the live set contents and never creates or deletes a table.

Phase 16 makes `pirewall-start` do steps 4 and 5 and the preflight below.
Until then, load the v2 tables by hand (`sudo nft -c -f FILE` first, then
`sudo nft -f FILE`).

**Reloading is safe and idempotent.** Each v2 template declares its tables
and sets, then flushes its **chains**. It never runs `delete table`, so set
elements (bindings, the allowlist, live blocks, offender state) survive a
reload. Only `infra4` is flushed and re-rendered, because it comes from
config. The netns tier checks this with live elements present
(`test_8_reload_twice_is_idempotent_with_live_elements`, env=sandbox).

A reload also re-renders the three `guard_verdict_*` chains from the
`[guards]` modes in config. A mode flipped at runtime, including by the
kill switch, goes back to the configured mode on the next reload.

## The `nftables.service` flush hazard

Debian's default `/etc/nftables.conf` starts with `flush ruleset`. If
`nftables.service` is enabled, or someone restarts it, it silently wipes
**every** table: NetworkManager's, the portal's, `pirewall_base` and both v2
tables. pirewall then enforces nothing, and nothing says so until core's
table check notices.

Before loading these templates on the Pi:

```sh
systemctl is-enabled nftables.service     # want: disabled (or masked)
grep -n 'flush ruleset' /etc/nftables.conf
```

Either keep `nftables.service` disabled, or remove `flush ruleset` from its
config. Phase 16's preflight refuses to start while the service is enabled
with a `flush ruleset` config.

## Kill switch, fail-open and panic

* **Kill switch:** flushes `block_mac`, `block4`, `ratelimit_mac` and
  `ratelimit4`, sets all three guards to observe, sets SHADOW. Every table
  stays loaded.
* **Clean fail-open shutdown:** flushes the same four sets, and leaves the
  guards as they were.
* **Panic:** deletes `inet pirewall_adaptive`, `inet pirewall_static` and
  `arp pirewall_static_arp`. `pirewall_base`, `pirewall_portal` and
  NetworkManager's tables stay. The console equivalent is:

  ```sh
  sudo nft 'delete table inet pirewall_adaptive; delete table inet pirewall_static; delete table arp pirewall_static_arp'
  ```

  Restore with `sudo pirewall-start`.

## Verification

* **Tested** (unit, no root): `tests/security/test_firewall_base_template.py`
  and `tests/unit/test_v2_template_invariants.py` parse the templates.
  They check that no rule reads `@offenders` in a verdict, that every
  LAN-facing chain is guarded by `iifname`, the C4 exemptions, the absence
  of an infrastructure-source accept, the pinned admin rule, and that every
  template renders completely.
* **Sandbox** (env=sandbox, real nft in network namespaces, never Pi
  results): `tests/netns/` loads the rendered templates and drives them
  through `FirewallManager` + `NftablesSetBackend`.
* **Environment-dependent:** loading on the Pi's nft 1.0.6, and real
  traffic on `wlan0`/`eth0`. See `docs/DEPLOYMENT.md`.

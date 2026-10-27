# Phase 13: Kernel data plane, set backend, guard modes, kill switch and panic

**Read first:**
- `CLAUDE.md` (v2 section)
- `docs/ADDENDUM_4.md` D1, D2 and D5
- `docs/V2_CONTRACTS.md`
- `docs/v2/PLAN_FINAL.md` §4.2 and §4.7
- `docs/v2/v2/RESULTS.md`, then **every file in `docs/v2/v2/`**: the templates, `render.py`, `netns_testbed.sh`, `test_ruleset.py` and `base_and_portal.diff`
- `docs/v2/critique_redteam.md` V1–V4
- `pirewall/firewall/` (all of it)
- `deploy/firewall/`
- `scripts/deployment/render_templates.py`

**Owns:**
- `deploy/firewall/**`
- `pirewall/firewall/backend/**`
- `pirewall/firewall/validator.py`
- New `pirewall/firewall/sets.py` and `pirewall/firewall/guards.py`
- `scripts/deployment/render_templates.py`
- `tests/netns/**` and the related unit tests

**Integrator duty:** this phase owns `pirewall/firewall/manager.py`.

Phases 12 and 15 may run in parallel.

## Goal
Move enforcement from per-rule linear `forward` chains to the tested two-table design: static guards plus adaptive sets with timeouts, on both the input and forward paths, written through libnftables. The v1 pipeline must keep working on top of it.

## Deliverables
1. **Templates.**
   - Port `docs/v2/v2/pirewall_static.nft.template` and `pirewall_adaptive.nft.template` into `deploy/firewall/`, unchanged unless a test forces a change. Document any change.
   - Apply `base_and_portal.diff` to `base.nft.template` only: admin pinned to `iifname eth0` + admin MAC + admin IP, and DNS pinned to the LAN interface. The portal set change belongs to phase 14.
   - Extend `render_templates.py` with the new variables (LAN/WAN interfaces, admin MAC, Pi addresses, every `[guards]` rate and burst). It refuses to render if a variable is missing.
2. **`NftablesBackend` v2** (`backend/nftables.py`, new class `NftablesSetBackend`; keep the old class until phase 16 removes its use).
   - **Transport.** Use libnftables through `python3-nftables`. Import it from a `.pth` path, falling back to `nft -j -f -` in batched mode with one call per batch. Add a `transport` property and metrics.
   - **Operations:**
     - `add_element(set, key, timeout)`, `delete_element`, `flush_set`
     - `list_set` (read-after-write needs a separate call [V])
     - `set_guard_mode(guard, mode)`: one atomic batch that flushes the `guard_verdict_<guard>` chain and adds `drop` or nothing
     - `table_exists`, `set_fill(set)`
     - `panic()`: delete both pirewall tables
   - **Never** `delete table` except in `panic()`, and never touch `pirewall_base` or `pirewall_portal`.
   - The Fake backend gets the same semantics: element timeouts on an injectable clock, set sizes with an add that fails when full, and guard chains.
3. **`FirewallManager` v2 path.**
   - Translate `FirewallRule`/decisions into set elements. BLOCK goes to `block_mac` when a MAC is known, otherwise `block4`. RATE_LIMIT goes to `ratelimit_mac`.
   - Until phase 14 adds MAC, IP-only targets go to `block4` and a `ratelimit4` IP set. Add `ratelimit4` to the adaptive template if it isn't there already.
   - Keep the `RuleStatus` lifecycle, the A3 rate cap (now counting element insertions), approval (A7) and SHADOW (no writes).
   - **Upgrades** (rate limit → block) are an atomic delete+add.
   - **Reconcile on start:** read live set contents and rebuild RuleStatus. Never recreate tables.
   - **`revert_to_base`** (kill switch and fail-open) flushes the adaptive sets and sets every guard to observe. **Fail-open shutdown flushes adaptive sets only; guards stay as they were.**
   - **`panic()`**, with an RPC stub; phase 16 does the wiring.
4. **Validator v2.** Keep the stage order from PLAN_FINAL §4.6:
   - The safety stage checks targets against the infra set (Pi addresses, gateway, admin IP and MAC) and against non-unicast or multicast MACs.
   - Expiration is mandatory (≤ `policy.max_ttl_seconds`).
   - Escalation replaces priority.
   - Duplicate and conflict checks are per target, not per port tuple.
5. **Invariant test helpers:**
   - A ruleset-diff helper that dumps `nft -j list ruleset` (or the Fake state) before and after an operation and asserts that only allowed objects changed.
   - A test that no rule in any template reads `@offenders` in a verdict.
   - A test that every LAN chain rule is guarded by `iifname`.
6. **Netns test tier** (`tests/netns/`, marked `@pytest.mark.netns`, skipped unless root, nft and hping3 are present). Port `docs/v2/v2/netns_testbed.sh` and `test_ruleset.py` assertions 1–13 so that they run **through `NftablesSetBackend` and `FirewallManager`**. Add:
   - An adaptive BLOCK of a MAC that still allows DHCP, DNS and the portal (C4 notice reachable).
   - A kill switch → panic sequence.
   - Reload idempotency with live elements present.
   - That fail-open shutdown leaves the guards active.
7. **Docs.** Update `docs/FIREWALL.md` for the set-based lifecycle. Add `deploy/firewall/README.md` notes covering load order and the `nftables.service` flush hazard.

## Tests
- Unit: Fake-backend semantics, the manager's v2 path, validator v2 stages, the invariant helpers, the guard-mode flip.
- Netns: as listed above. In the summary, report which ones ran and which were skipped, and why.

## Non-goals
No MAC plumbing through capture (phase 14), no detection changes, no `pirewall-start` changes (phase 16).

## Definition of done
- ruff, pyright strict and pytest green. Netns tests pass where they can run.
- `docs/FIREWALL.md` and PROGRESS are updated.
- KNOWN_ISSUES v1 items 13, 14 and 15 and audit item 17 are marked fixed in code (Tested/Mocked as appropriate). Environment-dependent: Pi nft 1.0.6 verification.

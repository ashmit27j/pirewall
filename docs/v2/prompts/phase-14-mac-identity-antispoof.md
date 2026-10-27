# Phase 14: MAC identity end to end, bindings, anti-spoof and portal binding

**Read first:**
- `CLAUDE.md` (v2 section)
- `docs/ADDENDUM_4.md` D3
- `docs/V2_CONTRACTS.md` (RuleTarget, Binding, BindingTable, FlowRecord additions)
- `docs/v2/critique_round2.md` items 3 and 8
- `docs/v2/critique_safety_eval.md` A4–A7
- `native/src/parse.rs`, `flow.rs`, `lib.rs`, `typings/pirewall_native.pyi`
- `pirewall/capture/`, `pirewall/flow/`, `pirewall/core/models/flow.py`
- `tests/unit/test_native_parity.py`
- `pirewall/portal/`, `pirewall/ipc/portal_service.py`
- `pirewall/firewall/` (after phase 13)

**Depends on:** phase 13. **Integrator duty:** this phase owns `pirewall/runtime/core.py` and `pirewall/firewall/manager.py` for its changes.

## Goal
Carry the source and destination MAC from the frame to every decision. Bind IP↔MAC from the NetworkManager dnsmasq lease file plus static config. Make enforcement, the allowlist, portal sessions and block notices MAC-aware, keeping every existing behaviour working for IP-only callers.

## Deliverables
1. **Parser and flow MACs.**
   - Add `src_mac`/`dst_mac` to `native/src/parse.rs` → `FlowState` → `FlowRecord`/`NewFlowRecord` → the `.pyi` stub.
   - Do the same in Python `PacketMetadata` and the flow state, and add `Flow.source_mac`/`destination_mac` (optional, default None, so the CICIDS and UNSW adapters stay valid).
   - Extend the parity test so both paths produce identical MACs.
   - **MAC is never a model feature.** Add a test asserting `FEATURE_NAMES` contains no MAC or OUI field.
2. **`BindingTable` + lease sync (core thread).**
   - Watch `antispoof.lease_file` with inotify where available, plus a poll every `antispoof.poll_seconds` (default 2).
   - Parse only `expiry MAC IP` using strict regexes. **Ignore the hostname and client-id fields** and never log them unescaped.
   - Merge in `antispoof.static`.
   - Sync through `FirewallManager.sync_bindings()`, a non-RuleStatus path like portal elements:
     - On a changed pair, delete the old pair before adding the new one.
     - Timeout = lease expiry.
     - One nft batch per sync.
   - Keep sync outside the RPC lock and serve a snapshot.
   - On startup, a failed seed sets the raw guard to observe and emits SYSTEM_WARNING.
3. **`RuleTarget` everywhere.**
   - `CandidateRule`/`FirewallRule` get an optional `target: RuleTarget`. Keep `source`/`destination` for v1 compatibility.
   - The v1 generator fills `target.mac` via `BindingTable.resolve_mac(src_ip)`.
   - The manager prefers `block_mac`/`ratelimit_mac` when a MAC is known.
   - `blocking_rules_matching(ip)` resolves IP→MAC and matches on either.
4. **Allowlist entries gain an optional MAC.** The `allow_bound` set is rendered and synced from entries that have both IP and MAC. The validator refuses any target whose IP or MAC is allowlisted.
5. **Portal.**
   - The `authed` set becomes `ipv4_addr . ether_addr`, using the `base_and_portal.diff` portal part.
   - The gate becomes `ip saddr . ether saddr @authed`.
   - `portal_service.login`/`keepalive`/`logout` resolve the client MAC via `BindingTable` from the request IP. Login is refused if no binding exists, with a clear message.
   - Sessions store `(ip, mac)`.
6. **Block notice (C4)** is looked up by IP→MAC.
7. **ARP anti-poisoning table.** Port it from the templates if phase 13 didn't. It is synced from the same bindings.

## Tests
- **Parity:** MACs are identical in the native and Python paths. A spoofed-source frame carries the attacker's MAC.
- **Lease parser** fuzz-ish cases: malformed lines, an injected newline in the hostname, IPv6 lines, duplicates and expiry `0`.
- **Sync** delete-before-add ordering, using the Fake backend's call log.
- **Startup seed failure** leaves the raw guard in observe mode.
- **Portal** login/keepalive with and without a binding, and a session refused when the MAC changes.
- **Netns** (if root): spoofing a bound neighbour's IP → dropped, and the neighbour never appears in a set. A MAC-keyed BLOCK still reaches DHCP, DNS and the portal notice.

## Non-goals
No detector changes (phase 17), no startup-script changes (phase 16).

## Definition of done
- ruff, pyright strict, pytest and the native parity tests all green.
- `cargo test` and `cargo clippy -D warnings` clean in `native/`.
- PROGRESS and KNOWN_ISSUES updated: v1 #12/#16 and audit #16 are fixed in code. Environment-dependent: that `ether saddr` on brcmfmac `wlan0` is the station MAC (see `RUNBOOK_PI.md` H1).

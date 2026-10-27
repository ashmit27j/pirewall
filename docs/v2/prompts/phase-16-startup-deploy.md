# Phase 16: `pirewall-start` v2, deployment templates, systemd, data modes and the lab victim

**Read first:**
- `CLAUDE.md` (v2 section)
- `docs/ADDENDUM_4.md`
- `docs/v2/PLAN_v3.md` §4 and §6 (the spec for this phase)
- `docs/v2/RUNBOOK_PI.md`
- `scripts/deployment/pirewall-start` (all 610 lines; keep its ordering rules and its idempotent style)
- `scripts/deployment/configure.py`, `render_templates.py`
- `deploy/systemd/*`
- `deploy/network/*`
- `docs/SETUP.md`, `setup-new-network.md`

**Depends on:** phases 13, 14 and 15. **Integrator duty:** owns `pirewall/runtime/core.py` and `pirewall/ipc/dispatcher.py` for the RPC wiring.

## Goal
One script brings the v2 stack up correctly in every mode, refuses unsafe states, and records a manifest. When this phase is done, **v2.0 is deployable**: kernel guards plus anti-spoofing plus adaptive sets, driven by the v1 pipeline.

## Deliverables
1. **`scripts/deployment/pirewall-start` v2**, exactly as PLAN_v3 §6 specifies.
   - **Flags:** `--engine v1|v2`, `--guards`, `--guard-input`, `--guard-forward`, `--guard-raw`, `--data-mode live|scripted|mock`, `--panic`, `--lab-victim up|down`, `--manifest PATH`. Keep `--check`, `--dry-run`, `--no-portal` and `--skip-nft`.
   - **Preflight refusals,** each with an actionable message and exit code 2. Refuse when:
     - `nftables.service` is enabled and its conf contains `flush ruleset`
     - IPv6 is enabled on the LAN interface
     - the config needs migration
     - the admin MAC is missing
     - the model artifact hashes don't match their sidecars (skip this check for `--engine v2` with ML disabled)
   - **Preflight reports** (warnings only): the libnftables transport, whether `pirewall_native` is present and `HAS_PACKET_RING`, whether the lease file is readable, and chrony sync.
   - **Load order:** base → static → adaptive → seed bindings, `pi_addrs` and `allow_bound` → set guard verdicts → core → api → portal → `portal.nft`.
   - **Manifest** at `/var/lib/pirewall/manifest.json`, plus the `--manifest` copy. It records the git SHA and dirty flag, the config hash, model hashes, `nft --version`, `uname -r`, the guard modes, `enforcement_mode`, `pipeline.engine`, the `env` tag and a ruleset dump hash.
   - **`--panic`** deletes both pirewall tables, prints the exact restore command, and logs to journald.
   - **`--data-mode mock`** needs no root and runs no nft. It runs core with `capture.backend=replay` against `lab/mock/out/` (or `--pcap PATH`), uses the Fake firewall backend, and runs the API on 127.0.0.1. This mode never writes a `pi-*` env tag.
   - **`--data-mode scripted`** behaves like live, but sets `lab.env_tag = "pi-scripted"` and reminds the user to start `lab/benign/background.py` on client devices.
   - **`--lab-victim up|down`** is idempotent:
     - creates the `labvictim` netns with a veth `lab0` (address from `[lab]`, a routed /30)
     - starts sshd, nginx, iperf3 -s and a DNS responder inside it
     - loads a tiny `pirewall_lab` table that permits LAN→lab0 forwarding **only while it is up**
     - `down` removes all of it
2. **systemd.** Core gets `ReadOnlyPaths=/var/lib/NetworkManager` (for the lease file), and `pirewall-tmpfiles.conf` gets entries for the new state. Add a `pirewall-crashloop-alert.service`, triggered through `OnFailure=` on core, that emits a Wazuh/syslog CRITICAL. Remember that the guards keep running.
3. **`configure.py`** collects the admin MAC (offered from `ip neigh` and ARP candidates; a human confirms), the LAN interface MAC and Pi addresses, and optional static bindings. It also writes the `[guards]`, `[antispoof]` and `[lab]` sections.
4. **`.pth` installer.** `scripts/deployment/install_nftables_pth.sh` links the system `python3-nftables` package into the uv venv and verifies the import.
5. **RPC wiring:** `get_guard_modes`, `set_guard_mode`, `panic`, `list_offenders`, `list_bindings` and `get_engine_stats`. Serve them from snapshots, outside the core RPC lock. Add an API route plus a minimal control-panel panel: guard modes with an observe/enforce toggle (admin only, with re-auth for enforce), offenders, bindings, and a panic button with confirmation.
6. **Docs.** `docs/SETUP.md` v2 section and a `setup-new-network.md` delta (new steps: install python3-nftables, run the `.pth` installer, configure MACs, disable `nftables.service`, `--check`, then bring-up), plus a troubleshooting entry for panic recovery.

## Tests
- A bash test harness using `--dry-run` that asserts the command order for every mode.
- Preflight refusal cases, simulated through env overrides or fixture files.
- `--data-mode mock` brings core and api up as a non-root user in CI and processes a mock pcap end to end.
- Lab victim up/down idempotency (netns tier, root only).
- RPC/API auth tests for the new routes.

## Non-goals
No new detectors (phase 17), no lab harness (phase 18).

## Definition of done
- All suites green.
- `pirewall-start --check` runs cleanly on a dev machine in mock mode.
- PROGRESS marks **v2.0 deployable** (Implemented/Tested/Mocked). Environment-dependent: the RUNBOOK H1–H3 and H10 steps.

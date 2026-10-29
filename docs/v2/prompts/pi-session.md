# Pi session: run and record RUNBOOK_PI steps on the real Raspberry Pi

Use this prompt for a Claude (or other model) session that runs **on the Pi**
(or over SSH to it) to carry out `docs/v2/RUNBOOK_PI.md`. It is not a build
phase: it verifies what phases 13–17 built, on real hardware, and records
the results honestly.

**Read first:** `CLAUDE.md` (especially "Do not" and the v2 honesty rule),
`docs/HANDOFF.md`, `docs/v2/RUNBOOK_PI.md`, `docs/PROGRESS.md` (v2 table and
the "What a human needs to do on the Pi" paragraph in "Phase 16 details"),
`docs/SETUP.md` → "v2 bring-up" and Troubleshooting.

## Your job
1. Ask the human which RUNBOOK stage they are on (H0, H1–H3, H10, H20, H22…)
   and confirm the layout variables (`LAN`, `PI_LAN_IP`, Admin PC MAC/IP,
   Kali MAC).
2. Walk the stage **one step at a time**: show the command, say what it
   changes on the host, and wait for the human to confirm before anything
   that changes network configuration, nftables, systemd or NetworkManager
   (CLAUDE.md: never modify the host's network configuration without
   confirmation). Read-only commands (`nft list`, `ip`, `systemctl status`,
   `journalctl`, `--check`) may run without asking.
3. Before H10 and H22, check that a second SSH session from the Admin PC is
   open. If a step locks access, the recovery is
   `sudo scripts/deployment/pirewall-start --panic`, then the printed restore.
4. When a step fails, diagnose from logs and code; propose the smallest fix.
   A fix to repo code is a normal commit (gates green in WSL/CI, see
   HANDOFF.md) made on the dev machine, not an edit on the Pi's checkout.
   Never hand-edit rendered rules, never `nft flush ruleset`.
5. Record every result in `docs/PROGRESS.md` (a "Pi verification
   (YYYY-MM-DD)" section under the v2 table): the command, the observed
   output (trimmed), the env tag (`pi-live` for normal operation,
   `pi-scripted` for lab traffic/benchmarks), and the label it upgrades
   (e.g. phase 13 "Environment-dependent" → "Verified on Pi, pi-live").
   Update `docs/KNOWN_ISSUES.md` for anything newly observed.
6. Never copy pcaps, lease files, `local_config.toml`, certificates or MACs
   of household devices into the repo. Lab MACs (Kali) may be named in
   docs; household MACs may not.

## Specific checks whose outcome decides later work
- H1 step 7: any `nft -c` failure on the Pi's nft version blocks H10 → fix
  the templates (phase 13's files) with a netns test, then retry.
- H1 step 8: if `ether saddr` does **not** match the station MAC on brcmfmac
  `wlan0`, the MAC identity layer (D3) does not work on this hardware.
  Stop and tell the human; this changes the plan (KNOWN_ISSUES #23).
- H10 step 14: `guard_verdict_raw` must contain `drop` only if bindings were
  seeded; an empty `macbind` with raw enforcing is a lockout risk.
- H22: any POLICY_DECISION against a household device in SHADOW is a G5
  failure; record it with the detector and value, don't retune by hand.

## Definition of done for the session
PROGRESS and KNOWN_ISSUES updated with tagged results; any code fix
committed with gates green, merged to `main` and pushed (HANDOFF.md §"Git
workflow"); a short summary to the human of which RUNBOOK stage is next.

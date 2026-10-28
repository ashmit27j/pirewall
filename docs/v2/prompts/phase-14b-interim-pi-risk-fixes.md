# Phase 14b (interim): close four live risks on today's v1 Pi

**Read first:**
- `CLAUDE.md` (v2 section)
- `docs/ADDENDUM_4.md` D4 (ML ceiling) and D5 (failure)
- `docs/KNOWN_ISSUES.md` #1, #2, #23
- `docs/PROGRESS.md` "Phase 14 details" (deviations 5 and 6)
- `pirewall/engine/{scoring,threat,decision}.py`, `pirewall/runtime/pipeline.py`
- `pirewall/runtime/core.py` (`_revert_ruleset_if_failing_open`)
- `pirewall/firewall/manager.py` (`revert_to_base`, `fail_open_shutdown`)
- `pirewall/config/models.py` (`ThreatConfig`, `AntispoofConfig`, `PirewallConfig`)
- `pirewall/core/bindings.py` (`parse_leases`)
- `scripts/deployment/{pirewall-start,configure.py,discovery.py,migrate_config.py}`
- `deploy/firewall/portal.nft.template`

**Depends on:** phase 14. **Runs before:** phases 15 and 16.

**Ownership deviation (approved by the human, 2026-10-28).** This batch edits
`pirewall/runtime/core.py` and `scripts/deployment/pirewall-start`, which
V2_CONTRACTS §12 assigns to phase 16. Every change here is small and must be
recorded as a deviation in PROGRESS so phase 16 builds on it rather than
redoing it. It also overrides KNOWN_ISSUES #1's "deliberately not done"
note for the duration of the interim ML cap.

## Goal
The Pi runs the v1 pipeline today with a model known to be confidently
wrong on this network, a shutdown path that switches the guards off, a
hardcoded lease-file path that portal sign-in now depends on, and a manual
nft migration step. Close all four without pulling phase 15 or 16 forward.

## Deliverables
1. **Fail-open shutdown keeps the guards (audit #17).**
   - `CoreDaemon` calls `FirewallManager.fail_open_shutdown`, not
     `revert_to_base`, on a clean `fail_open` stop.
   - With a set backend, call it even when the manager tracks no active
     rule, because elements from a previous run may still be in the sets.
   - Without a set backend, behaviour is unchanged (`fail_open_shutdown`
     already falls back to `revert_to_base`).
   - Update the module docstring.
2. **Interim ML ceiling on v1 (D4 applied to v1; KNOWN_ISSUES #1, #2).**
   - New `threat.ml_evidence_can_enforce: bool`, default **false**, in the
     model, `default_config.toml` and `configure.py`'s template.
   - When false, the *action* is chosen from the score of the
     non-ML evidence alone (behaviour plus protocol signature, through the
     same `score_evidence`). ML evidence (LightGBM and Isolation Forest) can
     still raise the reported score and level, for the UI and explanation,
     and can lift an ALLOW to MONITOR, but never to anything stronger.
   - The scoring layer computes this ceiling (`assess_threat`) and the
     decision layer applies it (`decide`), so neither layer re-implements
     the other.
   - A capped decision says so in its reason.
   - The Isolation Forest is not recalibrated: under the cap it cannot
     change an action. Calibrating `anomaly_score_threshold` needs a Pi
     baseline and is **Environment-dependent**.
3. **Lease-file path that cannot silently be wrong.**
   - `antispoof.lease_file`, when not set explicitly, is derived from
     `network.lan_interface`
     (`/var/lib/NetworkManager/dnsmasq-<lan_interface>.leases`). An explicit
     value still wins. `default_config.toml` and `migrate_config.py` stop
     writing a fixed path.
   - New `scripts/deployment/lease_check.py`, a testable pure function plus
     a CLI. Given the path, it checks the file exists and is readable. It
     reads `/proc/*/cmdline` to confirm a running dnsmasq is writing **that**
     file (`--dhcp-leasefile=`). It counts the leases `parse_leases` would
     accept, and never prints a hostname.
   - `pirewall-start` preflight runs the CLI. If the portal is enabled, a
     missing or unreadable file, or one no dnsmasq is writing, is a refusal
     (exit 2) with an actionable message. With the portal off it is a
     warning.
   - The preflight also checks that the `pirewall-core` user can read the
     file, when that user exists and the script runs as root.
   - `configure.py` offers LAN neighbours that have a MAC but no lease as
     `[[antispoof.static]]` candidates. A human confirms each one, and none
     is added by default. It also gains a `--static-bindings` mode that adds
     entries to an existing config without touching anything else.
4. **Portal table migration in `pirewall-start`.**
   - Before loading `portal.nft`, detect an existing `inet pirewall_portal`
     whose `authed` set is not `ipv4_addr . ether_addr`.
   - In that case, delete the table and load the new one **in one nft
     transaction**: syntax-check it first, and if the load fails the old
     table stays.
   - Say that this signs every client out once.
   - Under `--dry-run` without root the state is unknown, so warn rather
     than guess.

## Tests
- Daemon: a fail-open stop with a set backend leaves every guard's mode
  unchanged and flushes the adaptive sets. Run it with and without active
  rules.
- Decision: the KNOWN_ISSUES #1 case is capped at MONITOR. That is a "Bot"
  verdict plus an anomaly flag, alone and with page-load behaviour
  (diversity + repeated + frequency + burst).
- Decision: a scan plus ML still reaches RATE_LIMIT, behaviour-only results
  are unchanged, `ml_evidence_can_enforce = true` restores the old ladder,
  and a capped reason is explained.
- Config: the derived lease path follows `lan_interface`, and an explicit
  path wins.
- `lease_check`: the file is missing, unreadable, or written by no dnsmasq
  or by another one, the `-l`/`--dhcp-leasefile` spellings are handled, and
  hostnames never appear in the output.
- `configure`: neighbour MAC parsing, candidate filtering (leased, the Pi
  itself, group MACs) and `--static-bindings` file surgery, including
  replacing `static = []`, validated before writing.
- `pirewall-start` static checks: the lease check runs in preflight, and
  the portal migration is one checked transaction that runs before the
  plain load.

## Non-goals
No set-backend default (phase 16), no native hardening (phase 15), no
detector or threshold changes, no Pi run.

## Definition of done
`ruff check .`, `pyright` and `pytest` are clean, and the netns tier is not
regressed. PROGRESS gets a "Phase 14b" entry with honesty labels and the
ownership deviations. KNOWN_ISSUES #1, #2 and #23 are updated.

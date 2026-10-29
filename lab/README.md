# lab/ — the measurement harness (phase 18)

Every number pirewall reports comes out of a script in this directory, from
hashed inputs, with exactly one env tag, and can be re-checked later
(`verify_manifest.py`). Nothing here is imported by `pirewall/`
(`tests/unit/test_lab_import_graph.py`).

## Env tags and the no-mixing rule (ADDENDUM_4.md D7)

| Tag | Where the data came from |
|---|---|
| `pi-live` | the real Pi, real household traffic (benign capture, campaigns) |
| `pi-scripted` | the real Pi, traffic scripted on client devices (`benign/background.py`) |
| `sandbox` | the netns testbed, x86, WSL or Docker |
| `mock` | the synthetic pcaps of `mock/gen_pcaps.py` |

* Every output directory holds a `manifest.json` with **exactly one** tag.
* A script takes `--env-tag` only where no input manifest names it, never
  defaults to a `pi-*` tag, and refuses `pi-*` off a Pi (the same Pi check
  `pirewall-start` uses: `scripts.deployment.startup.SystemProbe`).
  `benign/background.py` is the one exception: it runs on client devices,
  and the Pi-side capture of its traffic carries the checked tag.
* `aggregate.py` refuses (exit 2, naming the runs) to put two tags, or dev
  and eval runs, in one table. `verify_manifest.py` refuses a sub-directory
  whose tag differs from its parent's.
* `mock` and `sandbox` numbers are regression evidence. They are never Pi
  results and never averaged with them (CLAUDE.md, v2 honesty rule).

## Where outputs go

Only under `lab/runs/`, `lab/data/`, a `lab/**/out/` directory (all
gitignored) or outside the repository. Scripts refuse anything else
(`common.check_output_location`). pcaps are never committed. A sealed
directory is never re-sealed: re-running makes a new directory.

## Layout

| Path | Runs on | What |
|---|---|---|
| `manifest.py` | anywhere (stdlib) | the one manifest schema: git SHA + dirty flag, config / thresholds / policy / model / ruleset hashes, engine, modes, tool versions, clock offsets, env tag, a SHA-256 per file |
| `verify_manifest.py` | anywhere | re-hash sealed directories; eval runs must have frozen thresholds |
| `seal.py` | Pi | seal a directory written by something else (a benign capture session) |
| `common.py` | — | env-tag guard, output locations, project hashes |
| `stats.py` | — | rule of three, exact Poisson CI, order-statistic median CI (stdlib) |
| `mock/gen_pcaps.py` | dev machine | `mock` data: seeded synthetic pcaps + ground truth (scapy, dev/lab only) |
| `mock/replay.py` | dev machine | replay them through a real pirewall-core (`pirewall-start --data-mode mock`) |
| `capture/benign_capture.sh` | Pi, root | `pi-live` benign capture: hourly pcaps, disk watchdog, consent, lab-MAC list |
| `benign/background.py` | client devices (stdlib) | `pi-scripted` benign traffic with ground truth; also the campaign's legit-client probe |
| `campaigns/{dev,eval}.toml` | — | campaign specs: attacks, N, seed, cooldown |
| `attacks/*.sh` | attacker host (Kali) | one script per attack; refuse any target outside the lab |
| `preflight.py` | Pi, root | is the Pi ready for a campaign? |
| `run_campaign.py` | Pi, root | randomised runs: capture, probe, trigger over SSH, poll, cool down, seal |
| `poll_state.py` | Pi (`pirewall-ipc` member) | read-only RPC polls of core |
| `capture.sh` | Pi, root | victim-side pcap for TTM (labvictim netns, or an NFLOG tap on the input path) |
| `victim_pcap.py` | — | read those pcaps (Ethernet / NFLOG / raw IPv4), stdlib |
| `score_run.py` | anywhere | TTD, TTM, mitigation effectiveness, collateral, admin API p95 per run |
| `aggregate.py` | anywhere | medians and CIs per attack and metric; JSON + CSV, tag in every row and file name |
| `meter_sim.py` | — | the static template's per-MAC meters, simulated (rates and bursts parsed from the rendered template) |
| `benign_fp.py` | dev machine or Pi | offline G5: D1 + meters + policy over clean benign hours; "forward guard may enforce: yes/no" |

## Data modes

### mock (no Pi)

```sh
uv sync --extra lab                                   # scapy: dev/lab only
uv run python lab/mock/gen_pcaps.py --seed 1          # lab/mock/out/*.pcap + ground_truth.jsonl (~45 MB)
scripts/deployment/pirewall-start --check --data-mode mock      # now passes without --pcap
uv run python lab/mock/replay.py --engine v2          # sealed run under lab/runs/, env tag mock
```

Same seed and scale give byte-identical files. `--scale 0.05` makes a
small set for quick tests.

**Read benign false positives from `benign_fp.py`.** A mock replay now
evaluates D1 on the capture clock (phase-18 hand-over fix), so `max` speed
no longer squeezes minutes of capture into one 10 s window; the driver
still exercises replay pacing and the production evaluation cooldown, so
it is a pipeline regression check. `benign_fp.py` runs on capture time and
is the false-positive measurement.

### pi-live: benign capture (RUNBOOK_PI.md step 5)

```sh
sudo bash lab/capture/benign_capture.sh start          # shows a consent banner, asks "yes"
sudo bash lab/capture/benign_capture.sh status
sudo bash lab/capture/benign_capture.sh stop           # stops tcpdump + watchdog, seals the session
```

* Each `start` opens `/var/lib/pirewall-lab/benign/<UTC stamp>/`, hourly
  `benign-%Y%m%d%H.pcap` files, `-s 128` (headers only), on
  `network.lan_interface` (or `--iface`).
* The watchdog stops the capture at 85% disk (`--threshold`) and logs why
  (`watchdog.log`, `logger -p user.crit`).
* Lab devices are **not** filtered at capture time. Keep
  `/var/lib/pirewall-lab/lab_macs.txt` up to date (`<mac> <note>` per
  line); `stop` copies it into the session manifest (`extra.lab_macs`).
* After a reboot the session was never sealed:
  `sudo bash lab/capture/benign_capture.sh seal <session dir>`.

Unattended, surviving logout (a transient unit; rerun after a reboot):

```sh
sudo systemd-run --unit=pirewall-benign-capture \
  bash "$PWD/lab/capture/benign_capture.sh" start --foreground --i-have-consent
sudo systemctl stop pirewall-benign-capture            # seals the session on the way out
```

or without systemd: `sudo nohup bash lab/capture/benign_capture.sh start --i-have-consent &`.
`--i-have-consent` is only for restarts after you have asked everyone.

### pi-scripted: client-device traffic

Copy `lab/` to the client (no venv needed, Python 3.12+), then:

```sh
python3 lab/benign/background.py --profile mixed --env-tag pi-scripted --duration 7200 \
    [--victim <labvictim ip>] [--mac <this device's LAN MAC>]
```

Profiles: `web`, `video`, `update`, `dns-burst`, `idle`, `iperf`, `mixed`.
Each segment writes one `benign:<profile>` window to the run's
`ground_truth.jsonl`. Keep the client's clock synced.

## Campaigns (RUNBOOK_PI.md H24–H41)

On the **attacker host**: copy `lab/` over (`scp -r lab kali@<kali>:lab`).
Install hping3, nmap, masscan, hydra, slowhttptest, dsniff (arpspoof),
isc-dhcp-client. Every script prints `TOOL_VERSION=` lines (recorded in the
run manifest) and refuses (exit 2) unless the target is the Pi's LAN
address, inside `[lab] victim_network`, or an explicit `--lab-target`
inside `network.protected_network`; scans take `--scan-net` of at most a
/24 inside those. Try any of them with `--dry-run` first.

On the **Pi**:

```sh
sudo scripts/deployment/pirewall-start --lab-victim up
sudo uv run python lab/preflight.py --host kali@<kali-ip> [--host <legit client>]
sudo uv run python lab/run_campaign.py lab/campaigns/dev.toml \
    --attacker kali@<kali-ip> --attacker-ip <kali LAN ip> --attacker-mac <kali LAN mac> \
    --param neighbour_ip=<a bound household IP> --param attacker_iface=<kali LAN iface> \
    --param wordlist=<wordlist path on kali> \
    [--legit-client user@<laptop> --legit-kind wifi] --dry-run      # then without --dry-run
uv run python lab/score_run.py lab/runs/<stamp>-dev/*/
uv run python lab/aggregate.py lab/runs/<stamp>-dev --out lab/runs/<stamp>-dev-aggregate
```

* The run order is a pure function of the campaign `seed`.
* Between runs the campaign **only polls** until core shows no live
  RATE_LIMIT/BLOCK rule and no offender for `cooldown_quiet_polls` polls; it
  never flushes a set and never uses the kill switch. If the sets do not
  drain in `cooldown_timeout_seconds` it stops.
* The env tag comes from `pirewall-start`'s manifest
  (`/var/lib/pirewall/manifest.json`), never from a flag.
* `eval.toml` (campaign #2) refuses to start unless the D1 thresholds file
  is `frozen = true` (`fit_d1_thresholds.py --freeze`, H35). Every eval run
  records the thresholds and policy-table hashes.
* Victim-side capture: `--side forward` runs tcpdump inside `labvictim`;
  `--side input` loads a lab-only tap table (`inet pirewall_lab_tap`,
  input hook, priority 150, after every pirewall input chain) that NFLOGs
  what the Pi accepted, and deletes it on `stop`.

## Offline G5 (RUNBOOK_PI.md step 24)

```sh
uv run python -m scripts.dataset.pcap_to_flows ~/benign/<session> --out ~/flows-benign \
    --config config/local_config.toml --continuous --env-tag pi-live
uv run python lab/benign_fp.py ~/flows-benign --out lab/runs/g5-<date> --pcaps ~/benign/<session> \
    --config config/local_config.toml --capture-manifest ~/benign/<session> \
    [--ground-truth lab/runs/<campaign>/*/ground_truth.jsonl] [--leases <lease file copy>]
```

It prints `forward guard may enforce: yes|no — <reason>`. "yes" needs
`pi-live` data, the meters simulated, at least `--min-device-hours` (24)
clean device-hours, and with the forward guard enforcing: no forward meter
trip, no forward backstop hit, no enforce action against a clean device.
It never changes a guard; flipping it stays the human's step
(`pirewall-start --guard-forward enforce`).

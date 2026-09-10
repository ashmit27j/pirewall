# Known issues and outstanding work

Everything currently known to be wrong, unverified, or deliberately deferred,
with the evidence behind each claim. Written to be picked up cold: each item
says what is wrong, how it was observed, what it costs, and what fixing it
would involve.

Status labels follow `CLAUDE.md`'s honesty rules. **Observed** means it was
seen on real hardware and the evidence is quoted. **Reasoned** means it
follows from the code but has not been triggered. **Deferred** means it is a
deliberate choice with a stated reason, not an oversight.

Last reviewed: **2026-09-10**, after the first real client session and the
move to a new uplink network.

---

## Priority summary

| # | Issue | Severity | Status |
|---|---|---|---|
| 1 | ML models misclassify ordinary browsing as attacks | High | Observed |
| 2 | Isolation Forest flags benign traffic as anomalous | High | Observed |
| 3 | Behaviour thresholds still tuned for a quiet network | Medium | Observed |
| 4 | Demo portal accounts are live on this deployment | High | Observed |
| 5 | Enforcement is `assisted` without the recommended SHADOW soak | Medium | Fixed |
| 6 | Wazuh and Netdata integrations never verified end to end | Medium | Fixed |
| 7 | Portal serves plaintext HTTP | Medium | Deferred |
| 8 | Portal sessions do not survive a core restart | Low | Deferred |
| 9 | `make_certs.sh` writes only one SAN | Low | Observed |
| 10 | Runtime allowlist additions are not persisted | Medium | Fixed |
| 11 | `AF_PACKET`, `nft` and systemd paths remain partly unverified | Medium | Deferred |
| 12 | Dashboard JS is checked by a scanner, not a parser | Low | Deferred |
| 13 | An unmerged branch predates this work | Low | Fixed |
| 14 | `capture_stats.packets_seen` did not move during a live check | Low | Observed |
| 15 | `pirewall-api` cannot write its own log file | Low | Observed |
| 16 | Moving the Pi to a new network silently staleness-rots the config | Medium | Fixed |
| 17 | `security.session_timeout_seconds` is read by nothing | Low | Observed |
| 18 | A TLS-only port answers plaintext HTTP with a bare teardown | Low | Observed |
| 19 | Some tests depend on the host's real network addressing | Low | Observed |
| 20 | Real floods/scans are detected but never scored above LOW | High | Observed |
| 21 | A flood evicts the bounded history buffers within seconds | Medium | Observed |
| 22 | Restart button can't be built as `sudo` + sudoers under `NoNewPrivileges` | Low | Blocked |

---

## 1. The ML models misclassify ordinary browsing as attacks

**Status: Observed.** From the running daemon during the first real client
session:

```
192.168.100.78 -> 104.26.12.204 (Cloudflare)  'Bot'         99.99974%
192.168.100.78 -> 23.227.38.74  (Shopify)     'Bot'         99.99992%
192.168.100.78 -> 20.202.170.5  (Microsoft)   'FTP-Patator' 99.99551%
```

All three were a phone loading a shopping site. This is the CICIDS2017
generalisation gap `docs/ML_DATA_AUDIT.md` already describes: the model's
reported test-set precision (0.9927) does not transfer to this network's
traffic. The confidence is not merely high, it is saturated — the model is
not uncertain, it is confidently wrong, so raising
`known_attack_confidence_threshold` cannot help.

**Cost.** At `known_attack_weight = 60`, one such classification plus an
anomaly flag reaches exactly `high_threshold` (75) → `RATE_LIMIT`. That is
bounded — it no longer reaches BLOCK, and in `assisted` mode a
high-confidence BLOCK queues for approval — but it still throttles innocent
traffic.

**What fixing it involves.** Retraining on traffic captured from this
network, which is the spec §34 attack-lab exercise: capture a labelled
baseline of normal use, run the documented attacks against a test host,
retrain, and re-evaluate. Environment-dependent, and the only real fix.

**Deliberately not done:** lowering `known_attack_weight` to hide it. That
would move a model problem into a tuning constant and make the weights stop
meaning what `pirewall/engine/scoring.py` documents them to mean.

## 2. Isolation Forest flags benign traffic as anomalous

**Status: Observed.** Every non-ALLOW decision in the session carried
`anomaly_evidence.is_anomaly = True`, with scores between -0.04 and -0.26
against `anomaly_score_threshold = 0.0`. Ordinary HTTPS to a CDN is not
anomalous; the model was trained on a different network's traffic.

`docs/PROGRESS.md` already records this as "documented, not fixed" and
explicitly declines to change `anomaly_weight` or `anomaly_score_threshold`
without data to justify a new value. That decision still stands — but the
data now exists to revisit it, because a real session's score distribution
has been observed.

**What fixing it involves.** Either retraining alongside item 1, or setting
`anomaly_score_threshold` from a measured baseline of this network rather
than from the model's default. The latter is cheap and honest if the
baseline is captured properly and the chosen value is recorded with the
evidence.

## 3. Behaviour thresholds are still tuned for a quiet network

**Status: Observed, one sub-cause fixed (2026-09-10).** Two of the six
behavioural patterns were fixed after the first session (`SCANNING` now
counts ports per destination, and `REPEATED_FAILURES` now requires an
unanswered TCP SYN). The rest still fire on ordinary browsing:

| Threshold | Value | Observed on one phone loading one page |
|---|---|---|
| `destination_diversity_threshold` | 15 | **91 distinct destinations** |
| `repeated_connections_threshold` | 20 | trips on any busy page |
| `high_frequency_per_second_threshold` | 2.0 | a page load far exceeds this |
| `burst_count_threshold` | 10 in 5 s | a page load far exceeds this |

A modern web page opens dozens of connections to dozens of CDN, analytics
and font hosts. Fifteen destinations is what a single page costs, not what a
scanner does.

**Cost.** Each pattern adds `behavior_weight / 9` ≈ 2.8 points, so four
patterns is ~11 points — not enough alone, but enough to push a
misclassified flow over a threshold. They also satisfy the evidence-maturity
gate's path (b), which is the gate's whole purpose.

**Investigated this session: is "new device" the trigger, per the user's
hypothesis, or a distinct amplifier on top of this same issue?** Reading
`pirewall/detection/behavior.py`'s `SourceBehaviorState` (no live device was
connected this session to capture a first-minute-vs-later comparison — this
finding is **Reasoned** from the code, not **Observed** from a live
capture) found a real, distinct, previously-unrecorded defect in
`HIGH_FREQUENCY` specifically: its rate was `state.connection_count /
(last_seen - first_seen)` — a *lifetime* average, not a current rate. A
source `BehaviorAnalyzer` has just started tracking (a genuinely new
device, or *any* existing device re-tracked after `pirewall-core` restarts
or its LRU state is evicted) has a tiny `(last_seen - first_seen)`, so its
first burst of connections — ordinary for a device that just joined Wi-Fi —
produces an artificially inflated rate. The identical instantaneous burst
from a long-tracked source gets diluted away by its own history and never
trips this signal at all, regardless of how it's tuned — backward for
security, since an established source becomes harder to flag over time,
not easier.

**Conclusion: "new device" is not an independent root cause** requiring its
own bypass/grace-period mechanism (the mitigation the user proposed, and
evaluated rather than implemented — see below). It is this pre-existing
issue's effect made *more visible* on new devices, for two compounding
reasons: (a) `HIGH_FREQUENCY`'s dilution bug specifically protects
long-tracked sources from a threshold that is already too low for everyone
(the "not enough evidence" side of this same table), so a fresh source hits
the exact same too-low threshold with none of that accidental cover; and
(b) a device that just joined Wi-Fi characteristically opens *more*
simultaneous connections than steady browsing (OS update checks,
push-notification registration, several apps syncing at once), making the
already-too-low threshold even easier to cross.

**Fixed:** `HIGH_FREQUENCY`'s rate is now measured over
`state.recent_connection_times` (already bounded by
`recent_connections_window`, the same deque `BURST` reads) instead of the
source's entire tracked lifetime — `pirewall/detection/behavior.py`'s new
`_recent_frequency()`. This does **not** change
`high_frequency_per_second_threshold`'s value (still whatever's
configured, no data existed this session to justify a new number) — it
makes the existing threshold apply consistently regardless of how long a
source has been tracked, rather than only to freshly-tracked ones.
**Tested**: `test_a_long_tracked_source_is_judged_on_its_current_burst_not_diluted_by_history`
in `tests/unit/test_behavior.py`, confirmed to fail against the pre-fix
code first. This is expected to make long-tracked sources trip
`HIGH_FREQUENCY` on their own ordinary bursts too, which the shadow log
should now show — that is the point: it exposes the true extent of this
table's problem rather than half-masking it for whichever sources happen
to have history.

**Evaluated, not implemented: a per-device grace period.** The user's
proposed mitigation — relax or bypass the decision engine for a device's
initial communication window, continuing to log/collect evidence but not
act on it — was considered against this session's own instruction to
confirm it addresses the actual root cause before adopting it. Given the
finding above, a grace period would not have fixed anything: the dilution
bug it would be working around is now fixed directly, and a device-age
bypass would still have left `destination_diversity_threshold`,
`repeated_connections_threshold` and `burst_count_threshold` exactly as
easy to trip for a new device as for an old one (none of those three are
first-seen-dependent — they are cumulative counts or genuine sliding
windows, so age never explains their false positives). Adopting an
age-based bypass on top of an already-identified formula bug would also
have created exactly the security hole this session's own instructions
warned against: a window where a genuinely malicious first connection gets
less scrutiny, for a benefit ("new" devices misbehave) this investigation
did not actually find to be true.

**Still open, unchanged this session** (no measured baseline exists to set
new values without guessing, per this document's existing discipline):
`destination_diversity_threshold`, `repeated_connections_threshold`, and
`burst_count_threshold` are still absolute per-deployment constants, all
still too low for a modern web page load, new device or old. **What fixing
them involves** remains what this section already said: values set from a
measured baseline (the SHADOW soak now running, per item 5, is exactly
that baseline-gathering window), and ideally made rate-based per source
compared against that source's own recent history — the same principle
just applied to `HIGH_FREQUENCY` above — rather than one absolute constant
for every deployment.

## 4. Demo portal accounts are live on this deployment

**Status: Observed.** `demo-alice` … `demo-erin` still exist, with the
passwords published in `docs/SETUP.md` and in this repository.

```sh
for u in demo-alice demo-bob demo-carol demo-dave demo-erin; do
  sudo -u pirewall-core uv run python -m scripts.deployment.portal_users remove "$u"
done
```

Anyone who has read the repository can join the protected network until this
is done. pirewall says so at every core startup, on the sign-in page, and on
the control panel — those warnings are working as intended and should be
believed.

## 5. Enforcement is `assisted` without the recommended SHADOW soak

**Status: Resolved as a deliberate operating policy (2026-09-10).**
`firewall.enforcement_mode` was moved to `"shadow"` earlier this session
(to run items 1–3's detection-code changes and the Step 5 attack-lab
without anything getting live-BLOCKed mid-edit) and has now been moved
back to `"assisted"` at the user's explicit direction, who confirmed this
is deliberate standing policy, not an oversight: **`assisted` is the
normal operating mode; `shadow` is a failsafe/manually-triggered state,
not something to leave running as a background soak.**

That policy is already exactly how the code behaves, independent of this
config value — nothing needed changing beyond restoring the value itself:

- **The kill-switch is "the button"** — `FirewallManager.revert_to_base`
  (ADDENDUM.md A8, `pirewall/firewall/manager.py`) sets
  `enforcement_mode = SHADOW` and removes every active adaptive rule,
  already wired to the dashboard's kill-switch control.
- **Fail-open already falls into that same state automatically** —
  `CoreDaemon._revert_ruleset_if_failing_open` (ADDENDUM.md A6,
  `pirewall/runtime/core.py`) calls that identical `revert_to_base` on any
  `pirewall-core` shutdown while `failure.mode = fail_open` (the default).

ADDENDUM.md A1's one-to-two-week SHADOW soak recommendation was not run
under this policy — that tradeoff (assisted's live enforcement now, versus
a full pre-enforcement observation window) is the user's own informed
call, made with items 1–3's measured false-positive rate and item 20's
measured false-negative gap both already known at the time of the
decision, not made in ignorance of them.

## 6. Wazuh and Netdata integrations were never verified end to end

**Status: Fixed (2026-09-10).** Both are enabled in config and pointed at
the Admin PC. Original baseline:

```
nc -zv 192.168.101.2 514    -> timeout
nc -zuv 192.168.101.2 8125  -> timeout
```

**Netdata: fully working end to end.** The Admin PC already had a native
Netdata install; its `[statsd]` config bound `udp:localhost` only. The user
changed it to `bind to = udp:0.0.0.0:8125` and restarted the service.
Confirmed: `ss -lunp` on the Admin PC now shows `0.0.0.0:8125`,
`pirewall-core` logs zero Netdata forwarding failures since the restart
(previously constant), and `GET /api/v1/charts` on the Netdata API lists
18 real `statsd_pirewall.*` charts (cpu/memory, packet rate/drops, flow
creation/expiration rate, inference count/latency, detection/block/rule
counts, rule-rejection, api/capture/firewall health, adaptive-rule-budget
fraction) — every metric §33 defines, actually arriving.

**Wazuh: already running, and now fully working end to end too.** It
turned out the Admin PC already had a full Wazuh stack (manager, indexer,
dashboard, Docker Compose, `wazuh/wazuh-manager:4.14.7`) running for
several days — this session's earlier RAM-budget concern and decision to
timebox installing it was moot once checked directly. The actual gap was
narrower: the manager published `514/udp` only (pirewall forwards over
**TCP**), and its `ossec.conf` had no syslog collector configured at all
(only the default `1514/tcp secure` agent-enrollment listener). The user:

1. Added a `<remote>` block (`connection=syslog`, `port=514`,
   `protocol=tcp`, `allowed-ips=192.168.101.0/24`) to the manager's live
   `ossec.conf` inside the container (persists in its named volume).
2. Added `"514:514/tcp"` to `docker-compose.yml`'s manager service and ran
   `docker compose up -d wazuh.manager` to publish it.
3. Restarted the Wazuh process (`wazuh-control restart`) to load the new
   collector.

Confirmed both directions: `nc -zv 192.168.101.2 514` succeeds; `docker
port` shows `514/tcp -> 0.0.0.0:514`; the manager's own log shows
`wazuh-remoted: INFO: Remote syslog allowed from: '192.168.101.0/24'` and
`Listening on port 514/TCP (syslog)`; and `pirewall-core` logs zero Wazuh
forwarding failures since (previously logged one on every single startup
and every event, for the life of this deployment). **A security event
pirewall generates has reached a SIEM for the first time.**

Not verified further this session: whether Wazuh's ruleset has (or needs)
a decoder for pirewall's raw-JSON-over-syslog message format so events
become properly classified alerts rather than merely received,
unclassified log lines — the transport gap this item tracked is closed;
message *parsing* on the Wazuh side is a separate, not-yet-investigated
question.

`setup-new-network.md` §8.3–8.4 has the install procedure for both, with
and without Docker, for a future deployment starting from nothing.

## 7. The captive portal serves plaintext HTTP

**Status: Deferred** — see ADDENDUM_3.md C5 for the full reasoning. A
self-signed certificate breaks OS captive-portal detection and trains users
to click through certificate warnings, so every mainstream portal does this.
The consequence is real and stated rather than hidden: **portal credentials
cross the LAN in the clear.**

A deployment needing confidential LAN authentication should terminate it at
the radio (802.1X / WPA-Enterprise), not by putting a warning-generating
certificate in front of this page.

## 8. Portal sessions do not survive a `pirewall-core` restart

**Status: Deferred.** Sessions live in memory, mirroring pirewall-api's own
`SessionStore`. A restart signs every LAN client out, and
`PortalService.reconcile()` deliberately revokes their kernel grants so the
two views cannot disagree.

This is the safe direction to fail, and a restart is rare. Persisting
sessions would mean writing session tokens to disk, which is a meaningfully
larger security surface for a convenience gain. Worth revisiting only if
restarts turn out to be frequent in practice.

## 9. `make_certs.sh` writes only one SAN

**Status: Observed.** It accepts a single IP. A three-interface deployment
where the Admin PC connects on a different address than the LAN needs both,
and the script cannot express that — `setup-new-network.md` §5.2 works around
it with a hand-written `openssl` command.

Small, self-contained fix: accept additional addresses as extra arguments and
join them into the `subjectAltName` extension.

Related, and already fixed on this box: the certificate deployed before
2026-09-10 had **no SAN at all**, only `CN=pirewall`, so strict verification
failed outright. Any deployment predating that should regenerate.

## 10. Runtime allowlist additions are not persisted

**Status: Fixed (2026-09-10).** `POST /api/v1/allowlist` used to mutate
`FirewallManager`'s in-memory list only — `config.firewall.allowlist` is
re-read at startup, so every allowlist entry added through the control
panel was silently lost on the next restart, for the mechanism that is
supposed to outrank every adaptive rule unconditionally (ADDENDUM.md A2).
An operator who allowlisted a printer, restarted for an unrelated reason,
and then watched that printer get blocked had no way to connect the two
events.

Fixed the second way this document already named: a separate state file
the config seeds, mirroring the exact single-writer pattern portal
accounts already used (ADDENDUM_3.md C3) rather than giving `pirewall-api`
write access to `config/local_config.toml`.

- New `pirewall/firewall/allowlist_store.py` — `AllowlistStore`, same
  temp-file-then-`os.replace` write discipline, `0600` mode, as
  `pirewall.portal.store.PortalUserStore`. Only `pirewall-core` ever opens
  it; already covered by the existing `deploy/systemd/pirewall-core.service`
  `ReadWritePaths=.../var/lib/pirewall` and
  `pirewall-portal.service`'s `InaccessiblePaths=/var/lib/pirewall` — no
  deployment/systemd changes needed, the file lives alongside
  `portal_users.json` in a directory already locked down correctly.
- New `firewall.allowlist_store_path` config field (default
  `/var/lib/pirewall/allowlist.json`).
- `FirewallManager` takes an optional `allowlist_store` — `None` (every
  existing caller, including every test that doesn't care) keeps the old
  in-memory-only behavior exactly. When given one (wired in
  `CoreDaemon.__init__`), `add_allowlist_entry`/`remove_allowlist_entry`
  read/write through it, and startup seeds the in-memory list from
  `config.firewall.allowlist` (the static, deployment-declared entries)
  **union** the store's persisted entries (runtime-added ones). Removing a
  config-seeded entry is a no-op against the store (it was never there) —
  it reappears on the next restart, same as always; only runtime-added
  entries are this item's persistence concern, and those now survive.

**Tested**: `tests/unit/test_allowlist_store.py` (7 cases: persistence
across a fresh store instance, overwrite-by-id, permissions, missing
parent directory) and `tests/unit/test_allowlist_persistence.py` (4 cases:
a runtime-added entry surviving a simulated restart, removal persisting,
a config-seeded entry correctly *not* removed from the store, and
`allowlist_store=None` behaving exactly as before). 916 passed; `ruff
check .` and `pyright --strict` clean.

## 11. `AF_PACKET`, `nft` and systemd paths remain partly unverified

**Status: Deferred**, and partly resolved further this session. As of this
deployment the following *are* exercised for real on the Pi: `nft` rule
loading, the adaptive backend creating and populating its table, both
`AF_UNIX` RPC sockets with their group ownership, systemd supervision of
all three units, and the crash-loop limiter actually firing.

**`AFPacketCapture` under sustained load: now Observed (2026-09-10)**, via
the attack-lab benchmark (`benchmarks/2026-09-10-attack-lab/REPORT.md`). A
~10,000 pkt/s `hping3` SYN flood for 15s produced `packets_seen=19,695`
against `packets_dropped=297,595` — **roughly 94% of the flood dropped** at
the kernel/ring-buffer level before reaching pirewall's own pipeline. A
~8,900 pkt/s UDP flood showed the same shape (~77% dropped). The Pi's
hardware is the bottleneck, confirmed real rather than assumed; what
survived capture was still enough for the behavioral layer to flag every
attack (see #20 for what happened to the score once flagged).
`pirewall-core`/`pirewall-api`/`pirewall-portal` stayed `active` throughout
both floods — no crash, no watchdog intervention, load average recovered.

Still unverified: `NftablesBackend` rule *removal* under contention, and
the watchdog actually reaping a hung process — nothing in this session's
traffic exercised either (enforcement stayed in `shadow`, and the daemon
never hung).

`docs/PROGRESS.md` carries the per-phase labels.

## 12. Dashboard JavaScript is checked by a scanner, not a parser

**Status: Deferred.** `tests/unit/test_dashboard_javascript.py` scans the
emitted script for raw newlines inside string literals and for unbalanced
brackets, because no JS engine is available in this environment and adding
one would exceed `CLAUDE.md`'s dependency list.

It catches the fault that shipped — a Python `\n` becoming a real newline
inside a JS string, which silently disabled every control on the page — and
its regex-literal handling uses a heuristic that is exact for the JS this
project emits. It is not a substitute for a real parse. If `node` is ever
available on a CI host, `node --check` on the emitted block is strictly
better and should replace the scanner.

## 13. An unmerged branch predates this work

**Status: Fixed (2026-09-10).** `fix/ap-uplink-and-detection-false-positives`
at `d32a6b2` — "four false-positive/self-lockout defects from the first AP
deployment" — reviewed this session against `main` and against `c88f724`
(which landed after the branch and independently fixed one of its four
issues). Outcome per defect:

1. **Heartbleed false-positive on ordinary HTTPS** — `c88f724` already
   fixed the "checks only `payload[0]==24`" root cause on `main`, but
   neither `main` nor the branch's *own* fix caught a second, distinct bug:
   the length comparison was judged against `len(fragment)` (whatever bytes
   happened to be captured in *this* TCP segment) rather than the record's
   own declared length, so a large, entirely ordinary TLS record split
   across segments could still false-match. Cherry-picked just that guard
   (record must be complete within the segment before being judged at all)
   onto `main`'s current detector, keeping `main`'s existing
   `_LEGAL_HEARTBEAT_TYPES` check that the branch's version had dropped.
   New regression test confirmed to fail against the pre-fix code first.
2. **Rules naming the Pi's own address passed safety validation** — not
   covered by `c88f724` at all. Cherry-picked whole:
   `pirewall/firewall/local_addresses.py` (reads `/proc/net/fib_trie` for
   every address the host actually holds, stdlib-only, TTL-cached,
   degrades to empty on any error) plus `validator.py`'s safety-stage
   changes (rejects a candidate naming one of the host's own addresses,
   and rejects any candidate touching a non-unicast address at all —
   unspecified, broadcast, multicast, loopback, link-local, reserved).
   Both files' branch tests (`test_local_addresses.py`,
   `test_validator.py`'s six new cases) applied unchanged and pass.
3. **DHCP `0.0.0.0`/broadcast traffic became flows** — not covered by
   `c88f724`. Cherry-picked whole: `is_routable_unicast()` in
   `pirewall/flow/aggregator.py`, filtering non-unicast source/destination
   addresses at the pipeline's single entry point, plus its
   `protected_network`-aware subnet-broadcast check, wired into
   `CoreDaemon`'s `FlowAggregator` construction. Branch's
   `test_flow_aggregator.py` additions applied unchanged and pass.
4. **ARP reported as a malformed `CAPTURE_ERROR`** — already fixed on
   `main` by `c88f724`'s `UnsupportedProtocolError` (the branch's version
   is the same fix under the name `UnsupportedFrameError`, dropping the
   "counted, never reported" behavior `c88f724` chose to keep). Discarded;
   `main`'s version stands.

`docs/FIELD_FIXES.md` (branch-only) was reviewed and not imported — it
documents host NetworkManager/nftables changes made by hand on a network
topology this deployment has since moved off twice (see item 16), so it is
historical record rather than actionable content; `setup-new-network.md`
and this document already carry the current state.

Applying items 2–3 surfaced one test that depended on this machine's real
address (item 19), fixed at the point of failure. Branch deleted
(`git branch -D fix/ap-uplink-and-detection-false-positives`) — everything
useful in it is on `main` now, or was superseded.

## 14. `capture_stats.packets_seen` did not move during a live check

**Status: Confirmed (2026-09-10).** After a restart,
`get_capture_stats()` reported `packets_seen=0` while the daemon was
demonstrably parsing packets — the log showed it processing ARP frames from
traffic generated seconds earlier.

The metrics-tick-lag hypothesis is now confirmed rather than assumed: during
the attack-lab benchmark (`benchmarks/2026-09-10-attack-lab/`), querying
`get_capture_stats()` immediately after a burst of traffic showed no
change in `packets_seen`; re-querying 3 seconds later showed it had
advanced by 2,138. The counter is genuinely only sampled on the metrics
tick, not incremented and read live — a real operator reading the control
panel's Network panel right after a burst (or a restart) will see a stale
number for up to one tick interval, which is cosmetic rather than a
capture fault. Whether frames that fail to parse are excluded from the
counter (this document's second open question) was not specifically
isolated this session.

---

## 15. `pirewall-api` cannot write its own log file

**Status: Observed.** From `journalctl -u pirewall-api` on every start:

```
pirewall: could not open log file /var/log/pirewall/api.log
([Errno 30] Read-only file system: '/var/log/pirewall/api.log'); logging to stderr only
```

`pirewall/api/__main__.py` logs into `<[logging] log_dir>/api.log`, which is
the shared `/var/log/pirewall` owned `pirewall-core:pirewall-ipc`. But
`deploy/systemd/pirewall-api.service` has `ProtectSystem=strict` and grants
`ReadWritePaths=/run/pirewall /var/log/pirewall-api` — a *different*
directory, which exists and is owned by `pirewall-api` but is never written
to. So the path the unit prepared and the path the code uses do not agree,
and the code falls back to stderr.

**Cost.** Low: systemd captures stderr, so the lines are in the journal and
nothing is lost. What is lost is the `RotatingFileHandler` bound by
`logging.max_bytes`/`backup_count`, and the assumption in the docs that
`/var/log/pirewall/api.log` exists.

**Fixing it** means choosing which half is right. The per-process directory
matches how `pirewall-portal` already works (`[portal] log_dir =
/var/log/pirewall-portal`), so the consistent fix is an api-specific
`log_dir` in config rather than widening the api unit's write access to
core's log directory — that widening would be the one change that hands the
API process write access inside core's own directory, which the A4 split
exists to avoid.

---

## 16. Moving the Pi to a new network silently staleness-rots the config

**Status: Fixed (2026-09-10).** After the Pi moved to a new uplink,
`config/local_config.toml` still read `upstream_gateway = "192.168.1.1"`
while the live default route was via `10.253.156.97`. Nothing failed
loudly — the value is not used for routing. By this session, the network
had moved *again* (the AP's own upstream changed to `192.168.1.1` via
`wlan1`, coincidentally reusing the earlier value) — confirming this drifts
more than once and needed the structural fix, not another hand edit.

**Cost.** `_validate_safety` in `pirewall/firewall/validator.py` protects
`upstream_gateway` from being blocked, precisely because a /32 against the
gateway is an internet outage that the `0.0.0.0/0` check does not catch.
Pointed at a stale address, that guard protects an address no longer on the
network **and leaves the real gateway unprotected** — an adaptive rule
against the real live gateway would have validated cleanly and cut the
Pi's own uplink. `--check-config` accepts any syntactically valid address,
so nothing would have caught it before this session.

**Fixed two ways:**
- **Immediate:** `config/local_config.toml`'s `upstream_gateway` corrected
  to `192.168.1.1`, matching the live default route observed via `ip -j
  route` at the time of this fix.
- **Structural:** `pirewall/core/network_drift.py` (new), called from
  `CoreDaemon.start()` on every `pirewall-core` startup. It compares
  `network.upstream_gateway`/`wan_interface` against the kernel's live
  default route (parsed from `/proc/net/route`, stdlib-only — no
  `subprocess`, so it doesn't reach for `scripts/deployment/discovery.py`,
  which is setup-time tooling outside the `pirewall` package on purpose),
  and `pirewall_lan_ip`/`protected_network` against `lan_interface`'s
  actual address (via `SIOCGIFADDR`/`SIOCGIFNETMASK`). `admin.admin_pc_ip`
  and any of `integration.wazuh_host`/`netdata_host` that parse as a literal
  IPv4 (not a hostname) are checked against every subnet the host has an
  address on, across all interfaces — not just WAN/LAN, since the Admin PC
  segment is a third interface (`eth0` on this deployment). Every mismatch
  emits a `SYSTEM_WARNING` `SecurityEvent` rather than refusing to start,
  since the uplink can legitimately be down at boot.

**Tested**: `tests/unit/test_network_drift.py`, 8 cases covering exact
match (no warnings), gateway-only drift, interface drift, LAN
IP/network drift, stale Admin PC IP, integration hosts skipped when
disabled or when they're hostnames rather than IPv4 literals, and a
missing default route reported without crashing. Full suite: 886 passed;
`ruff check .` and `pyright --strict` clean.

---

## 17. `security.session_timeout_seconds` is read by nothing

**Status: Observed (2026-09-10).** `grep -rn "security\.session_timeout_seconds"
pirewall/ tests/` returns nothing. The field is declared in
`SecurityConfig` and set in both `config/default_config.toml` and the
deployment's `local_config.toml`, but no code path reads it. The admin
session lifetime is governed solely by
`authentication.token_expiry_seconds`, which `pirewall/api/app.py:129`
hands to `SessionStore`.

**Cost.** An operator who wants longer admin sessions finds a setting whose
name says exactly that, changes it, and observes no effect — the failure is
silent and the config gives no hint which of the two similarly-named keys is
live. Found while raising session lifetimes at the user's request.

**Fixing it** means deciding what the field is *for*. Either delete it (a
config-schema change that breaks any existing file setting it, so it needs a
deprecation pass in the loader) or give it the meaning its name implies —
an idle timeout distinct from `token_expiry_seconds`'s absolute lifetime,
which is a real feature rather than a rename. Documented in place for now:
`config/default_config.toml` carries a comment pointing at the key that
actually works.

---

## 18. A TLS-only port answers plaintext HTTP with a bare teardown

**Status: Observed (2026-09-10).** Captured on the wire from the Admin PC:

```
192.168.101.2.58112 > 192.168.101.1.8443: Flags [P.], length 351
    GET /control-panel HTTP/1.1
    Host: 192.168.101.1:8443
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) ... Firefox/140.0
192.168.101.1.8443 > 192.168.101.2.58112: Flags [F.]      ← FIN, no data
```

A browser given `192.168.101.1:8443` with no scheme defaults to `http://`.
uvicorn's TLS layer sees non-TLS bytes and closes the connection without
data, which Firefox reports as "the connection was reset" — indistinguishable
from a firewall drop or a dead service. The same symptom appears for a client
that cannot negotiate `security.min_tls_version` (TLS 1.3 here), because the
server closes without sending a `protocol_version` alert.

**Cost.** Pure diagnosis time, and it is expensive: it sent this session
looking at nftables, listeners, certificates and the admin-PC gate, all of
which were healthy. The access log is no help either — neither case ever
reaches the application, so a working server shows no trace of the failed
attempt.

**Fixing it** is awkward and may not be worth it. One port cannot serve both
schemes, so a redirect needs a second listener on plain HTTP, which is a new
attack surface on the management interface for a usability win. The cheaper
mitigation is documentation: `setup-new-network.md` and `docs/SETUP.md`
should give the panel URL with an explicit `https://` every time it appears,
and this symptom belongs in a troubleshooting section so the next person
recognises it in one step instead of thirty.

---

## 19. Tests that submit a candidate rule without pinning `local_addresses` depend on the host's real addressing

**Status: Observed (2026-09-10), one instance fixed.**
`pirewall/firewall/local_addresses.py` (cherry-picked this session from
`fix/ap-uplink-and-detection-false-positives`, see item 13) made the safety
validation stage consult the *real* kernel's own address table by default
(`cached_local_addresses()`) whenever a caller doesn't inject
`local_addresses` explicitly — which is exactly right for
`pirewall-core` in production, but means any test that calls
`FirewallManager.submit_candidate` (which does not expose a way to inject
`local_addresses`) without choosing addresses known to be unclaimed
anywhere is silently host-dependent.

Hit immediately:
`tests/integration/test_addendum_lifecycle.py::test_kill_switch_removes_active_rules_and_sets_shadow_mode`
used destinations `192.168.1.20`–`192.168.1.22/32`; on this Pi, `wlan1`
(the WAN interface) currently holds `192.168.1.22` as its live DHCP lease,
so the safety stage correctly rejected that one candidate as unsafe and the
test failed — not a bug in the check, but a test that happened to name the
machine's own address. Fixed by moving the test to `203.0.113.0/24` (RFC
5737 TEST-NET-3, reserved for documentation and never a real host's
address).

**Cost.** Low today (one test, one obvious fix), but the same shape can
recur in any future test that exercises the real validation path with a
private-range address, and it will only surface on whichever machine
happens to hold that address at the time — a classic "passes in CI, fails
on the Pi" (or vice versa) flake.

**Fixing it properly** would mean giving `FirewallManager`/
`submit_candidate` an explicit (optional) `local_addresses` parameter the
way `validate_candidate_rule` already has, so tests can pin
`LocalAddresses(host=frozenset(), broadcast=frozenset())` the same way
`tests/unit/test_validator.py` does — not attempted this session, since it
touches `FirewallManager`'s public signature and the only concrete failure
found was one test, fixed at the point of failure. Worth doing before this
bites again.

## 20. Real floods/scans are detected but never scored above LOW

**Status: Observed (2026-09-10)**, from the attack-lab benchmark
(`benchmarks/2026-09-10-attack-lab/REPORT.md`). Five attack types were run
against the Pi's own LAN address in `shadow` mode: a `nmap -sS` port scan,
a `hping3` SYN flood (~10,000 pkt/s), a `hping3` UDP flood (~8,900 pkt/s),
a slow brute-force login, and 200 concurrent small HTTP requests. **The
behavioral layer correctly flagged every one of the first, second, fourth
and fifth as anomalous** (`scanning`, `high_frequency`, `burst`,
`repeated_failures`, `slow_rate_dos` all fired appropriately), and the
third was caught by the portal's own independent login throttle. But
**none of them ever reached a `threat_score` above 33.3/100 —
`ThreatLevel.LOW` throughout, never MEDIUM, HIGH, or CRITICAL.**

**Cost.** This is the mirror image of items 1–3 (false positives on benign
traffic): here the pipeline correctly identifies genuinely malicious
volumetric traffic as anomalous and then **fails to act on its own
finding**. In `active` enforcement mode, none of these four attack types
would have been rate-limited or blocked — only logged. A real, sustained
SYN flood or port scan against this deployment today would pass through
enforcement entirely unaffected.

**Why.** `known_evidence` never corroborated any of these — LightGBM's
`predicted_class` stayed `BENIGN` even for the port scan at 99.99%
confidence (the same CICIDS2017 generalization gap items 1–2 already
document, just in the opposite direction: here the model *should* have
flagged an attack and didn't). `pirewall/engine/scoring.py`'s current
weighting depends on `known_evidence` corroboration to reach a score high
enough to act; a behavior-only signal, however many patterns it fires,
tops out well below the levels current default thresholds would act on.

**Not fixed this session** — out of scope for Step 2's false-positive
investigation, and a real threshold/weight change here needs the same
measured-baseline discipline items 1–3 already established, this time
using attack-lab data (which now exists, in this benchmark's raw output)
rather than production browsing data. **What fixing it involves**: either
retraining/extending the ML model on labeled scan/flood traffic so
`known_evidence` can corroborate a real attack (the same spec §34
attack-lab exercise items 1–2 call for, now with real captured attack
traffic to use), or deliberately reweighting `pirewall/engine/scoring.py`
so a behavior-only signal with multiple concurrent patterns (as observed
here — up to six firing at once) can reach RATE_LIMIT on its own, with the
evidence-maturity gate (ADDENDUM_2.md B3) still guarding against a single
weak signal doing so alone.

## 21. A flood evicts the bounded history buffers within seconds

**Status: Observed (2026-09-10)**, from the same attack-lab benchmark.
`pirewall-core`'s in-memory history (`list_flows`/`list_detections`/
`list_threats`, each capped at 500 entries — the same bounded-state
discipline as the event history item 12 already describes) exists so the
control panel and any RPC client can see recent activity without unbounded
memory growth. Under the SYN flood (~10,000 pkt/s for 15s), **all 500
entries in every one of those three lists were flood traffic within
seconds** — the port-scan detection records captured moments earlier
(saved to this benchmark's `1-nmap-scan-state.json` before the flood, for
comparison) were completely gone from live state by the time the flood
ended, evicted by the flood's own volume.

**Cost.** At the time this was measured, Wazuh forwarding was still broken
(item 6), so there was no external copy of anything evicted this way — a
flood large enough to matter could also erase the record of everything
that happened immediately before it, from the one place (the control
panel / RPC state) an operator without a working SIEM has to look.

**Item 6 is now fixed** (Wazuh forwarding confirmed working end to end,
same session, after this finding), which closes the specific gap above —
a durable external copy exists now, before `pirewall-core`'s own bounded
buffers evict anything. This item is left open regardless: it was never
really about Wazuh being down, only exposed by it. **The bounded
in-memory history itself is still evicted by a large enough flood** —
Wazuh being up means events matched *before* the eviction reached it, but
an operator relying only on the control panel (or a SIEM query slow
enough to lag behind, or Wazuh being down again for some other reason)
still loses the same window. This is a genuine forensic gap distinct from
item 12's dashboard-only description: it affects every RPC consumer, not
just the rendered page.

**What fixing it involves**, beyond item 6's now-real mitigation:
persisting the bounded buffers to disk (a larger change, and a new place
secrets-adjacent data would live, so not undertaken lightly), or raising
the cap (only delays the same problem at a larger flood size). Not
attempted this session; recorded here because it was directly observed,
not merely theorized.

## 22. A "restart pirewall" control-panel button cannot be built as `sudo` + a sudoers grant

**Status: Blocked, not attempted (2026-09-10).** Attempted per this
session's phase prompt (Step 4b): a `POST /api/v1/system/restart` route,
protected the same way every other write route is
(`require_session`/`require_admin_pc`), shelling out via a narrow explicit
`sudoers` grant restricted to exactly one command
(`scripts/deployment/pirewall-start`), mirroring how CAP_NET_RAW/
CAP_NET_ADMIN are scoped narrowly to `pirewall-core` and zero for
`pirewall-api` (ADDENDUM.md A4).

**`sudo` cannot run at all under `pirewall-api.service`'s existing
`NoNewPrivileges=true`.** Confirmed empirically, not assumed:

```
$ sudo systemd-run --property=NoNewPrivileges=true --property=User=pirewall-api \
    --wait --pipe sudo -n true
sudo: The "no new privileges" flag is set, which prevents sudo from running as root.
```

`NoNewPrivileges` blocks any privilege-gaining `execve` for the process
and everything it spawns — that includes `sudo`'s own setuid-root
mechanism, unconditionally, regardless of any `sudoers` entry. The design
as specified cannot work without touching that hardening, and the phase
prompt's own instruction was explicit: stop and report rather than
improvise a broader privilege grant to make it fit. Brought back to the
user rather than decided unilaterally; the user chose to skip this item
for the session rather than pick a workaround under time pressure.

**Real options, for whenever this is picked up:**

1. **D-Bus/`systemd` unit activation instead of `sudo`.** `pirewall-api`
   asks `systemd` (pid 1, already privileged) over its D-Bus socket to
   start one specific, narrowly-scoped unit
   (e.g. `pirewall-restart.service`, `Type=oneshot`, running as root,
   `ExecStart=scripts/deployment/pirewall-start`) — a `polkit` rule
   restricts *which* caller may start *which* unit, so the grant stays as
   narrow as the `sudoers` line would have been, and `NoNewPrivileges`
   never has to move: no privilege escalation happens inside
   `pirewall-api`'s own process at all, it only sends a message.
   `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` already permits the
   D-Bus socket's address family, so this is plausible without loosening
   that either — but it is new infrastructure (a helper unit + a `polkit`
   rule + a D-Bus client call), not a one-line config change, and needs
   its own careful review before trusting it.
2. **Drop `NoNewPrivileges=true` from `pirewall-api.service`.** Matches
   the originally-specified design exactly, but reopens the setuid/
   capability-gaining attack surface A4's process split deliberately
   closed for this specific process — explicitly the path this session
   was told not to take without asking first, and the user did not choose
   it when asked.
3. **Skip the feature.** What happened this session.

Not implemented; no code changed for this item.

## Not issues

Recorded because they look like problems and are not:

* **Loading the portal gate does not disconnect anyone immediately.**
  Existing connections match `established,related` and keep flowing until
  conntrack ages them out; only new connections are gated. Severing in-flight
  transfers to enforce a policy that was not in place when they started would
  be worse. See ADDENDUM_3.md C2.
* **`nat-masquerade.nft` is not loaded on this deployment.** NetworkManager's
  shared mode already masquerades the protected network. Loading both leaves
  two masquerade rules where one is wanted. `pirewall-start` detects this.
* **IPv6 is not gated by the portal.** It does not need to be here:
  `ipv6.method` is `disabled` on the AP connection, so protected clients get
  no IPv6 at all. This *would* become a real bypass if IPv6 were ever enabled
  on the LAN side — v1 is IPv4-only for the adaptive pipeline (ADDENDUM.md
  A5), so a client with IPv6 connectivity would be unanalysed and ungated.
  Check this before enabling IPv6 on the AP.

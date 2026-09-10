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
| 5 | Enforcement is `assisted` without the recommended SHADOW soak | Medium | Observed |
| 6 | Wazuh and Netdata integrations never verified end to end | Medium | Observed |
| 7 | Portal serves plaintext HTTP | Medium | Deferred |
| 8 | Portal sessions do not survive a core restart | Low | Deferred |
| 9 | `make_certs.sh` writes only one SAN | Low | Observed |
| 10 | Runtime allowlist additions are not persisted | Medium | Reasoned |
| 11 | `AF_PACKET`, `nft` and systemd paths remain partly unverified | Medium | Deferred |
| 12 | Dashboard JS is checked by a scanner, not a parser | Low | Deferred |
| 13 | An unmerged branch predates this work | Low | Observed |
| 14 | `capture_stats.packets_seen` did not move during a live check | Low | Observed |
| 15 | `pirewall-api` cannot write its own log file | Low | Observed |
| 16 | Moving the Pi to a new network silently staleness-rots the config | Medium | Observed |
| 17 | `security.session_timeout_seconds` is read by nothing | Low | Observed |
| 18 | A TLS-only port answers plaintext HTTP with a bare teardown | Low | Observed |

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

**Status: Observed.** Two of the six behavioural patterns were fixed after
the first session (`SCANNING` now counts ports per destination, and
`REPEATED_FAILURES` now requires an unanswered TCP SYN). The rest still fire
on ordinary browsing:

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

**What fixing it involves.** These are per-deployment values and should be
set from a measured baseline, not guessed. The principled version is to make
the diversity and frequency signals *rate-based per source* and compare
against that source's own recent history, so a busy device is judged against
its own normal rather than an absolute constant. That is a design change,
not a tuning change.

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

**Status: Observed.** `firewall.enforcement_mode = "assisted"`.
ADDENDUM.md A1 recommends one to two weeks in `shadow` first, reviewing the
shadow log, before enforcing anything. That soak has not happened, and items
1–3 are exactly what it exists to surface.

Given the false-positive rate now measured, `shadow` is the honest setting
until items 1–3 are addressed. Enforcing on a detection stack known to
misclassify ordinary browsing means throttling real users to no benefit.

## 6. Wazuh and Netdata integrations were never verified end to end

**Status: Observed.** Both are enabled in config and pointed at the Admin PC,
and neither is listening:

```
nc -zv 192.168.101.2 514    -> timeout
nc -zuv 192.168.101.2 8125  -> timeout
```

`pirewall-core` logs a forwarding failure for every event it tries to send.
The forwarder degrades correctly — it counts failures and re-reports
periodically rather than blocking the pipeline — so this is a missing
dependency, not a fault. But it means **no security event pirewall has ever
generated has reached a SIEM**, and the whole §32/§33 integration path is
unexercised outside its unit tests.

`setup-new-network.md` §8.3–8.4 has the install procedure for both, with and
without Docker.

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

**Status: Reasoned** (from the code; not triggered deliberately).
`POST /api/v1/allowlist` mutates `FirewallManager`'s in-memory list only.
`config.firewall.allowlist` is re-read at startup, so **every allowlist entry
added through the control panel is silently lost on the next restart** — and
the allowlist is the mechanism that is supposed to outrank every adaptive
rule unconditionally (ADDENDUM.md A2).

An operator who allowlists a printer, restarts for an unrelated reason, and
then watches that printer get blocked has no way to connect the two events.

Fixing it means deciding who owns the allowlist: the config file (in which
case the API must write back to it, atomically, the way
`scripts/deployment/configure.py` does) or a separate state file that the
config seeds. The first keeps one source of truth; the second avoids the API
process needing write access to config. Worth an ADDENDUM entry either way.

Portal accounts already solved the same problem — see ADDENDUM_3.md C3 for
the single-writer pattern to copy.

## 11. `AF_PACKET`, `nft` and systemd paths remain partly unverified

**Status: Deferred**, and partly resolved. As of this deployment the
following *are* exercised for real on the Pi: `nft` rule loading, the
adaptive backend creating and populating its table, both `AF_UNIX` RPC
sockets with their group ownership, systemd supervision of all three units,
and the crash-loop limiter actually firing.

Still unverified: `AFPacketCapture` under sustained load (drop counters,
promiscuous mode, kernel drop statistics), `NftablesBackend` rule *removal*
under contention, and the watchdog actually reaping a hung process.

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

**Status: Observed.** `fix/ap-uplink-and-detection-false-positives` at
`d32a6b2` — "four false-positive/self-lockout defects from the first AP
deployment". It has never been merged and its subject overlaps directly with
items 1–3. Review it before doing further false-positive work; some of it may
already be fixed, and some may still be needed.

## 14. `capture_stats.packets_seen` did not move during a live check

**Status: Observed, cause not established.** After a restart,
`get_capture_stats()` reported `packets_seen=0` while the daemon was
demonstrably parsing packets — the log showed it processing ARP frames from
traffic generated seconds earlier.

Most likely the counter is only sampled on the metrics tick and the read
raced it, in which case nothing is wrong except that a operator reading the
control panel's Network panel right after a restart sees a zero that is not
true. Worth confirming: if the counter is genuinely not incremented for
frames that fail to parse, the Network panel under-reports traffic, and
"packets seen" would not mean what an operator assumes.

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

**Status: Observed (2026-09-10).** After the Pi moved to a new uplink,
`config/local_config.toml` still read `upstream_gateway = "192.168.1.1"`
while the live default route was via `10.253.156.97`. Nothing failed
loudly — the value is not used for routing.

**Cost.** `_validate_safety` in `pirewall/firewall/validator.py` protects
`upstream_gateway` from being blocked, precisely because a /32 against the
gateway is an internet outage that the `0.0.0.0/0` check does not catch.
Pointed at a stale address, that guard protects an address no longer on the
network **and leaves the real gateway unprotected** — an adaptive rule
against `10.253.156.97` would have validated cleanly and cut the Pi's own
uplink. Fixed by hand this session; `--check-config` accepts either value,
so nothing would have caught it.

**Fixing it** means a startup cross-check: compare `upstream_gateway`
against the kernel's actual default route for `wan_interface`, and against
`pirewall_lan_ip`/`protected_network` for `lan_interface`, and emit a
`system_warning` event on a mismatch rather than refusing to start (the
uplink can legitimately be down at boot). `scripts/deployment/discovery.py`
already parses `ip -j route` and could supply the comparison. The same drift
applies to `[integration] wazuh_host`/`netdata_host` and `[admin]
admin_pc_ip`, which are all addresses on networks the Pi can be moved off.

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

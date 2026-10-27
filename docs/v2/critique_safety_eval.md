# Critic #4 — Safety, operability, and experiment design (review of PLAN_v0_draft.md)

Labels:
- **Verified**: run in this sandbox. The sandbox is Ubuntu 24.04, kernel 6.18, nft 1.0.9, root, in a netns+veth topology.
- **Reasoned**: follows from the code, the docs or how the kernel behaves, but was not run.

Sandbox experiments run for this review, all **Verified**:
1. An nft dynamic-set meter (`add @synmeter { ip saddr limit rate over 50/second burst 100 packets } add @offenders { ip saddr } drop`) loads, fires on an hping3 SYN flood, and fills `@offenders`.
2. The same meter **without** `drop` works as observe-only. Offenders are recorded and nothing is dropped.
3. A two-set anti-spoof works. Packets from an IP in `@bound_ips` whose `ip . ether` pair is not in `@ipmac` are dropped (spoof of 10.9.0.77 from another MAC: 1,804 packets dropped). Packets from unbound sources are dropped (`--rand-source`: 1,673 packets dropped). Legitimate traffic passes.
4. Comparing against a map as an rvalue (`ether saddr != ip saddr map @ipmac`) is a **syntax error in nft 1.0.9**. A one-MAC-per-IP map can't be enforced directly, so use the two-set design and have core replace bindings.
5. The tools are installable via apt: `iproute2 hping3 nmap tcpreplay tcpdump iperf3 dnsmasq`. Netns creation works.

---

## (a) False-positive lockouts and self-DoS: the top risks in v2

The v1 failure mode was "logs a lot, never acts". The v2 failure mode will be **"acts on the whole device, in-kernel, without the validator"**. That is a worse class of failure, so it needs harder guards.

| # | Risk | Label | Fix |
|---|---|---|---|
| A1 | **The forward-path UDP/ICMP packet-rate meters will throttle normal traffic.** QUIC/YouTube, video calls, cloud gaming and game consoles run hundreds to thousands of UDP packets per second per source. A per-source UDP pps meter on `forward` is a household outage generator. | Reasoned | Meter **new conntrack entries** (`ct state new`), never raw packets, on `forward`. Keep packet-rate meters only on `input`, for floods aimed at the Pi itself. Set thresholds from P99.9 of the benign capture, with a floor of 3–5× that value. |
| A2 | **The SYN/new-connection meter on forward collides with P2P and BitTorrent, Windows Delivery Optimization, download managers, browser cold starts and smart-TV CDN fan-out.** These easily reach 100+ new connections per second in bursts. | Reasoned | Default `forward` meters to **observe** mode (record offenders, don't drop). Change to enforce only after the benign capture shows the threshold is never crossed. Key the meter per `(saddr, daddr)` for floods and keep `saddr`-only for fan-out evidence. |
| A3 | **DNS bursts.** Phones waking from sleep, smart TVs and Chromecast discovery send bursts of dozens to hundreds of queries to the Pi's port 53 (input). | Reasoned | The `input` UDP-53 meter needs a measured threshold, plus a generous burst value. |
| A4 | **mDNS, SSDP and IGMP multicast** reach the Pi's `input` hook. The unbound-source anti-spoof rule would drop link-local or self-assigned (169.254/16) devices. | Reasoned | Exempt `ip daddr 224.0.0.0/4` and DHCP (`udp sport 68 dport 67`; tested) **before** anti-spoof. Document that 169.254 devices are not supported. |
| A5 | **A core restart or table reload empties `@bound_ips`/`@ipmac`, which is a full-LAN outage.** Every client becomes "unbound" and is dropped. This is the single most dangerous v2 failure. | Reasoned (follows directly from the tested rule) | (1) Core never deletes or recreates the table if it exists. It reconciles instead. (2) On load, seed bindings from the dnsmasq leases file **and** a static-bindings config. (3) If the leases file is unreadable, anti-spoof loads in **observe** mode, not drop mode (fail open). (4) Run a startup self-test that the admin path and at least one known lease pass. |
| A6 | **Static-IP devices, and devices whose MAC rotates** (iOS "rotating" private address, Windows per-network randomization), lose service. When a lease is reassigned, a stale `ip . mac` element lets the *old* device keep using the IP. | Reasoned | Core is the only writer of bindings. On a lease change it **deletes the old pair before adding the new one**, and on lease expiry it removes the binding. Static devices are declared in `[[antispoof.static]]`. |
| A7 | **dnsmasq `dhcp-script` → core RPC hands the script core's socket.** That socket includes the kill switch and rule mutation, so this is an A4/C1 privilege leak. | Reasoned | **Don't use dhcp-script.** Core polls or inotify-watches the leases file read-only. If a push is ever needed, it goes through a third, single-method socket. |
| A8 | **A source /32 BLOCK takes a whole device offline.** The v1 tuple rules only blocked one destination port. One false positive now costs a household member's connectivity, and "TTL doubles on repeat" turns a recurring false positive into a 1-hour lockout. | Reasoned | BLOCK always needs human approval in ASSISTED mode. In ACTIVE mode, only deterministic, high-certainty evidence may BLOCK. Escalation (doubling) requires **new independent evidence**, not re-triggering by the same detector. Keep the C4 block notice so the user knows why. Admin unblock is one click and also adds a temporary allowlist entry. |
| A9 | **Captive-portal probe storms.** An unauthenticated device retries rejected connections. The portal chain runs at -10 and rejects first, so `forward` meters at -5 never see those packets. Its connections to the portal on `input` (8080 / redirected 80) *are* metered, though. | Reasoned | Exempt the portal port on `input` from the new-connection meter, or give it its own higher threshold. Add a test: an unauthenticated client with 200 probes in 5 s must not land in `@offenders`. |
| A10 | **Admin PC, Pi and gateway.** The Admin PC is on eth0, so it is safe as long as every pirewall rule is `iifname "<LAN>"`. The Pi's own output is not filtered. WAN-ingress replies don't match LAN iif. | Reasoned | Make `iifname LAN` mandatory in the template (enforced by a test that parses the rendered ruleset). Add `ip saddr @infra4 accept` (Admin PC, Pi addresses, gateway) as the **first** rule of every pirewall chain, before allowlist and meters. |
| A11 | **Wi-Fi airtime.** A Wi-Fi attacker flooding at high pps consumes RF airtime. Kernel drops can't give legitimate Wi-Fi clients their throughput back. G1's ">80% throughput" target will fail for reasons outside the firewall. | Reasoned | Measure collateral damage on a **wired** legitimate client and separately on a Wi-Fi one. State in the paper that RF/L2 DoS is out of scope. |
| A12 | **Capture is still blinded under floods.** AF_PACKET/libpcap taps (`ptype_all`) run *before* netfilter, and before tc and nf `ingress`, so nft drops don't reduce what userland capture has to process. Only XDP comes earlier. | Reasoned (kernel RX path order) | Flood evidence must come from **kernel counters and the offender set**, not from userland flows. Report capture drop % separately; it isn't a mitigation failure. Use a BPF capture prefilter to shed load, or accept the blind window. |

### SHADOW-by-default and kernel enforcement

v1's A1 applies to *adaptive* rules. Always-on kernel drops that fire before any human review are a new category, and if they are on by default they break the *intent* of A1 ("observe before you can get locked out"). Proposed resolution (an ADDENDUM_4 item):

- **Kernel guard = static policy, not adaptive.** It is rendered from a template, reviewed and loaded like `base.nft`, and its thresholds are in config. It is not produced by ML or by the decision engine, so ML still "produces evidence, never commands".
- **Per-guard defaults:**
  - `input_guard = enforce`. It protects the Pi's own services, and the false-positive surface is small.
  - `forward_guard = observe`.
  - `antispoof = enforce`, but only if bindings were seeded successfully; otherwise `observe`.
  - The adaptive sets (`block4`/`ratelimit4`) follow `EnforcementMode` exactly as in v1. In SHADOW, core never writes elements.
- Switching guard modes = an atomic `nft -f` that flushes and reloads the chain. Observe-only is the same rule without `drop` (Verified).

### The kill switch needs two levels

- **Kill switch (A8, extended).** Set mode to SHADOW, flush `@block4`/`@ratelimit4`, switch `forward_guard` and `antispoof` to observe, record a per-element audit entry, and leave base + portal untouched. It runs through `FirewallManager`.
- **Panic.** `delete table inet pirewall`. That removes every pirewall-induced drop, including meters and anti-spoof, and leaves base and portal intact. It is available over RPC **and** as a documented one-liner for the console or SSH when core or the API is dead. Without it, an anti-spoof misconfiguration has no recovery path from the control panel.
- **Clean shutdown under `fail_open`.** v1 removed adaptive rules on clean shutdown. v2 must also flush `@block4`/`@ratelimit4`. A crash leaves elements in place until their timeout, which bounds an orphaned block to at most `max_ttl`. Document this as a deliberate change, and cap `max_ttl` at 1 h.

---

## (b) Keeping the v1 safety invariants once enforcement moves to sets and meters

| v1 invariant | How it breaks in v2 | How to keep it |
|---|---|---|
| **One authorized deploy path** (`FirewallManager` only) | Kernel meters write `@offenders` themselves, and dnsmasq writes bindings (A7). | Kernel-written sets are **evidence-only**. No rule reads `@offenders` to drop; the drop happens in the meter rule itself, which is static policy. `@block4`, `@ratelimit4`, `@bound_ips`, `@ipmac` and `@allow4` have exactly one writer: `FirewallManager` → backend. An import-graph test, plus a test asserting that no chain *reads* `@offenders` in a verdict rule. |
| **Validator chain in order** | "priority" and "conflict" lose their meaning with sets. Source /32 targets change what "broader than evidence" means. | Keep the stage order. Changes: **safety** gains a check against `@infra4` contents; **duplicate/conflict** checks whether an IP is in both sets (precedence: block4 > ratelimit4, and an upgrade = delete from ratelimit4 + add to block4 in one nft batch); **priority** becomes **escalation**, which allows an upgrade only with new independent evidence; **expiration** makes `timeout` mandatory on every element (`max_ttl` ≤ 3600 s); **rate cap** counts element insertions. |
| **Allowlist outranks everything** | Kernel meters act *before* core ever sees the allowlist. | `@allow4` is checked by the second rule (after `@infra4`) in every pirewall chain, *before* meters and anti-spoof. It is written by core from `AllowlistStore` and seeded from the rendered template. Test: flood from an allowlisted IP, and assert it never appears in `@offenders`, `@block4` or the drop counters. Document the trade-off: an allowlisted device has no flood protection. |
| **ML evidence ≠ commands** | The policy engine makes D3 alone "MONITOR" by convention. | Encode the policy table as data, with a test matrix (every combination of D1/D2/D3/kernel evidence → maximum action). Assert that `ML-only → ≤ MONITOR` and `anomaly-only → ≤ MONITOR`. |
| **Never auto-modify network configuration** | Anti-spoof and kernel guards are network config. | They are rendered templates loaded by `pirewall-start` / a human, as in v1. Core only adds and removes *elements*. |
| **Never block Admin PC, Pi, gateway, LAN, internet** | Kernel meters bypass the safety stage. | `@infra4` first-rule accept, plus `iifname LAN` on every rule (A10). Netns tests: flood from the Admin PC namespace (on a second interface) and from an address equal to the Pi or gateway. |

---

## (c) Attack-lab experiment design

### Topology problems to fix before running anything
1. **Intra-BSS traffic may never reach the Pi's IP stack** (Reasoned). In AP mode, Broadcom FullMAC (brcmfmac) can bridge client-to-client frames in firmware. A victim that is another Wi-Fi client could then be **invisible** to pirewall, and the result would be a silent false negative.
   - **Verify:** ping between two Wi-Fi clients while running `tcpdump -i wlan0` on the Pi.
   - **Fix:** `ap_isolate=1` in hostapd (verify brcmfmac honours it). That makes lateral client-to-client attacks *prevented by design* rather than detected. Say so in the paper.
2. **Separate victim host.** Put it on a routed segment, so attacks traverse `forward`. A USB-Ethernet adapter on the Pi with a laptop or second Pi behind it works. Run a second campaign against the Pi's own address for the `input` path. Victim services: sshd, nginx, a DNS responder and an iperf3 server.
3. **Wired legitimate client** (plus one Wi-Fi legitimate client) to measure collateral damage.
4. **Clock sync.** chrony on the Pi, attacker, victim and Admin PC. Record `chronyc tracking` offsets in the run manifest. TTD/TTM are meaningless without this.

### Ground truth
- The **attacker-side harness** records `t_start`/`t_end` for every attack in a `ground_truth.jsonl` (monotonic plus NTP wall-clock), along with the attacker's IP, MAC, tool, the exact argv and the offered rate.
- Ground truth is never derived from pirewall's own logs.
- A detection counts as a TP if it is attributed to the attacker IP or MAC within `[t_start, t_end + 30 s]`. Anything else is an FP.

### Metric definitions (put these verbatim in the paper)
- **TTD** = first pirewall event (≥ MONITOR) attributed to the attacker − `t_start`. If there is no event by `t_end + grace`, the run is *not detected*. It is reported as a miss count and never averaged in as a large number.
- **TTM** = first time the **victim-side** attack packet rate stays below 10% of the offered rate for 2 s − `t_start`. It is measured from victim pcap or counters, not from pirewall's claims. The `@block4`/`@offenders` insertion time (from the 1 s poller) is reported as a secondary figure.
- **Mitigation effectiveness** = 1 − (attack packets reaching the victim during `[t_start + TTM, t_end]`) / packets offered in that interval.
- **Collateral damage**: legitimate-client iperf3 TCP throughput and HTTP-fetch p95 latency during the attack, as a ratio of the pre-attack baseline (wired and Wi-Fi reported separately). Also the number of actions against non-attacker IPs.
- **FP per device-hour** on the **held-out** benign capture = alerts at each severity ÷ Σ(device active hours). A device is active in an hour if it had ≥1 flow in it. Report MONITOR and RATE_LIMIT/BLOCK separately, with a Poisson 95% CI. If there are zero events, report the rule-of-three upper bound 3/T. About 30 h × a few devices is a weak bound, so say so.
- **Pi health**: CPU, RSS, kernel capture drops and nft counter rates, every 1 s.
- **Repetitions**: N ≥ 5 per (attack, mode, variant). Randomize the order. Cool down until `@offenders`/`@block4` are empty, or flush via a *logged* harness command. Report mean, SD, min and max.

### Train/test separation of attack-lab data
If the same tool, parameters and day are used for both training and evaluation, the results are meaningless.
- Split by **run ID**.
- Evaluate on held-out **parameter variants** (other rates, port ranges, nmap timings) and on at least one **held-out attack family**.
- Use a different day, and ideally a different attacker device.
- Record the split in a manifest that the training script reads, so it can't silently use eval runs.

### Traceability and anti-fabrication (G7)
- Every run directory holds a `manifest.json`: git SHA and dirty flag, config SHA-256, model artifact SHA-256, the `nft -j list ruleset` dump, the enforcement and guard modes, tool versions, clock offsets, and the SHA-256 of every raw file.
- Results directories are append-only (`chattr +a`, or just never rewritten). A re-run produces a new directory.
- **Paper tables come only from `lab/aggregate.py` output** (CSV + LaTeX), generated by a Makefile target. Each cell's footnote or appendix row names a run directory and a JSON key. A CI or local check diffs the paper's tables against the aggregate output.
- No metric is ever typed by hand. Sandbox or netns numbers are tagged `env=sandbox` in the manifest, and `aggregate.py` refuses to mix them with `env=pi`.

### Harness scripts needed (CLI signatures)
```
lab/preflight.py        --config lab/lab.toml --out results/<ts>/        # clocks, versions, hashes, modes, ruleset dump → manifest.json; aborts on dirty tree unless --allow-dirty (recorded)
lab/run_campaign.py     --campaign lab/campaigns/<name>.toml --runs 5 --mode shadow|assisted|active
                        --guard-mode observe|enforce --order random --seed 42 --out results/<ts>/
lab/attacks/syn_flood.sh   --target IP --port P --rate PPS --duration S --spoof none|neighbor:IP|random
lab/attacks/udp_flood.sh   --target IP --port P --rate PPS --duration S --spoof ...
lab/attacks/icmp_flood.sh  --target IP --rate PPS --duration S
lab/attacks/portscan.sh    --target IP --ports 1-1000 --timing T2|T3|T4 --type sS|sT|sU
lab/attacks/bruteforce.sh  --target IP --service ssh|http|portal --rate RPS --duration S
lab/attacks/slowloris.sh   --target IP --port P --sockets N --duration S
lab/attacks/frame_neighbor.sh --victim-ip IP --target IP --duration S           # G4 spoof test
lab/benign/background.py   --profile web|video|update|mixed --duration S --out FILE   # legit load + collateral probes (iperf3, HTTP p95, DNS latency)
lab/poll_state.py       --api https://PI:8443 --interval 1 --out FILE.jsonl     # events, sets, counters, capture stats
lab/capture.sh          --iface wlan0,eth1 --snaplen 256 --out DIR --rotate 100M # Pi + victim side
lab/score_run.py        --run results/<ts>/<run-id>/ --grace 30                 # → metrics.json (TTD/TTM/effectiveness/collateral)
lab/benign_fp.py        --events FILE --windows benign_windows.jsonl --devices lab/devices.toml --out fp.json
lab/aggregate.py        results/<ts>/ --out results/<ts>/tables/ --format csv,latex
lab/verify_manifest.py  results/<ts>/                                           # recompute hashes, check env tags, fail loudly
```

---

## (d) Sandbox test strategy (no Pi)

What is available here is **Verified**: root, nft 1.0.9, netns, veth, hping3, nmap, tcpreplay, tcpdump, iperf3, dnsmasq. Caveats: the Pi runs Bookworm with nft ~1.0.6 and kernel 6.6/6.12, so rule syntax must be checked against those versions (Reasoned). veth is not brcmfmac. CPU numbers do not transfer.

- **Tier U (existing):** Fakes. Add the policy-matrix test and the set-semantics fake (timeouts, single writer).
- **Tier N (netns integration, `@pytest.mark.netns`, skipped unless root):**
  - Namespaces `attacker`, `legit`, `admin` (on a second veth, standing in for eth0), `router` (runs pirewall-core with the **real** `NftablesBackend` plus the rendered base, portal and v2 templates) and `victim` (behind a second router veth).
  - Assertions:
    - (1) SYN flood → attacker in `@offenders`; drop counters rise; legit iperf3 ≥ X% of baseline.
    - (2) Spoofing the legit IP from the attacker → dropped, and legit is *not* rate-limited (G4).
    - (3) `--rand-source` → unbound drop, and `@synmeter` stays small, which shows set-exhaustion protection.
    - (4) An allowlisted flooding IP never appears in any set.
    - (5) Admin namespace reachability during the flood.
    - (6) `kill -9` core → elements persist until their timeout; restart → bindings intact, with no LAN outage (A5).
    - (7) Kill switch → sets flushed and guards set to observe; panic → table gone; base and portal intact.
    - (8) Loading the template twice is idempotent.
    - (9) Unauthenticated portal probe storm → no offender (A9).
- **Tier R (replay):** tcpreplay of the Pi's benign capture into `router` at 1× and 5×, for false positives and throughput. Use `tcprewrite` to map IPs/MACs onto namespace addresses and seed bindings from the pcap's IP↔MAC pairs, otherwise anti-spoof drops everything. Sandbox replay numbers are for regression only and must never be reported as Pi results.

---

## (e) Honest scope statement for the paper (draft)

> Pirewall v2 is a host-level adaptive defense for a single Raspberry Pi 4 acting as a Wi-Fi access point for a small LAN. It mitigates volumetric floods, port scans and brute-force attempts originating from LAN clients, and blocks IP spoofing of other LAN clients, using static in-kernel nftables guards plus adaptive per-source sets driven by deterministic and ML evidence. It does not inspect payloads and does not see inside encrypted traffic. It does not defend against RF-layer attacks (jamming, deauthentication; mitigated only by 802.11w PMF) or MAC cloning by an attacker who holds the PSK. Client-to-client traffic is isolated at the AP rather than analysed. The design is IPv4-only, and it cannot restore airtime consumed by a Wi-Fi flood. The ML components were trained on a short (~30 h) capture of one network plus public data re-extracted with the same flow exporter. False-positive rates are bounded statistically over that capture and may not transfer to other networks. All reported results come from N scripted runs on real hardware, with raw data and manifests published.

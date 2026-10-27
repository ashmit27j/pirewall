# Critique #3: systems and feasibility review of PLAN_v0 (Pi 4 Wi-Fi AP)

Labels: **Verified** means I ran it in the sandbox (x86_64, kernel 6.18, nft 1.0.9, NFStream 6.6.0 / nDPI 5.x, Python 3.12). **Reported** means a third-party source says so. **Reasoned** means it follows from the code or docs but was not run. Anything marked Verified here still has to be re-checked on the Pi, which runs Bookworm with nft 1.0.6 and kernel 6.6 or 6.12.

## 0. The finding that changes the plan

**S0. On the onboard Wi-Fi, client-to-client traffic never reaches pirewall.** (Reported + Reasoned. This is a blocker for the threat model.)

The Pi 4's BCM43455 chip runs as FullMAC under brcmfmac, and its firmware bridges intra-BSS frames itself. RaspAP documents that `ap_isolate=1` "is not compatible" with the BCM43455 on the 3B+/4B: "clients will not be isolated from one another" (https://docs.raspap.com/features-insiders/ap-isolation/).

Consequences:

- When one LAN client attacks another (a scan, a brute force against an IoT device, ARP poisoning), the traffic never enters the Pi's netfilter hooks or its AF_PACKET taps.
- pirewall can neither see nor block lateral movement.
- v1's attack lab only ever targeted the Pi itself, which is consistent with this blind spot rather than evidence against it.

What v2 can cover is **client→Internet (forward)** and **client→Pi (input)**.

The fix for lateral traffic is a USB adapter on the mac80211 driver stack (e.g. MT7612U or MT7921AU) with `ap_isolate=1`, plus `net.ipv4.conf.<lan>.proxy_arp_pvlan=1` and `send_redirects=0`. Client-to-client traffic then hairpins through the Pi's `forward` chain, which also needs `iifname LAN oifname LAN` rules in `pirewall_base`. That route breaks mDNS and casting.

Within 42 h: either buy or borrow such an adapter on day 1, or write this down as a scope limit.

The test to confirm the blind spot on the real Pi:
1. Run `tcpdump -ni wlan0 host <B>` on the Pi.
2. Ping B from client A.
3. If tcpdump prints nothing, the blind spot is confirmed.

**Victim placement for the attack lab:** the victim host must sit on `eth0`, a USB-Ethernet adapter, or the WAN side. A second Wi-Fi client will not work.

## 1. nftables design

A working ruleset is in `/home/claude/plan/v2_ruleset_draft.nft`.

What I Verified in a veth/netns testbed, with an interface named `wlan0` and the full ruleset loaded:

- `nft -c` passes and the ruleset loads.
- **Per-element meters work.** The rule is `add @syn_meter { ether saddr limit rate over 200/second burst 400 packets } update @offenders { ether saddr . 1 }`. A 5,000-SYN burst from one MAC produced 4,594 drops, and `@offenders` was populated with a 120 s timeout.
- **Random-source floods are caught.** 5,000 SYNs with random spoofed in-subnet source IPs from one MAC were all metered, because the key is `ether saddr`, not the IP. This fixes v1's per-IP blindness (KNOWN_ISSUES #12).
- **Anti-spoofing works.** The rule is `ip saddr @bound4 ip saddr . ether saddr != @macbind drop`. All 100 of 100 packets spoofing a bound neighbour's IP were dropped.
- **Reload keeps state.** The idiom is to declare the table, flush the *chains*, then re-add the rules. A reload kept the `macbind` elements. PLAN_v0's implied `delete table` would wipe every block and binding on each `pirewall-start`.
- **`define VERDICT = drop` is a syntax error**, so a SHADOW/ACTIVE toggle cannot be done with a define. Instead, every meter hit does `jump meter_verdict`, which holds `drop` in active mode and is empty in shadow mode. Core can flip the mode atomically at runtime with `flush chain …; add rule … drop`. I Verified that in shadow mode, hits are counted and offenders exported. **PLAN_v0 has a gap here:** kernel meters would enforce even in SHADOW, which breaks A1.
- **Priorities.** The meters and anti-spoofing sit at prerouting `raw` (-300), which is *before conntrack*. That means floods cannot fill the conntrack table and break NAT for everyone. v1 had this problem (Reasoned): random-destination SYN floods each create a forward conntrack entry.
- **Chain order.**
  - Adaptive sets are at -5 on **both** `input` and `forward`.
  - The portal forward chain (-10) still runs first.
  - `pirewall_base` (input 0, forward 10, policy drop) is unchanged.
  - NM's `nm-shared-*` tables are not affected, because a drop anywhere is final.
  - Masquerade happens in postrouting, after all of these chains, so `ip saddr` is still the LAN address when these rules see it.
- **The IPv6 bypass (A5) is closed:** `meta nfproto ipv6 drop` on LAN ingress.
- **DNS has its own bucket** (100/s per MAC). The v1 UDP flood targeted :53. Under PLAN_v0's general 3,000/s UDP limit, dnsmasq would still have absorbed 3,000 qps.
- **A DHCP starvation brake** limits DHCP to 10/min per MAC.
  - NM shared mode runs dnsmasq with `--dhcp-lease-max=50`, and `chaddr` is client-chosen, so one associated client can exhaust the pool. This is Reasoned.
  - nft cannot compare `chaddr` with `ether saddr` because the right-hand side must be a constant or a set, so the brake only slows starvation down.
- **Meters do not reduce capture load.** AF_PACKET taps (`ptype_all`) run before netfilter, so a flood still reaches NFStream (Reasoned). Only XDP, including generic XDP, sheds load before the taps. The design rule follows: floods are the kernel's job, capture may drop under a flood, and that is fine.

Still open:

- The per-MAC identity assumption. On WPA2, the source address equals A2, which is bound to the PTK (Reasoned). But an insider who knows the PSK can re-associate with a new random MAC every ~2 s and evade `block_mac`. When the portal is enabled, block the **portal account** too.
- Benign phones rotate their MACs (iOS 18 "Rotating", Android non-persistent), so per-device baselines keyed by MAC will churn.
- The allowlist exempts devices from the meters, so a compromised allowlisted device can flood. That is a policy choice; write it down.
- `ratelimit_mac` limits *all* packets to 20/s, which is harsh for TCP. Consider limiting only `ct state new`.
- The thresholds (200 SYN/s, 3,000 UDP/s, 50 ICMP/s) are placeholders. Set them from the benign capture: take the per-MAC per-second max, multiply by a margin, and apply floors.
- Add ARP anti-spoofing in an `arp` family table, so a forged ARP whose sender IP doesn't match `macbind` is dropped. This protects only the Pi's own ARP cache.

## 2. Controlling nft from Python

Measured on x86 (Verified):

| Method | Rate |
|---|---|
| `nft -j -f -` subprocess | 3.1 ms per element (~320/s) |
| libnftables via `python3-nftables` ctypes | 0.21 ms per element (~4,900/s) |
| 1,000-element batch | 21.5 ms |
| Listing `@offenders` | 0.54 ms |

On the Pi, expect roughly 5–10× slower (Reasoned). That is still far above the A3 cap of 20 rules per minute, so update rate is not a bottleneck. v1's real costs were the linear chain and list-by-comment, which sets remove.

`python3-nftables` is a pure-Python ctypes wrapper over `libnftables.so.1`.
- Install with `apt install python3-nftables libnftables1` on Bookworm.
- The module lives in `/usr/lib/python3/dist-packages`. The uv 3.12 venv won't see it, so either add a `.pth` file or vendor the two `.py` files. It is pure Python and uses no ffi callbacks, so `MemoryDenyWriteExecute` is fine (Reasoned).
- Keep `NftablesBackend` as the only holder of the handle, and keep the Fake.
- Batch removals through set-element timeouts. **Blocks then expire in the kernel even if core is dead.** That is the right "fail-open in time" property.

## 3. NFStream

**Install** (Verified): 6.6.0 bundles libpcap and nDPI 5.x. Wheels exist for `manylinux_aarch64` cp312. It is a cffi API-mode `.abi3.so` with no callbacks.

**Not pure C** (Verified by reading the source): the per-packet loop (`capture_next` → `consume()` dict lookups) is Python. It gets parallelism from **multiple processes with PACKET_FANOUT** (`n_meters`, default CPUs−1).

**Throughput** (Verified on x86, 2.8 GHz Xeon, one meter, 400k-packet synthetic pcap):

| Configuration | Throughput |
|---|---|
| Plain | ~71k pkt/s |
| `statistical_analysis` | ~70k pkt/s |
| `statistical_analysis` + `splt=10` | ~64k pkt/s |

Pi 4 estimate (Reasoned, from typical single-thread gaps): **~12–18k pkt/s per meter**. That has to be measured on the Pi with the same pcap (`/tmp/claude-0/mkpcap.py`). Use `n_meters=2` and raise `CPUQuota` to about 250%, leaving one core for brcmfmac softirq and netfilter. Each spawned meter imports pandas and numpy, at about 60–100 MB each, which is tight against `MemoryMax=768M`.

**Expiry** (Verified): **NFStream does not end flows on FIN or RST.** A FIN-closed connection followed by a new SYN→RST on the same 5-tuple came out as **one 9-packet flow**, with `expiration_id=0` (idle).

Flows only expire on `idle_timeout` or `active_timeout`. Splitting on FIN/RST would need an NFPlugin `on_update`, which runs Python per packet. So:
- Detection latency for short flows is at least `idle_timeout`.
- Scans show up roughly `idle_timeout` seconds later.
- Fast-scan blocking has to come from the kernel or a separate SYN path.
- Training must use exactly the same timeouts.

**Accounting** (Verified): the default `accounting_mode=0` counts link-layer bytes (54 B for a bare TCP packet). Use `accounting_mode=1` (IP length) in **both** training and live, so Ethernet pcaps (CIC) and wlan0 captures agree, and snaplen does not affect byte counts (Reasoned).

**TLS:** the strings in `_lib_engine` show nDPI 5 with JA4 client and JA3S server. `client_fingerprint` is most likely JA4 (Reasoned, check on a real ClientHello). Snaplen matters: post-quantum hybrid ClientHellos (X25519MLKEM768) are about 1.8 KB and span two packets. **Training pcaps must use the same snaplen as live (1536)**. PLAN_v0's `tcpdump -s 256` would break nDPI features and create a fresh train/serve skew.

**systemd hardening breaks NFStream** (Verified): the unit has `SystemCallFilter=~@resources`, which turns `sched_setaffinity` into EPERM. NFStream's `set_affinity` error path has a format bug, `"...({err})".format(err)`, which raises **KeyError and kills the meter process**. I reproduced it directly. Fix: add a final `SystemCallFilter=sched_setaffinity sched_getaffinity` line to the unit, or patch `nfstream.utils.set_affinity` in a module imported before the meters spawn.

Other hardening needs:
- `AF_PACKET` and `AF_NETLINK` are already in `RestrictAddressFamilies`.
- `/dev/shm` stays writable under `ProtectSystem=strict`, which multiprocessing needs.
- `TasksMax` is fine.
- Watchdog pings must stay in the parent process.

**AP mode:** libpcap on `wlan0` in AP mode sees 802.3-converted frames, the same as v1 (Reasoned). Intra-BSS traffic is still invisible (S0).

## 4. DHCP leases → macbind

The deployment uses an **NM hotspot with `ipv4.method shared`**, so NM spawns its own dnsmasq with:
- `--dhcp-leasefile=/var/lib/NetworkManager/dnsmasq-<if>.leases`
- `--dhcp-lease-max=50`
- `--conf-dir=/etc/NetworkManager/dnsmasq-shared.d`

`dhcp-script` would work from that conf-dir. The script runs with root privileges unless `dhcp-scriptuser` is set, and dnsmasq serializes the calls. But a script would need either root code talking to the core socket or a new privileged helper.

**Recommendation:** have core **poll or inotify the lease file read-only** every 1–2 s, adding `ReadOnlyPaths=/var/lib/NetworkManager` to the unit, and sync `bound4`/`macbind` from it with timeouts equal to the lease expiry. Restarts are simpler too, because there is no "old" event replay to handle.

Gaps (Reasoned):
- Static-IP clients never get bound. Fix: drop `ip saddr` values in the protected network that are not in `bound4`, after a grace period, or accept the gap.
- Spoofing *unleased* IPs is still possible. It is harmless for framing, and the meters are per MAC anyway.

## 5. PMF / WPA3 on the onboard Wi-Fi

- One hostap-list report (2024) has **hostapd** SAE with `ieee80211w=2` working with the Pi as AP, while station-mode SAE failed (https://lists.infradead.org/pipermail/hostap/2024-June/042773.html). Reported, not Verified.
- **The deployment does not use hostapd.** An NM hotspot uses **wpa_supplicant's AP mode**, which is a different and less complete code path. The equivalent is `nmcli con modify pirewall-lan-ap 802-11-wireless-security.pmf required` plus `key-mgmt sae` (or `wpa-psk` with PMF required). It may or may not work on brcmfmac.
- **Timebox it to 30 minutes on the Pi:** `iw phy | grep -iA2 "MFP\|cipher"`, then join a modern phone. If it fails, document it.
- **Deauth detection: cut it.** brcmfmac can't run monitor mode while it is an AP (it needs nexmon), so detection would need a second radio.

## 6. Process model and failure modes

- **Survives a core crash** (Reasoned from nft semantics): the tables, sets, meters, anti-spoofing and existing blocks all stay in the kernel, and blocks self-expire. SIGKILL or OOM runs no shutdown hook.
- **`_revert_ruleset_if_failing_open` must be changed:** in v2 it should flush only `block_mac`, `ratelimit_mac` and `block4`, never the meters or anti-spoofing. Otherwise A6 turns an attacker-induced crash back into an off switch (finding 17).
- **On startup,** core must reconcile its `RuleStatus` table against the live set contents.
- **One single point of failure remains:** if the core dies, `bound4`/`macbind` stop updating. New leases go unbound and fail open for spoofing. Existing bindings expire with their leases, and a stale binding could drop a legitimate IP reassignment. Use a binding timeout equal to the lease time. Reasoned.
- **Single RPC lock:** v1 serialises every RPC behind one lock (see `api.rpc_timeout_seconds`). The meter consumer, offender polling and lease sync must not run under that lock.
- **Keep the v1 capture path behind `capture.engine = "afpacket" | "nfstream"`** as a fallback during the 42 h.

## 7. Schedule

The 42 h plan is too much for one pass. Critical path: Pi checks (S0, nft 1.0.6, PMF) → benign capture → attack-lab pcaps → training → deployment → re-run.

**User actions on the Pi, in order:**

| When | Action |
|---|---|
| **H0** | Push the overhaul branch. Delete the demo accounts. Start the benign capture: `tcpdump -ni wlan0 -s 1600 -G 3600 -w /var/tmp/benign-%Y%m%d%H.pcap`. Put the pcaps on USB or SSD if the SD card is small, and keep the capture running the whole time. |
| **H0–2** | Run `apt install python3-nftables libnftables1 hping3 nmap`. Record `nft --version`, `uname -r` and the `iw phy` output. Run the S0 test. Load `v2_ruleset_draft.nft` with `nft -c -f`, then load it in shadow mode (empty `meter_verdict`). Run the NFStream throughput test on the synthetic pcap. Do the PMF timebox. |
| **H2–4** | Decide the victim host (eth0 segment) and whether a USB Wi-Fi adapter is available. |
| **H10–20** | Run the scripted attack lab from Kali on wlan0 against the eth0 victim and the Pi, capturing labelled pcaps: attacker MAC, start and stop times, and the command line. |
| **H30–38** | Deploy v2. Re-run the lab in SHADOW, then ACTIVE. Measure CPU, drops and memory. |

**Cut list:**
1. XDP/eBPF.
2. The deauth sensor.
3. WPA3, beyond the 30-minute PMF try.
4. Per-device anomaly models (replace with one benign IF and per-MAC rate quantiles).
5. Full CIC-IoT2023 or CICIDS2017 re-extraction. At most one small subset, and only if the download finishes by about H6.
6. The client-isolation hairpin, unless an adapter turns up.
7. The dashboard redesign.
8. SQLite forensics. Do per-type in-memory quotas plus journald instead.

**Keep:**
1. The kernel plane with the SHADOW switch.
2. Anti-spoofing from the lease file.
3. The set-based backend.
4. NFStream with identical train and live config (`accounting_mode=1`, snaplen 1536, fixed timeouts).
5. Source-level policy.
6. The admin throttle.
7. A scripted evaluation.

**Freeze features at H28.**

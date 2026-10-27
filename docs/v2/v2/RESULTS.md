# pirewall v2 kernel data plane: sandbox verification results (2026-10-27)

## Scope

These are real nft rulesets driven by real traffic (hping3, scapy, ping, curl) on a netns testbed. All results are `env=sandbox` regression evidence. They are **not Pi measurements**, and none of these numbers are performance figures for the Pi.

## Environment

- Kernel 6.18.44 (x86_64, root in the sandbox).
- nftables **1.0.9** (system). The full suite was also re-run with rulesets compiled by **nftables 1.0.2** userspace: Ubuntu jammy `nftables_1.0.2-1ubuntu3.1` with `libnftnl 1.2.1`, run via `LD_LIBRARY_PATH`.
  - 1.0.2 is *older* than Bookworm's 1.0.6, so everything 1.0.2 compiles also exists in 1.0.6.
  - I could not get 1.0.6 itself: netfilter.org, deb.debian.org and git.netfilter.org all returned 403.
- hping3, nmap, scapy 2.8, iperf3, conntrack-tools, python3-nftables 1.0.9.

## Files

| File | What it is |
|---|---|
| `pirewall_static.nft.template` | Static guards: pre-defrag fragment drop, raw anti-spoof + stateless per-MAC meters + global backstops, `input_guard`, `forward_guard`, verdict chains, and an `arp` anti-poisoning table. |
| `pirewall_adaptive.nft.template` | FirewallManager-only sets: `block_mac`, `block4`, `ratelimit_mac`, plus `infra4`/`allow_bound` exemptions. Hooked at prerouting -299. |
| `base.nft.template`, `portal.nft.template`, `base_and_portal.diff` | Admin rule pinned to `iifname eth0` + admin MAC + IP. DNS accepts pinned to the LAN interface. Portal `authed` set is now `ipv4_addr . ether_addr`. |
| `render.py` | Renderer. Unknown or missing `${VAR}`s are a hard error. |
| `netns_testbed.sh` | `up` / `down` / `load`. Namespaces: router (with lan0/wan0/adm0), a switch bridge, attacker, legit, allowlisted, WAN victim, admin. NM-shared-style masquerade. Kernel `rp_filter` is OFF, so nft has to do the work. |
| `svc.py` | Test services: a UDP echo that counts what it receives, and a TCP listener. |
| `test_ruleset.py` | 19 assertions. |
| `bench_nft.py` | Set-element update latency. |
| `results_nft1.0.9.log` / `.json`, `results_nft1.0.2.log`, `bench_nft.json` | Raw evidence. |

Test-only threshold overrides (lower than production defaults so a ~10k pps hping3 can trip them): `FORWARD_VERDICT=drop UDP_FWD_PPS=2000 UDP_FWD_BURST=4000 METER_SIZE=64 GLOBAL_UNBOUND_PPS=200 GLOBAL_SYN_PPS=500`.

## Results

Every assertion was run identically under nft 1.0.9 and 1.0.2, with the same outcome.

| # | Assertion | Result | Evidence (nft 1.0.9 run) |
|---|---|---|---|
| 1a | SYN flood to the Pi (`:8080`); attacker MAC in `@offenders`; legit traffic still works | **PASS** | 30,000 sent, 1,322 reached the service. 28,622 dropped by `guard_verdict_raw`. Offender codes {1 SYN, 8080 portal concurrency}. Legit portal + WAN curl OK during the flood. |
| 1b | SYN flood through the Pi to the WAN victim | **PASS** | 30,000 sent, 342 reached the victim. Codes {1, 6, 7}. Legit curl OK. |
| 1c | UDP flood through the Pi to the WAN victim, per-(MAC, dst) forward meter | **PASS** | 30,000 sent, 14,309 received, 15,691 dropped. Code {8}. Legit OK. |
| 1d | ICMP flood to the Pi and to the victim | **PASS** | 30,000 sent, 29,603 dropped. Code {3}. Legit ping OK. |
| 2 | `--rand-source` flood | **PASS** | 20,000 of 20,000 dropped as `c_bogon` (source outside the protected network); 0 reached the router. In-subnet random sources from the attacker's MAC: bound IPs go to `c_spoof`, unbound ones are metered by the unbound chain. `syn_meter` held 1 key, so it did not fill. |
| 3a | Spoofing a bound neighbour's IP | **PASS** | 2,000 of 2,000 counted in `c_spoof`; 0 reached the router. The legit MAC appears in no accusatory set. |
| 3b | ARP poisoning of a bound IP (extra test) | **PASS** | 20 of 20 dropped (`c_arp_spoof`). The router's neighbour entry stayed on the legit MAC. |
| 3c | The legit MAC never enters `offenders` / `unbound_seen` / adaptive sets in any test (t7 deliberate case excluded) | **PASS** | `legit_hits_per_test: []` |
| 4 | Allowlisted (MAC+IP) device is never metered; its IP cannot be spoofed | **PASS** | 20,000 of 20,000 of its SYNs reached the router, and it appears in no set at all. A spoof of its IP from another MAC: 2,000 of 2,000 dropped. |
| 5 | Admin reaches the API during a flood; the LAN cannot spoof the admin | **PASS** | Admin curl to 8443 OK twice during a 10k pps flood. 1,000 of 1,000 spoofed-admin packets dropped (`c_bogon`). 0 LAN packets reached 8443. The attacker using its own IP is refused by base. |
| 6 | Observe / enforce flip in one atomic batch | **PASS** | Observe: 10,000 of 10,000 reached the router, and offenders were still recorded ({1, 4, 8080}). Enforce: 433 reached. Each verdict chain has exactly 1 rule in both modes. |
| 7 | Kill switch; panic leaves base intact | **PASS** | **Before the kill switch:** `block_mac` blocked the attacker. `ratelimit_mac` held a `ping -f` to 20 pps (69.6% loss). **After the kill switch:** the adaptive sets were flushed and every guard was set to observe; the attacker passes again; the static and adaptive tables are still loaded. **After panic:** both pirewall tables are gone, `pirewall_base` remains, legit forwarding works, and base still refuses LAN→API. |
| 8 | Reloading the templates twice is idempotent | **PASS** | `bound4`, `macbind`, `allow_bound`, `offenders`, `block_mac` and `infra4` element counts were identical before and after. The per-chain rule counts were identical too. |
| 9 | Established-flow UDP flood to a responding `:53` | **PASS** | The conntrack entry was ESTABLISHED before the flood. 30,000 sent, 788 reached the service. Codes {2, 53}. Legit DNS still answered. |
| 10a | IPv4 fragments from the LAN are dropped | **PASS** | `c_frag` = 9; the 4,000-byte ping fails and a normal ping works. |
| 10b | IPv6 from the LAN is dropped | **NOT TESTABLE HERE** | The sandbox kernel has no IPv6 stack (`/proc/sys/net/ipv6` is missing), so inet hooks never see IPv6. The rule loads under both nft versions. **Verify on the Pi.** |
| 11 | Meter fill: many source MACs → the global backstop engages | **PASS** | 6,000 packets with random MACs. `unbound_meter`, `syn_meter` and `pps_meter` each capped at 64 keys (= size). `c_bk_unbound` = 4,550. |
| 12 | LAN→WAN DNS and DoT (53/853) not via the Pi is blocked | **PASS** | The victim received 0 UDP/53 packets and 0 TCP/853 accepts. `c_dns_bypass` = 23. DNS via the Pi works. |
| 13 | DHCP DISCOVER from 0.0.0.0 passes; per-MAC starvation brake | **PASS** | 3 of 3 DISCOVERs reached the router's input. A 40-packet burst from one MAC: 5 passed (= burst). Offender code 67. |

**Totals:** 18 of 19 PASS and 1 NOT TESTABLE, identical under nft 1.0.9 and 1.0.2.

## Findings that change PLAN_v1

1. **Fragment rules must run before defrag.** I placed rule probes at both priorities and sent a 4,000-byte ping:
   - at priority -300 (raw), 0 packets matched;
   - at priority -460, 6 fragments matched.

   `nf_defrag_ipv4` runs at -400, so a fragment rule in `prerouting raw` can never match. The template therefore has a separate `prerouting_frag` chain at **-450**.
2. **Burst is part of the threshold.** The first 1c run failed: with the default `UDP_FWD_BURST=40000`, a 3 s, 30k-packet flood fitted entirely inside the burst. Rule of thumb: burst ≈ 1–2 s of rate, and benign-capture calibration must fit **rate and burst together**.
3. **Every source gets an element in a meter set.** Even a benign source appears in `syn_meter` as soon as it sends one SYN. Accusation must come only from `@offenders` (written only when the limit is *exceeded*) or the adaptive sets. Detection code must not treat meter membership as evidence. The test separates the two cases.
4. **Observe mode must flip every verdict chain.** In the first run of test 6, only `raw` was flipped, and `input_guard`'s portal-concurrency rule (`ct count over 20` per MAC) still dropped. The kill switch and SHADOW-for-guards must flip raw, input and forward together (implemented in test 7).
5. **The adaptive table moved from input/forward to prerouting -299.** It runs right after anti-spoof and before conntrack, so a blocked or rate-limited device costs no conntrack entries and covers both paths with one chain.
6. **`ip saddr != @bound4 → unbound` plus `@unbound_seen`** gives static-IP devices a working but tightly metered path, together with evidence of which MAC+IP pairs need a static binding. This avoids the PLAN_v1 A5 full-LAN outage from an empty binding set. The bindings themselves must still be seeded before the raw verdict goes to enforce.
7. **Never name a chain `meters` (renamed to `flood_meters`).** nft 1.0.2 cannot run `list chain … meters` because `meters` is a keyword; `fwd` is reserved too (red-team V1).
8. **The portal change needs code too.** `NftablesBackend.authorize_portal_client` and `deauthorize_portal_client` must pass `{"concat": [ip, mac]}` elements, and the portal process must learn the client's MAC from core's binding view, not from the HTTP request. This was not done here.
9. **Set updates from Python** (`bench_nft.json`, 600 operations each way):
   - libnftables via `python3-nftables`: median **0.36 ms** per add or delete (p95 0.49 ms).
   - `nft -j -f -` subprocess: median **10.2 ms** (p95 24.7 ms).
   - 300 adds in one libnftables batch: 4.5 ms.

   Use libnftables. On Bookworm, `python3-nftables` installs to `/usr/lib/python3/dist-packages`, so the uv venv needs `--system-site-packages` or a `.pth` file pointing there. Its Python version must match. If it doesn't, keep the subprocess fallback: it is slower but still far faster than the A3 rate cap needs.

## Compatibility notes for the Pi (Bookworm nft 1.0.6, kernel 6.6/6.12)

Every construct used was compiled by nft **1.0.2** and behaved identically on the kernel, so the userspace parser in 1.0.6 is covered. The constructs are:

- `priority raw` and numeric priorities (-450, -299)
- dynamic sets with a per-element `limit rate over … burst … packets`
- `update @set { concat }`
- `ct count over` inside a dynamic set keyed on `ether_addr`
- `fib saddr . iif oif missing`
- `fib daddr type local`
- the `th dport` set
- concatenated negated lookup `ip saddr . ether saddr != @macbind`
- `ether saddr` in `forward`
- named counters
- the `arp` family with `arp saddr ip . arp saddr ether != @set`
- the interval set with inline elements plus `flush set`

The kernel features involved (nft_dynset with stateful expressions, nft_connlimit, nft_fib, the arp family) all exist in mainline well before 6.6. That is reasoned, not verified on Pi hardware.

**Still to do on the Pi:**

1. `nft -c -f` on each rendered template.
2. Test 10b (IPv6).
3. Confirm `ether saddr` is the station MAC on brcmfmac `wlan0` in AP mode (frames are 802.3-converted). If it is not, every MAC-keyed rule is wrong. This is the single most important Pi check.
4. Measure real pps ceilings: veth numbers do not transfer.

# Pirewall v2 — DRAFT plan v0 (to be attacked by critics)

Constraints (from user): ~42 hours wall-clock, 2-day deadline, Wi-Fi AP topology
(Pi 4 is the AP/router for the protected LAN on wlan0; uplink on wlan1/eth; Admin PC on eth0),
hybrid rewrite (Python control plane/ML/API/portal kept; hot path moves into the kernel),
assume current detection performance is terrible everywhere; retraining allowed; model change allowed.
Claude has no push access to GitHub and no Pi; Claude codes + tests in a Linux sandbox; the user
runs everything on the Pi/Kali and feeds back logs. Existing paper attack numbers are void.

## Goals / acceptance criteria (measured on the real Pi, scripted, logs saved)
G1 SYN/UDP/ICMP floods (fixed and random source) from a LAN client are mitigated in-kernel within 2 s,
   Pi stays responsive, legit clients keep >80% of baseline throughput.
G2 Port scans (nmap -sS default timing, -T4, and a slow -T2) are detected; fast scans are blocked at
   the *source* level within 5 s; slow scans detected within 60 s.
G3 Brute force (ssh/http/portal) detected and source rate-limited.
G4 IP spoofing of another LAN client is dropped (cannot frame a neighbour).
G5 Benign false-positive rate: <1 MONITOR alert per device-hour, 0 RATE_LIMIT/BLOCK on benign over
   the held-out benign capture.
G6 Protection (kernel meters + anti-spoof + existing block/ratelimit sets) persists if pirewall-core dies.
G7 Every reported number traceable to a saved file produced by a script.

## Architecture
### K: kernel data plane — new `table inet pirewall` (replaces per-rule linear chain)
- sets: `block4` (ipv4_addr, timeout), `ratelimit4` (ipv4_addr, timeout), `allow4` (interval, from
  allowlist + admin PC + Pi + gateway), `macbind` (ipv4_addr . ether_addr, from dnsmasq leases).
- dynamic sets: `newconn_meter`, `flood_offenders` (timeout 60s) populated by rules like
  `ct state new add @newconn_meter { ip saddr limit rate over 100/second burst 200 packets } add @flood_offenders { ip saddr } drop`
- chains at priority -5 on BOTH `input` and `forward` (iif LAN): allow4 → return; block4 → drop;
  ratelimit4 → per-source limit; static flood meters (SYN, UDP, ICMP, new-conn) → drop + mark offender.
- `prerouting` (iif LAN) anti-spoof: allow DHCP (0.0.0.0→255.255.255.255 udp 67); drop if
  `ip saddr . ether saddr` not in `macbind` once that client has a lease; dnsmasq `dhcp-script`
  → tiny helper → core RPC `bind_lease(ip, mac)` → set element.
- Python never forks `nft` per decision: one long-lived libnftables handle (python3-nftables
  bindings from Debian, or `nft -j -f -` batched) to add/remove set elements.
### C: capture + flows — NFStream (C/libpcap/nDPI, aarch64 cp312 wheels exist)
- One NFStreamer config (idle_timeout, active_timeout, splt_analysis=N, statistical_analysis=True,
  n_dissections) used for BOTH `scripts/dataset/pcap_to_flows.py` (training) and live capture.
  This is the train/serve-skew fix: identical code computes features in both places.
- Short active_timeout (e.g. 10 s) so long flows are evaluated in windows, not after 30 min.
- nDPI gives app protocol, SNI, client fingerprint (JA4 if available) → replaces home-grown JA3.
### D: detection
- D1 deterministic host-window detectors over flow stream per (source IP, MAC): fan-out (distinct
  dst ports / dst hosts per 10 s/60 s), failed-connection ratio (SYN without SYN-ACK, RST), auth-fail
  bursts per service, flood offenders from kernel set. Thresholds set from the benign capture's
  P99.9 per device class, with floors.
- D2 anomaly: Isolation Forest (or HBOS) trained on THIS network's benign flows; threshold = benign
  validation quantile targeting FPR 0.1%.
- D3 supervised LightGBM on NFStream features (destination port bucketed, no IPs), trained on own
  benign + own attack-lab pcaps + public pcaps re-extracted with the SAME NFStream config
  (CIC-IDS2017 pcaps with Engelen-corrected time windows, or CIC-IoT2023 per-attack pcaps).
  Calibrated (isotonic) probabilities.
- Evaluation: split by capture session/time, never random rows; cross-dataset test; report PR-AUC,
  FPR at operating point, per-class recall, time-to-detect.
### E: policy engine (replaces weighted sum)
- Explicit table: D1 high-certainty (kernel flood offender, fast scan) → RATE_LIMIT/BLOCK source
  alone (TTL 5 min, doubles on repeat, cap 1 h). D3 alone → MONITOR. D3 + D1/D2 → RATE_LIMIT.
  D2 alone → MONITOR only. Validator chain kept (ported to set targets), allowlist absolute,
  SHADOW/ASSISTED/ACTIVE kept, kill switch flushes block4/ratelimit4.
### F: access hardening
- delete demo accounts; admin login throttle; portal session bound to (ip, mac); hostapd
  `ieee80211w=2` (PMF required) or WPA3-SAE transition; document IPv6 disabled check at startup.
### G: forensics
- SQLite WAL event store with per-type quotas (flood can't evict scan records); Wazuh decoder file.

## Schedule (hours from start)
H0-2   P0: demo accounts removed, admin throttle, branch push, START benign pcap capture on Pi
       (tcpdump -i wlan0 -s 256 rotating, runs whole time).
H2-12  K data plane + new backend + anti-spoof + tests (Fake + real nft in netns in sandbox).
H6-16  NFStream exporter + feature schema v2 + pcap→dataset tool.
H8-18  Attack-lab harness scripts (Kali) + separate victim host; user captures labelled pcaps.
H18-28 Datasets, training, evaluation reports.
H24-34 Detection D1/D2/D3 + policy engine integration + dashboard.
H34-40 Pi deployment; full scripted attack-lab re-run in SHADOW then ACTIVE; measurements.
H40-42 Docs, KNOWN_ISSUES v2, results tables for the paper.

## Known risks (author's own)
- NFStream throughput on Pi 4 unknown; libpcap on wlan0 AP mode; nDPI JA4 availability.
- nft dynamic-set/meter syntax and kernel version on Bookworm.
- 42 h is not enough for a 1–2 week benign soak → benign capture only ~30 h.
- Public pcaps are huge (tens–hundreds of GB) — download time.

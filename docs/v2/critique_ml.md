# Critic #2: ML / evaluation methodology review of PLAN_v0_draft.md

Reviewer stance: a harsh S&P/NDSS reviewer, using the Arp et al. "Dos and Don'ts" pitfalls (P1–P10) as a checklist.

Labels: **Verified** means I ran it, or fetched and read the source, in this session. **Reasoned** means an inference or widely reported knowledge that I did not re-check here.

---

## 0. Verdict

The draft fixes the biggest v1 defect, train/serve skew, by using a single NFStream config for both training and serving. That is the right call.

The rest of the ML plan is still written like a Kaggle project:

- "Train on everything, calibrate, report PR-AUC."
- No defined unit of evaluation.
- No leakage controls for the new windowed flows.
- No defence against tool-artifact shortcuts.
- An unrealistic assumption that public pcaps are usable in 42 h.

A reviewer would reject it under P1 (sampling bias), P4 (spurious correlations), P7/P8 (wrong metrics, base rate) and P9 (lab-only).

**Recommendation.** Make deterministic detectors the only thing allowed to enforce. Demote supervised ML to a corroborating, MONITOR-level signal. Make an honest, ablated evaluation the paper's main contribution. Details are in §9.

---

## 1. NFStream facts the plan depends on

Installed nfstream 6.6.0 in the sandbox and ran it on a synthetic pcap (`/tmp/nfs/t.pcap`).

**1. Flows are emitted only at expiry. (Verified)**
- `expiration_id`: 0 = idle, 1 = active, -1 = custom plugin.
- A TCP SYN → RST probe followed 5 s later by a new SYN on the same 5-tuple was merged into **one** flow. NFStream does not end a flow on FIN or RST.
- Consequences:
  - "Early-flow (first N packets) classification" is **not early**. The `splt_*` features are only available when the flow expires.
  - Detection latency ≥ min(idle_timeout, active_timeout).
  - With the defaults (120 s / 1800 s), a scan probe sits in the table for 2 minutes.
  - You must set e.g. `idle_timeout=10, active_timeout=10` for live use **and identically for every training pcap**. That changes the flow definition, which in turn changes every feature distribution and the row counts. **Decide this once, before extracting anything.**
- A Python `NFPlugin.on_update` would allow genuinely early decisions, but it runs per packet in Python. That is the v1 bottleneck again (Reasoned).

**2. `accounting_mode` changes the size features. (Verified)**
- The same pcap gave `src2dst_min_ps` = 54 (mode 0, link layer), 40 (mode 1, IP) and 0 (mode 3, payload).
- Use **`accounting_mode=1` (IP)**. CIC pcaps are Ethernet and a Wi-Fi AP capture presents Ethernet framing, but IP-level sizes don't depend on link-layer quirks.
- Pin the mode in the feature-schema version.

**3. Feature list. (Verified)**
- 5-tuple, MACs and OUIs.
- Bidirectional, src2dst and dst2src: packets, bytes, durations, ps (packet size) min/mean/std/max, piat (inter-arrival) min/mean/std/max, and 8 TCP flag counts each.
- `splt_direction/ps/piat_ms` (lists of length N).
- nDPI fields: `application_name`, `requested_server_name`, `client_fingerprint`, `user_agent`.
- **IP, MAC, OUI, port, SNI and app name must never be model inputs.** They are shortcut and identity features. The plan only says "no IPs".

**4. JA4 is not automatic.**
- `client_fingerprint` is nDPI's `c_hash`. It is probably JA4 in recent nDPI, but I did not check this on a real TLS pcap (Reasoned).
- `nfstream.plugins.JA4` exists but is a per-packet Python plugin using dpkt, which is slow.
- Treat JA-fingerprints as deterministic indicator lookups, not as ML features.

**5. Snaplen versus SNI/JA4. (Reasoned)**
- The draft captures benign traffic with `tcpdump -s 256`.
- Modern Chrome/Firefox ClientHellos carry post-quantum (X25519MLKEM768) key shares of roughly 1.1 KB and often span two segments.
- At 256 bytes, nDPI will often miss SNI and the fingerprint, so the live system (full snaplen) and the training pcaps (truncated) would **diverge again**.
- Either capture with `-s 0`, which raises a privacy issue (see §8), or decide that DPI-derived fields are out of the model.

---

## 2. Data sources: feasibility and fitness

Sandbox egress check: `cicresearch.ca` does not resolve, and `intrusion-detection.distrinet-research.be` returns a proxy 403. **All public pcap downloads must happen on the user's machine (Verified).**

### 2a. Own benign capture (~30 h, home AP)

**This is the single most valuable data in the project.** It is also the weakest point of the draft:

- **About 30 h is one weekday-ish cycle.** It misses weekends, OS and app update storms, backups, new devices, a guest phone and video calls. Any threshold chosen from it will be tight and will produce false positives in the first week (P1 sampling bias, Reasoned).
- **Captured while development is happening.** Devs SSH to the Pi, run tests and probably port-scan accidentally. All Admin-PC and Kali traffic must be **excluded by MAC**, not by IP, and documented.
- **"Benign" is an assumption.** Nobody has verified the home LAN is clean, so treat the capture as unlabeled-but-presumed-benign and say so (P2). A cheap sanity pass: no SYN fan-out above 50 dests, no RST storms, and outbound connections reviewed against known SNI.
- **Mitigation:** keep capturing for the full 42 h and beyond. Split it **temporally** (§4). In the paper, report false positives on a later block the thresholds never saw, and state the coverage limits explicitly.

### 2b. Own attack-lab pcaps

These are good for testing **in this deployment**. As training data they are dangerous:

- **Tool artifacts / shortcut learning (P4, Reasoned, well known):**
  - hping3 floods: 40-byte IP packets, no TCP options, window 64 or fixed, constant inter-arrival.
  - nmap `-sS`: window 1024 plus MSS-only options, a single SYN, then RST.
  - hydra: fixed request templates.
  - A classifier trained on these learns "this is hping3", not "this is a flood". It hits 99.9% on the test split and misses `nping`/`masscan`/scapy/Mirai.
  - CICIoT2023 uses the same tools (hping3, nmap, hydra, slowloris; Verified, Table 2 of the paper), so adding it does **not** diversify tools.
- **Label assignment for windowed, spoofed and mixed traffic:**
  - The harness must log `start_ts`, `end_ts`, `attacker_mac`, `victim_ip`, `tool`, `args` and `run_id` for every run.
  - Label key: **`src_mac` == attacker MAC** within [start, end + idle_timeout]. Do not use source IP, because `--rand-source` floods have random IPs (NFStream exposes `src_mac`; Verified).
  - Use a **dedicated attacker device** with its background traffic disabled, or label only flows attacker → victim and drop all other attacker flows as "unlabeled".
  - Add an **"attempted / no-effect"** label, as Engelen did, for brute-force flows that never completed a handshake. Otherwise "attack" includes empty TCP fragments that look exactly like benign failed connections (P2).
  - Flows in the window that are reverse-direction responses (victim → attacker with `src_mac` = victim) must inherit the label of their bidirectional flow. NFStream is bidirectional, so this mostly holds (Reasoned).
- **Repeats:** at least 3 runs per attack, at different times, and ideally a second attacker device (e.g. a phone with Termux, or an ESP32 for floods). Without these you cannot do session-held-out evaluation.

### 2c. CIC-IDS2017 pcaps (UNB)

- **Sizes (Verified, UNB page):** Mon 11 GB, Tue 11 GB, Wed 13 GB, Thu 7.8 GB, Fri 8.3 GB; about 51 GB total.
- **Download URL:** http://cicresearch.ca/CICDataset/CIC-IDS-2017/ (page: https://www.unb.ca/cic/datasets/ids-2017.html).
- **Attack schedule (Verified):** attacker 205.174.165.73, victim 205.174.165.68 / 192.168.10.50. Examples:
  - Friday port scan 13:55–14:35 with the firewall on, 14:51–15:29 with it off.
  - Friday DDoS LOIT 15:56–16:16.
  - Wednesday DoS windows 09:47–11:23.
- **Labeling with NFStream:** label rule = (attacker IP set ∪ victim IP) ∧ time window ∧ direction. Two traps:
  - **(i) NAT.** Inside the capture, external attacks appear from the NAT address **172.16.0.1** (Reasoned; widely reported, and how Engelen relabel). Verify by plotting per-minute flow counts from 172.16.0.1 against the schedule.
  - **(ii) Timezone.** Schedule times are local (ADT, UTC-3) while pcap timestamps are epoch. Verify the offset with the same plot; don't assume it.
- **Engelen's corrected release** (https://intrusion-detection.distrinet-research.be/WTMC2021/, not fetchable here; paper: https://lirias.kuleuven.be/retrieve/713070) ships flows produced by **their modified CICFlowMeter**. Reusing those CSVs reintroduces exporter skew. **Only their labeling logic transfers** (IP/time windows, "attempted" class, TCP-appendix handling).
- **Fitness:** a 2017 wired enterprise network with Windows hosts. Exporter skew is gone after re-extraction, but domain shift remains. Cantone et al. 2024 report average cross-dataset MCC falling from 94.6% to 29.4%, with some attacks near zero in every cross setting (Verified: https://arxiv.org/html/2402.10974v1).
- **Use:** **Friday only** (8.3 GB: PortScan, DDoS, Bot) as an **external cross-dataset test set**, not for training. That is feasible in 42 h if the user starts the download in the first hours.

### 2d. CICIoT2023

**Facts (Verified, https://pmc.ncbi.nlm.nih.gov/articles/PMC10346235):**
- About 548 GB of pcap.
- One experiment per attack, with benign captured separately over 16 h.
- **Labels are per experiment.** "The entire traffic captured is labeled as belonging to that particular attack," which includes any background benign traffic during the experiment. That is label noise (P2).
- The shipped CSVs are **10- or 100-packet averaged windows**, not flows, and are useless for our schema.
- The attackers were Raspberry Pi 4s running hping3, nmap, hydra and similar.
- Download page: https://www.unb.ca/cic/datasets/iotdataset-2023.html

**Verdict: drop it from the 42 h plan.** It is too large, has noisy labels and the same tools as our own lab. At most, a few 10 MB chunks of 2–3 classes could serve as a sanity cross-test. Mention it as future work.

---

## 3. Features

- **Keep:** NFStream bidirectional/src2dst/dst2src counts, bytes, ps stats, piat stats, flag counts and duration, plus `splt` for N = 8 (sizes and directions; piat optional).
- **Exclude:** all IP/MAC/OUI fields, ports as raw integers, SNI, app name, user agent and timestamps.
- **Destination port:** the draft says "bucketed". Make it a coarse category (web / dns / ssh / other-wellknown / ephemeral) and run a **with/without ablation**. CIC-IDS2017's Bot class is known to correlate with port 8080 (Reasoned). v1's own audit found `destination_port` at 3% of gain, which proves nothing about shortcuts.
- **Host-window features** (fan-out, failure ratio, new-connection rate per source MAC per 10 s / 60 s) feed the *deterministic* tier. If they are also fed to ML, compute them from the same flow stream in the same code at training time.
- **Shortcut audit:** before reporting anything, train a depth-3 tree and print the top splits. If one feature (min_ps == 40, window size, constant piat) separates a class, write it down and test against a **different tool** (§4).

## 4. Splits and leakage

The draft says "split by session/time". Make that concrete:

1. **Group rows by connection.** `active_timeout = 10 s` turns one long connection into many rows. Rows of the same 5-tuple must never straddle train and test (GroupKFold on a connection or session key). Otherwise near-duplicate windows leak (P3, Reasoned).
2. **Benign: temporal blocks.** First 60% for training, the next 15% for validation (thresholds and calibration), a gap of at least 1 h, and the last 25% for test. Report the test block's day and hours.
3. **Attacks: hold out runs.** Train on runs 1–2 and test on run 3. Also do **leave-one-tool-out**: train with hping3 floods, test with nping/scapy/`t50`/masscan floods. Train with nmap, test with masscan or rustscan.
4. **Cross-dataset:** own data → CIC-IDS2017 Friday (re-extracted), and the reverse. This is expected to be bad; report it anyway as the honesty result.
5. **Dedupe and cap.** A 15 s flood yields millions of near-identical rows. Cap rows per (run, class), e.g. 5 k, for training. **Never report flow-level accuracy where floods dominate the denominator.**
6. **Model selection** only uses validation blocks. The test block is touched once, and its hash is recorded.

## 5. Metrics (P7, P8)

Flow-level accuracy/F1/PR-AUC is the wrong primary unit for a firewall. Report:

- **Attack-instance level:** for each run, detected (yes/no) by which tier, **time-to-detect** and **time-to-mitigate** (from the harness start timestamp to the first alert and the first set element in the kernel), with medians and IQR over at least 3 runs.
- **Benign cost:** alerts per **device-hour** on the held-out benign block, split by action (MONITOR / RATE_LIMIT / BLOCK), with Poisson 95% confidence intervals. With zero events in H device-hours the upper bound is 3/H; say so instead of claiming "0 FP".
- **ML component:** PR-AUC plus **recall at a fixed benign FPR** (10⁻³ and 10⁻⁴ per flow), with the *expected alerts per day* at that FPR given the measured benign flows/day. That makes the base rate explicit.
- **Calibration:** a reliability diagram on validation. Note that calibration does **not** transfer under prior shift (lab attack share ≠ home), so the operating threshold is set by **benign FPR**, not by F1 or by "probability > 0.5" (P5).
- **Baselines (P6):** the same harness on (a) v1 and (b) the deterministic tier alone. If ML doesn't beat (b) on something, say so.

## 6. Anomaly tier (D2)

- **One global IF/HBOS on about 18 h of training benign is fine** as MONITOR-only evidence. Use a threshold equal to the validation-block quantile for the target FPR, and record the quantile and the block.
- **Per-device baselines with this little data are not defensible as ML.** Many devices will have a few hundred flows.
  - Use **count-based** per-device envelopes instead (max fan-out, max new-connections/10 s seen in training × margin, with a global floor).
  - Fall back to a device-class or global envelope when a device has fewer than N training windows.
  - New devices start on the global envelope.
- **Drift:** compute PSI/KS between training benign and test benign per feature. Show it in the paper as evidence of how fast thresholds go stale. Live, log the anomaly-score distribution daily.

## 7. Is supervised ML worth it in 42 h? (Reasoned)

The goal set (G1–G4) is floods, scans, brute force and spoofing. All of these are **volumetric or structural**:

- Rate meters, fan-out counts, failure ratios and anti-spoofing detect them deterministically, explainably and tool-independently.
- A supervised flow classifier trained on hping3/nmap/hydra adds tool-specific shortcuts, latency (flow expiry) and false positives.

**Recommendation:**
- **Enforcement path:** kernel meters + D1 deterministic only. D1 thresholds are learned from benign data, so the ML framing stays honest: "data-driven thresholds".
- **D2 anomaly:** MONITOR only. It is the novelty net for things you didn't script.
- **D3 supervised LightGBM:** kept, but MONITOR plus corroboration only. Evaluate it with leave-one-tool-out and cross-dataset tests. The paper reports whether it adds detection beyond D1. Either outcome is publishable if the evaluation is honest; the current paper is not.
- **Time budget for ML:** at most about 10 h (dataset tooling 4 h, training/eval scripts 4 h, reports 2 h). Everything else goes to the kernel plane, the harness and measurement.

## 8. Ethics and threat-model items reviewers will ask about

- **Consent.** Capturing housemates' or family traffic with `-s 0` means recording payloads. Get consent, keep pcaps off git, and publish only derived flow features with IPs and MACs hashed. Say this in the paper.
- **Adversary model (P10).** State what the attacker can do: a LAN client, able to spoof IP and possibly MAC, aware of the thresholds. Then show one **adaptive-attacker** experiment, e.g. a scan paced just under the D1 threshold, and a flood split across many MACs (if MAC spoofing is possible on the AP).
- **Out of scope, flagged for the systems critic.** On Pi 4 brcmfmac in AP mode, intra-BSS client↔client frames may be forwarded by the radio firmware without reaching `wlan0`'s IP stack or capture, unless `ap_isolate=1` (Reasoned, unverified). That would make LAN-to-LAN attacks against a Wi-Fi victim invisible. It decides where the attack-lab victim must sit.

## 9. Recommended minimum-viable but defensible ML design

1. **One exporter.** `NFStreamer(idle_timeout=10, active_timeout=10, accounting_mode=1, statistical_analysis=True, splt_analysis=8, n_dissections=20)`. It is versioned as feature schema v2 and used by `pcap_to_flows.py` (training) and live capture alike.
2. **Data:**
   - Own benign capture, continuous, `-s 0` with consent, otherwise `-s 1600`.
   - Own attack runs, at least 3 per attack, logged by the harness, labeled by attacker MAC + window.
   - CIC-IDS2017 Friday as an external test only.
   - No CICIoT2023.
3. **D1 (enforces):** per-source-MAC 10 s / 60 s windows covering distinct destination ports, distinct destination hosts, failed-handshake ratio, auth failures per service and the kernel flood-offender set. Thresholds = max(benign training P99.9 × 2, floor). Floors and margins are documented.
4. **D2 (MONITOR):** IF on benign training flows, threshold at validation FPR 10⁻³.
5. **D3 (MONITOR / corroborate):** LightGBM binary (attack vs benign) plus a coarse family head (flood / scan / bruteforce / slow-DoS). Exclude identity and port-integer features. Cap rows per run. Isotonic calibration on validation; threshold at benign FPR 10⁻³.
6. **Protocol:** connection-grouped, temporally split benign; held-out attack runs; leave-one-tool-out; cross-dataset; every test set touched once; seeds, data hashes and model hashes written to `results/manifest.json`.

## 10. Paper tables and figures (exact)

- **Table I. Data:** per source, the hours, devices, flows, runs per attack, tools, and the split assignment.
- **Table II. Detectors:** tier, inputs, threshold, how the threshold was set and from which block, and the allowed action.
- **Table III. Per-attack results** (median over ≥ 3 runs): detected-by tier, time-to-detect, time-to-mitigate, legitimate-client throughput retained, and v1 versus v2.
- **Table IV. Benign cost:** alerts per device-hour by action on the held-out block, with 95% confidence intervals, v1 versus v2.
- **Table V. ML:** PR-AUC and recall at FPR 10⁻³/10⁻⁴ for in-distribution, leave-one-tool-out and cross-dataset (own→CIC, CIC→own), with and without the port category.
- **Table VI. Ablation:** kernel only / +D1 / +D2 / +D3, showing attacks detected and benign alerts per device-hour.
- **Table VII. Resources:** CPU, RSS, drop % at 1k/5k/10k/20k pps, v1 versus v2.
- **Fig. 1:** capture drop rate against offered pps (v1 versus v2).
- **Fig. 2:** time-to-mitigate CDF per attack class.
- **Fig. 3:** benign versus attack score distributions with the chosen thresholds.
- **Fig. 4:** reliability diagram for D3.
- **Fig. 5:** per-feature drift (PSI) between the training and test benign blocks.
- **Threats-to-validity paragraph,** mapped explicitly to Arp P1–P10:
  - Single home network.
  - About 42 h of benign traffic.
  - Lab tools.
  - Domain shift between the public data and the home network.
  - Adaptive attacker only partially tested.

## Sources

- NFStream 6.6.0: installed and inspected locally (`NFStreamer` signature, columns, expiry behaviour).
- CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html ; downloads http://cicresearch.ca/CICDataset/CIC-IDS-2017/
- CICIoT2023: https://pmc.ncbi.nlm.nih.gov/articles/PMC10346235 ; https://www.unb.ca/cic/datasets/iotdataset-2023.html
- Engelen et al. WTMC 2021: https://lirias.kuleuven.be/retrieve/713070 ; release page https://intrusion-detection.distrinet-research.be/WTMC2021/
- Cantone et al. 2024: https://arxiv.org/html/2402.10974v1
- Arp et al.: https://arxiv.org/abs/2010.09470
- Pinto et al. 2024 (flow exporter impact): https://arxiv.org/pdf/2412.14021

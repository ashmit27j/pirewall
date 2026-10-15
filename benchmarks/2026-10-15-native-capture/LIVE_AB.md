# Live-traffic A/B: feature schema 1.0.0 vs 2.0.0 — 2026-10-15

The held-out CICIDS2017 split cannot show whether the training/runtime
feature mismatch (docs/FEATURE_SCHEMA.md "Why 2.0.0") is fixed: it is the
same CSV distribution on both sides. This replays **real captured
traffic** through both pipelines instead.

## Method

- **Captures** (real packets, Docker Linux VM on the development PC — **not
  the Pi's network**; GRO disabled so segments are wire-sized):
  - `benign.pcap`, 22 MB: three rounds of HTTPS page + favicon fetches to 40
    popular sites (curl, browser User-Agent, parallel), an 8 MB download per
    round, and the DNS they cause — 780 flows.
  - `attacks.pcap`, 15 MB, on a veth pair against a target running a real
    HTTP server, one attacker address per attack: `10.99.0.2` nmap `-sS
    -p 1-1000`; `.3` hping3 SYN flood (57k SYNs over 15 s); `.4` hping3 UDP
    flood (117k packets over 15 s); `.5` 200 concurrent HTTP requests.
- **Pipelines**, each with its *own* default config and its *own* models:
  - **old** = `main` (schema 1.0.0, old behavior state and scoring), with
    LightGBM/Isolation Forest retrained in the same session with the shipped
    v0.4.0/v0.2.0 configuration (`0.4.0-repro`: accuracy 0.9970, macro-F1
    0.8479, matching the documented 0.9971/0.8546);
  - **new** = this branch (schema 2.0.0, windowed behavior, per-pattern
    scoring, source-level fast path, ML protocol-domain guard), LightGBM and
    Isolation Forest v1.0.0.
- **Replay** (`replay_score.py`, kept in the session scratchpad): packets in
  capture order through each checkout's own parser and aggregator; new-flow
  signals fold into behavior state at creation; each completed flow is
  analyzed, scored and decided the moment it completes; the fast path (new
  only) runs after each packet that opened a flow, on the packet clock.

**Caveat that favors the old pipeline**: both replays use the pcap's
kernel timestamps. The old *runtime* used `datetime.now()` at `recv()`,
which distorts the inter-arrival features (47% of LightGBM gain) further
under load — not reproduced here, so the old pipeline's real-world numbers
were, if anything, worse than shown.

## Benign traffic (780 flows)

| | old (schema 1.0.0) | **new (schema 2.0.0)** |
|---|---:|---:|
| flows LightGBM classifies as an attack | 1 ("DoS Slowhttptest", an ICMP flow) | **0** |
| flows Isolation Forest flags anomalous | **56.3%** | **10.3%** |
| flows with no ML evidence (out-of-domain protocol) | 0 | 1 (that ICMP flow) |
| threat levels | 779 LOW, 1 HIGH | **780 LOW** |
| decisions | 779 ALLOW, **1 RATE_LIMIT** | **780 ALLOW** |

Two findings came out of the first run of this replay and were fixed
before the numbers above:

1. **The one false action is an ICMP flow** — on both schemas, LightGBM
   called a flow to the Docker VM's DNS host "DoS Slowhttptest" (92% on
   2.0.0) and the new scoring BLOCKed it. The CICIDS2017 CSVs carry no
   protocol column, so the adapter only ever infers TCP or UDP: ICMP is
   outside the models' domain by construction. Fixed with
   `ML_DOMAIN_PROTOCOLS` (`pirewall/detection/coordinator.py`).
2. **The first per-pattern points made benign bursts MEDIUM** — busy-client
   patterns (45) plus Isolation Forest's residual ~10% false flag (15) put
   75 of 780 flows at MEDIUM (MONITOR, no rule, but one THREAT_DETECTED
   event each). Busy-pattern points were lowered (page load 30, 45 with a
   spurious anomaly → LOW) and SCANNING raised to 55 so the observed nmap
   pattern still reaches HIGH.

What this does **not** show: the KNOWN_ISSUES #1 symptom (Shopify/Cloudflare
traffic classified "Bot" at 99.9999%) did **not** reproduce on the old
pipeline here either — 0 TCP/UDP misclassifications. Plausible reasons, none
verified: the replay's kernel timestamps (see caveat); curl traffic is not a
phone's browser; or the Pi is not loading v0.4.0 at all. The only
LightGBM artifact on the development PC was v0.2.0, the diverged model
(macro-F1 0.197, raw scores up to 6.4e6) whose saturated confidences
match that symptom exactly. **Check which `model_version` the Pi's
`/api/v1/models` reports.**

## Attack traffic (124,130 flows)

Final branch state (after the FLOOD pattern and the responder fix below).
"First action" is packet time from the attacker's first packet to its first
RATE_LIMIT/BLOCK decision.

| attacker | attack | old (schema 1.0.0) | **new (schema 2.0.0)** | first action (new) |
|---|---|---|---|---:|
| `10.99.0.2` | nmap `-sS` 1–1000 | max LOW, never acted | **HIGH → RATE_LIMIT** (SCANNING + BURST + HIGH_FREQUENCY) | **0.00 s** |
| `10.99.0.3` | SYN flood, closed port | max LOW, never acted | **RATE_LIMIT** (FLOOD + rate patterns); 2 BLOCKs where LightGBM corroborated | **0.06 s** |
| `10.99.0.4` | UDP flood | max LOW, never acted | **RATE_LIMIT** (FLOOD + rate patterns) | **0.06 s** |
| `10.99.0.5` | 200 concurrent HTTP requests | max MEDIUM, never acted | **RATE_LIMIT** | 1.45 s |
| `10.99.0.1` | *the victim* (its RSTs/replies) | MEDIUM once | **LOW, never acted** | — |

Counts are per *flow decision*: e.g. ~56k RATE_LIMIT decisions for the SYN
flood. In the daemon these collapse into one rule per source — the
validator's duplicate stage and the A3 rate cap see to that, and the native
engine sheds most flood flows before they are even assessed.

Two more defects surfaced in the first attack replay, before the numbers
above:

3. **Floods against a closed port were never acted on.** Every SYN draws an
   RST, so nothing counts as an unanswered attempt, and the rate patterns
   are on/off — worth the same at 3/s and 3,000/s. Measured: the busiest
   benign client peaked at 39 new connections to one destination per 5 s;
   the floods at 21k–39k. Fixed with the FLOOD pattern (100/s to one
   destination, 80 points).
4. **The victim was rate-limited.** 60 stray RSTs from the target (sent
   after their flows had already closed) each opened a new flow "from" the
   target, which then looked like it was port-scanning its attacker. Fixed:
   only a connection initiation (TCP SYN without ACK/RST, or non-TCP) counts
   as a connection (`Flow.opened_by_initiation`). With 94% capture loss on
   the Pi, many SYN-ACKs arrive without their SYN, which is presumably why
   the 2026-09-10 attack lab flagged the Pi itself for scanning.

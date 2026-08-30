# pirewall — ADDENDUM_2 (v1 additions beyond ADDENDUM.md)

`docs/MASTER_SPEC.md` is frozen and stays verbatim. `docs/ADDENDUM.md` is the
first wave of agreed additions on top of it (A1-A8). This file is a second
wave, agreed after ADDENDUM.md was written. Where anything here conflicts
with `MASTER_SPEC.md` or `ADDENDUM.md`, **this file wins** — same rule
ADDENDUM.md established for itself, for the same reason: it's newer and more
specific. Every phase prompt tells you when to read this file.

Each item below: what it is, why it exists, and exactly what it changes,
following the same structure ADDENDUM.md uses for A1-A8.

---

## Why this pass exists

The original detection architecture evaluated every flow exactly once, at
completion — driven by `flow.active_timeout_seconds` /
`flow.inactive_timeout_seconds` (spec §8). That has two consequences worth
naming plainly:

1. **Fast volumetric attacks are detected only as fast as their constituent
   flows happen to complete, not as fast as the pattern is actually
   visible.** A port scan or a SYN flood reveals itself through the *rate and
   shape of new connections* — but the old architecture only folded a
   connection into `pirewall.detection.behavior`'s per-source counters once
   that connection's flow had already timed out or closed. Against the
   default 60s inactive timeout, a scan touching 50 ports in 2 seconds still
   took up to a minute to become visible as `SCANNING`.

2. **A tempting fix — periodically re-scoring partial (still-open) flows
   through the ML classifier — was considered and rejected.** It increases
   false positives on legitimately slow/long-lived benign traffic. This
   isn't theoretical: a real incident during this project's own traffic
   observation surfaced a DHCP broadcast flow misclassified as
   `DoS Slowhttptest` at 89% confidence by re-scoring partial flow shape.
   Partial-flow shape is inherently ambiguous between "a slow attack" and
   "ordinary slow benign traffic" (a DHCP lease renewal, a chatty IoT
   device's keepalive, a large backup transfer) — scoring it more often just
   samples that ambiguity more often, it doesn't resolve it. The classifier
   was trained on *completed*-flow statistics (spec §11); feeding it
   in-progress, structurally different partial data is an out-of-distribution
   query, and its confidence output doesn't know that.

The redesign below splits detection into distinct tracks, each suited to the
*kind* of evidence it actually has, instead of forcing every attack type
through one per-flow-completion pipeline:

* **B1** moves the *volumetric/behavioral* track off flow completion
  entirely — these signals (destination diversity, port diversity, burst
  rate) are knowable from connection *metadata* the instant a flow opens,
  and are safe to act on quickly because they are already aggregate,
  multi-observation signals by construction (see B1's "why this is safe to
  act on quickly" note).
* **B2** adds a new aggregate signal (slow-rate/slowloris-class DoS) to the
  same volumetric track, deliberately *not* by re-scoring ambiguous partial
  flows — it treats "many concurrent slow connections to one destination"
  as a source-level pattern, the same category of evidence as the existing
  scanning/burst signals, rather than a per-flow classification question.
* **B3** makes the "don't act on weak evidence" property from #2 above an
  explicit, testable, named invariant instead of an emergent side effect of
  today's tuned thresholds/weights — so it survives a future retrain or
  threshold change instead of quietly eroding.
* **B4/B5** add two narrow, cleartext-only protocol-structure signals (TLS
  heartbeat length mismatch, TLS ClientHello fingerprinting) that are
  genuinely different from the payload inspection spec §7 rules out — see
  each section's own explicit discussion of that distinction.
* **B6** is an honest empirical check of whether B1's speed-up incidentally
  helps against a class of attack pirewall was never designed to see
  content for (automated web-app probing).

---

## B1. Decouple fast/volumetric behavioral detection from flow completion

*(filled in when B1 is implemented — see the B1 commit)*

## B2. New slow-rate aggregate detection signal

*(filled in when B2 is implemented — see the B2 commit)*

## B3. Explicit maturity/evidence-based action-capping invariant

*(filled in when B3 is implemented — see the B3 commit)*

## B4. Heartbleed detector — TLS record-layer length check

*(filled in when B4 is implemented — see the B4 commit)*

## B5. TLS ClientHello fingerprinting for known attack tooling (JA3-style)

*(filled in when B5 is implemented — see the B5 commit)*

## B6. Empirical test: does the volumetric layer catch automated web-app probing?

*(filled in when B6 is implemented — see the B6 commit)*

---

## Summary — what changes where

| Item | Touches |
|------|---------|
| B1 Creation-time behavior counters | `pirewall/detection/behavior.py`, `pirewall/flow/aggregator.py`, `pirewall/runtime/core.py` |
| B2 Slow-rate aggregate signal | `pirewall/detection/behavior.py`, `pirewall/config/models.py`, `config/default_config.toml` |
| B3 Evidence-maturity gate | `pirewall/engine/decision.py`, `pirewall/config/models.py` |
| B4 Heartbleed detector | `pirewall/detection/tls_heartbeat.py` (new), `pirewall/capture/parser.py`, `pirewall/engine/scoring.py`, `pirewall/engine/threat.py`, `pirewall/core/models/evidence.py`, `pirewall/core/models/threat.py`, `pirewall/core/models/detection_record.py`, `pirewall/runtime/core.py` |
| B5 JA3 fingerprinting | `pirewall/detection/tls_fingerprint.py` (new), `config/known_tool_fingerprints.toml` (new) |
| B6 Empirical test | `tests/` only, no runtime code |
| §7 WAFFY scope boundary | `docs/ARCHITECTURE.md`, `docs/PROJECT_SUMMARY.md` (docs only) |

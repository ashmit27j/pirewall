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

**What:** `pirewall.detection.behavior`'s per-source rolling state
(`SourceBehaviorState`) now updates in two places instead of one:

* `observe_new_connection` (new) — folds in everything knowable the instant
  a flow *opens*: destination, destination port, timestamp. This drives
  `connection_count`, `destinations`, `ports`, `connections_per_destination`,
  and `recent_connection_times` — every input the SCANNING, DESTINATION_
  DIVERSITY, REPEATED_CONNECTIONS, HIGH_FREQUENCY, BURST, PERSISTENCE, and
  TEMPORAL_PATTERN checks in `_assess_state` read.
* `observe_completion` (new) — folds in the one signal that genuinely
  cannot be known until a flow ends: `failure_count`, from
  `backward_packet_count == 0`.
* `observe_flow` (existing name, kept) — both of the above against one
  already-completed `Flow` in a single call. Every pre-existing test in
  `tests/unit/test_behavior.py` calls this and needed **zero changes** —
  it reproduces the old behavior exactly. It's also the fallback
  `observe_completion` uses when no creation-time state exists yet (see
  "no double-counting" below).

**Wiring:** `pirewall.flow.aggregator.FlowAggregator` gained an
`on_new_flow: Callable[[NewFlowSignal], None] | None` constructor
parameter, invoked exactly once per flow — right when a genuinely new
`FlowKey` is inserted into the table, never on a later packet of the same
flow, never on eviction or completion. `NewFlowSignal` is a plain frozen
dataclass (source/destination/port/protocol/timestamp), not a Pydantic
model — same category as `pirewall.capture.interfaces.CapturedPacket`:
internal plumbing between layers, not a domain object crossing an API
boundary (spec §9).

This is a `Callable`, not an import, on purpose: `pirewall.flow` must not
depend on `pirewall.detection` (`CLAUDE.md`'s "dependencies flow one
direction" — capture -> flow/features -> detection -> engine -> firewall).
`pirewall.runtime.core.CoreDaemon` (top of that chain, allowed to know
about everything) is what actually connects the two: it enqueues each
`NewFlowSignal` onto a new bounded `_new_flow_queue` from the **capture**
thread, and a new `_drain_new_flow_signals` step in the **detection**
thread's loop drains it into `DetectionCoordinator.behavior_analyzer.
observe_new_connection` at least once per `_QUEUE_POLL_SECONDS` (0.5s).
Routing through this second queue — rather than calling
`BehaviorAnalyzer` directly from the capture thread — keeps `BehaviorAnalyzer`
mutated from exactly one thread, same as before this change, with no new
locking. `DetectionCoordinator.analyze` (still detection-thread-only, at
flow completion) now calls `observe_completion`, never `observe_flow`.

**Why the volumetric signals are safe to act on quickly, explicitly stated
per the phase prompt's request:** every one of them is already an
*aggregate, multi-observation* signal by construction, not a single-packet
trigger — `scanning_port_threshold` (default 10 distinct ports),
`repeated_connections_threshold` (20), `destination_diversity_threshold`
(15), and `burst_count_threshold` (10) all require that many *distinct*
qualifying observations from the same source before firing, regardless of
whether those observations happen to be recorded at flow creation or flow
completion. Moving *when* they update doesn't change *how much* evidence
they require to fire — B3 below makes this an explicit, checked invariant
rather than leaving it as something only true by inspection of today's
threshold values.

**No double-counting:** a real production flow gets exactly one
`observe_new_connection` call (at creation, via the queue) and exactly one
`observe_completion` call (at completion, via `DetectionCoordinator.analyze`)
— `observe_completion` never re-adds to `destinations`/`ports`/
`connection_count`, only `failure_count`. The one deliberate exception:
if a flow's creation-time signal never arrived (dropped under new-flow-queue
backpressure, or its source was LRU-evicted from `BehaviorAnalyzer` between
creation and completion), `observe_completion` falls back to a full
`observe()` rather than silently losing that flow's evidence — this is a
*single* state, recreated fresh in the eviction case, so it cannot double
anything that came before it.

**Tested:**
`tests/unit/test_behavior.py` (`test_scanning_detected_from_new_connections_before_any_completion`,
`test_single_new_connection_triggers_nothing`,
`test_observe_completion_before_any_new_connection_falls_back_to_full_observe`,
`test_observe_completion_does_not_double_count_a_connection_already_observed`,
plus all 6 pre-existing tests passing unmodified);
`tests/unit/test_flow_aggregator.py` (`test_on_new_flow_fires_once_per_new_flow_not_per_packet`,
`test_on_new_flow_fires_again_for_a_genuinely_new_flow_from_the_same_ports`,
plus all 9 pre-existing tests passing unmodified);
`tests/integration/test_core_daemon.py::test_scanning_visible_through_a_completing_flow_while_scan_flows_stay_open`
— written against the real `CoreDaemon` (real capture thread, real detection
thread, real queues, `FakePacketCapture`/`FakeFirewallBackend`), asserting
that 6 never-completed scan flows plus 1 completing flow from the same
source produce a `ThreatAssessment` (for the one flow that did complete)
already carrying `SCANNING`, while `list_flows()` shows only that one flow
ever completed — the literal claim of this section, exercised end to end.
**This last test is written and lint/type-clean but not executed in this
session**: `tests/integration/test_core_daemon.py` is entirely
`skipif(not hasattr(socket, "AF_UNIX"))`-gated (pre-existing, all 8 other
tests in that file are in the same state here) and this session ran on a
Windows dev machine, which lacks `AF_UNIX`. It should be run on the next
macOS/Linux session before relying on it.

**Not changed:** the actual pattern thresholds/config fields, `_assess_state`
itself, and `ThreatAssessment`/scoring — B1 only changes *when* the inputs
to `_assess_state` are collected, not the detection logic itself.

## B2. New slow-rate aggregate detection signal

**What:** a new `BehaviorPatternType.SLOW_RATE_DOS` pattern, structurally
the same category of evidence as `SCANNING`/`BURST` — a source-level
aggregate observation, not a per-flow classification of any single
ambiguous connection. Fires when `concurrent_slow_connections_threshold`
(default 8) or more currently-open flows from one source to one destination
have each been open at least `slow_connection_min_duration_seconds`
(default 15.0) while averaging at most `slow_connection_max_bytes_per_second`
(default 5.0) — new fields under `[detection]`.

**Implementation:**

* `pirewall.flow.aggregator.FlowAggregator.snapshot_slow_connection_clusters`
  (new) — iterates the *currently open* flow table (never pops, closes, or
  otherwise mutates a flow; the connections keep running exactly as they
  were), groups qualifying flows by (source, destination), and returns one
  `SlowConnectionCluster` per pair that meets the concurrency threshold.
  `SlowConnectionCluster.representative_flow` is a point-in-time snapshot
  of one qualifying flow's accumulated stats so far (`FlowState.to_flow`,
  the exact same conversion flow *completion* uses — just called without
  removing the flow from the table).
* `pirewall.detection.behavior.SourceBehaviorState`/`BehaviorAnalyzer`
  gained `note_slow_connections` — records a *live snapshot* count per
  destination (overwrites, doesn't accumulate: this is "how many qualify
  right now", not an event). `_assess_state` adds `SLOW_RATE_DOS` when
  `max_concurrent_slow_connections >= concurrent_slow_connections_threshold`.
* **Wiring, reusing the existing pipeline rather than building a parallel
  one:** `pirewall.runtime.core.CoreDaemon`'s sweep loop (already runs on
  `flow.cleanup_interval_seconds`, already iterates the flow table for
  `sweep_timeouts`) now also calls `snapshot_slow_connection_clusters` on
  the same pass — cheap (a duration/byte-count comparison per open flow, no
  feature extraction, no ML) so piggybacking costs nothing extra. Each
  cluster is handed to the detection thread through a new bounded
  `_slow_cluster_queue` (same reasoning as B1's `_new_flow_queue`:
  `BehaviorAnalyzer` must stay mutated from exactly one thread). The
  detection thread's `_drain_slow_clusters` records the cluster's count via
  `note_slow_connections` and then pushes `representative_flow` onto the
  *same* flow queue every genuinely completed flow uses — from there it
  goes through the completely unmodified
  `FlowPipeline` -> `DetectionCoordinator` -> `assess_threat` -> `decide` ->
  `generate_candidate_rule` -> `FirewallManager.submit_candidate` chain,
  producing a real (or SHADOW-logged) `RATE_LIMIT`/`BLOCK` decision the same
  way any other detection does. **Not** counted in the `flows_completed`
  metric (`RuntimeCounters`) — that would misrepresent a still-open
  connection as a completed one; it's pushed directly onto the flow queue
  instead of through `_enqueue`.

**Why this avoids the DHCP-style false positive** (the incident this whole
pass's intro describes): a single ordinary slow connection — one IoT device
polling slowly, one legitimate long download, one DHCP-adjacent
long-lived flow — produces a concurrent count of 1 at its destination,
which never approaches `concurrent_slow_connections_threshold` (8). Only a
genuine many-connections-at-once pattern to the *same* destination does.
This is the same "aggregate, multi-observation signal by construction"
argument B1 makes for `SCANNING`/`BURST`, applied to a new pattern —
`test_single_slow_connection_does_not_trigger_slow_rate_dos` is the direct
regression test.

**A known, disclosed side effect of reusing the pipeline rather than
building a parallel one**: while a qualifying slow-connection cluster
persists, its representative flow is re-snapshotted and re-pushed through
the pipeline on every sweep interval. This is safe from a rule-management
standpoint — a repeat candidate targeting an already-`ACTIVE` rule's exact
target is rejected at the validator's `duplicate` stage, before it can
consume any of A3's rate-cap budget — but in `SHADOW` mode (the default),
where nothing ever becomes `ACTIVE`, this does mean a new `ThreatAssessment`
and `SHADOWED` event get logged every sweep interval for as long as the
pattern persists, rather than exactly once. Documented rather than
suppressed: a human watching the shadow log during the recommended
SHADOW-mode observation period would see this as "still ongoing", not as
independent repeat detections, and A3's window rate-cap still bounds any
*enforced* consequence of it in ACTIVE/ASSISTED mode.

**Tested:**
`tests/unit/test_behavior.py` (`test_slow_rate_dos_detected_from_concurrent_slow_connection_count`,
`test_single_slow_connection_does_not_trigger_slow_rate_dos`,
`test_slow_connection_count_is_a_live_snapshot_not_an_accumulator`);
`tests/unit/test_flow_aggregator.py`
(`test_snapshot_slow_connection_clusters_finds_a_qualifying_cluster_without_closing_flows`,
`test_snapshot_slow_connection_clusters_ignores_a_single_slow_connection`,
`test_snapshot_slow_connection_clusters_ignores_flows_below_the_duration_floor`,
`test_snapshot_slow_connection_clusters_ignores_flows_above_the_rate_ceiling`).
Adding `SLOW_RATE_DOS` changed `BehaviorPatternType`'s member count from 8
to 9, which shifted the behavior-confidence/scoring-contribution fraction
(`len(detected_patterns) / len(BehaviorPatternType)`) — three pre-existing
tests hardcoding the old total (`test_behavior_pattern_type_values`,
`test_behavior_contribution_scales_with_pattern_count`,
`test_multiple_corroborating_evidence_types_sum`) were updated to the new
denominator; no production code has a hardcoded total (both use
`len(BehaviorPatternType)`). `ruff check .` and `pyright --strict` clean
across the whole repo; full suite 566 passed, 22 skipped, the same 1
pre-existing unrelated failure as B1 (see B1's section).

**Written, not executed this session** (same `AF_UNIX`-on-Windows
constraint as B1's end-to-end test):
`tests/integration/test_core_daemon.py::test_slow_rate_dos_detected_without_waiting_for_connections_to_close_or_time_out`
— 6 bare, never-FIN'd, never-timed-out SYN connections from one source to
one destination, asserting a `ThreatAssessment` carries `SLOW_RATE_DOS`
purely from the sweep loop's periodic snapshot. Run this on the next
macOS/Linux session.

## B3. Explicit maturity/evidence-based action-capping invariant

**What:** a real, named, testable invariant in `pirewall.engine.decision`:
no `ThreatAssessment` may produce a `BLOCK` or `RATE_LIMIT`
`FirewallDecision` unless it carries "mature" evidence, defined as exactly
one of:

* **(a)** a completed flow's known-attack classification
  (`known_evidence is not None`) — conclusive by what it *is*;
* **(b)** a behavioral pattern that already requires multiple independent
  observations by construction (`behavior_assessment.detected_patterns`
  non-empty) — every current `BehaviorPatternType` qualifies, including B2's
  new `SLOW_RATE_DOS`;
* **(c)** the same weak-but-elevated reading from the same source, recurring
  across `ThreatConfig.evidence_maturity_consistency_windows` (default 3)
  consecutive independent assessment windows that failed (a)/(b) —
  `EvidenceMaturityTracker`, a new bounded (LRU, same shape as
  `BehaviorAnalyzer`) per-source counter.

Anything reaching `BLOCK`/`RATE_LIMIT` without meeting one of these is
downgraded to `MONITOR` — never silently dropped, never re-scored, just
capped to the next mildest action, same ladder the rest of the module
already uses.

**Where it lives, and why:** `pirewall.engine.decision`, not
`pirewall.firewall.validator`. By the time a candidate rule reaches the
validator, its `action` (BLOCK/RATE_LIMIT/etc.) is already baked in from
the `FirewallDecision` that generated it (`pirewall.firewall.generator`
just copies `decision.action`) — downgrading at the validator stage would
mean either rejecting an otherwise-valid candidate outright (losing the
MONITOR-level visibility entirely) or regenerating a different candidate
from a different action mid-validation, which the validator's chain isn't
shaped for. Capping the action *before* a candidate rule is ever generated
means nothing downstream — generator, validator, manager, backend — ever
sees an immature BLOCK/RATE_LIMIT at all.

**Confirming this doesn't weaken anything already trusted** (the phase
prompt's explicit ask): under the current scoring weights
(`known_attack_weight=60`, `anomaly_weight=15`, `behavior_weight=25`,
`docs/ML_PIPELINE.md`), the maximum score reachable with *neither* (a) nor
(b) is `known_attack_weight + anomaly_weight = 75` — exactly
`high_threshold`, never `critical_threshold` (90) — and `known_evidence`
being present at all already satisfies (a). So today, path (c) is the
*only* way anything reaches `CRITICAL`/`BLOCK` without already qualifying
under (a) or (b); every completed-flow classification and every
volumetric-pattern scenario from earlier phases' tests is unaffected,
confirmed by `tests/unit/test_decision.py::test_high_maps_to_rate_limit_with_mature_evidence`
/ `test_critical_maps_to_block_with_mature_evidence` (realistic,
evidence-carrying HIGH/CRITICAL scenarios — the same shape real detection
actually produces) and `test_behavior_pattern_alone_is_sufficient_for_block`
still producing `RATE_LIMIT`/`BLOCK` as before. This is a safety net for a
future retrain or threshold change, not a new bottleneck on today's
detection.

**Tested:** `tests/unit/test_decision.py` — `test_high_without_mature_evidence_downgrades_to_monitor`
/ `test_critical_without_mature_evidence_downgrades_to_monitor` (the
literal "genuinely insufficient evidence, regardless of raw score" case
the phase prompt asked for), `test_consistency_tracker_grants_maturity_after_enough_windows`
(the 3rd of 3 consecutive weak windows from the same source flips
MONITOR->MONITOR->BLOCK), `test_consistency_tracker_is_per_source` (a
second source's first observation doesn't inherit another source's
streak), plus the "still produces BLOCK/RATE_LIMIT correctly" tests above.
`ruff check .` and `pyright --strict` clean across the whole repo; full
suite 571 passed, 22 skipped, the same 1 pre-existing unrelated failure
noted under B1.

## B4. Heartbleed detector — TLS record-layer length check

**What:** `pirewall.detection.tls_heartbeat.check_heartbleed` parses a raw
TCP payload as a TLS record, and — only for content type 24 (Heartbeat) —
compares the heartbeat message's claimed `payload_length` field against how
many bytes the record's own fragment actually contains. A mismatch
(`claimed_payload_length > available_bytes`) is exactly the CVE-2014-0160
signature: a vulnerable server trusts the claimed length when building its
response, leaking whatever heap memory follows its real (small) payload
buffer. This is the same field-relationship network-based scanners checked
against real CVE-2014-0160 servers in 2014 — not a technique invented here.

**Why this is not "payload inspection" in spec §7's sense** (stated
explicitly per the phase prompt's request, since it matters for the
paper's honesty): spec §7 rules out inspecting *application content* — an
HTTP body, message text, anything that was ever meant to be read by the
application at the other end. A TLS record header and a heartbeat message
header are neither of those things. They are sent **in cleartext, by
protocol design**, before any encrypted application data exists on the
connection — the same category of work as `pirewall.capture.parser`
reading a TCP header's data-offset field. `check_heartbleed` parses
exactly two fixed-width integers out of those headers; it never touches,
and structurally cannot touch, anything that was ever encrypted.

**Implementation:**

* `pirewall/detection/tls_heartbeat.py` (new) — pure, degrades to `None`
  for anything that isn't cleanly a heartbeat-record length mismatch
  (wrong content type, truncated, a well-formed heartbeat). Never raises
  (wrapped in its own belt-and-suspenders `except Exception`, matching
  `pirewall.capture.parser.parse_packet`'s own guard).
* `pirewall.capture.parser.extract_tcp_payload` (new) — the one place raw
  TCP payload bytes are ever produced at all. Deliberately **not** added
  to `PacketMetadata` (the path every other consumer — flow aggregation,
  features, ML — actually uses): that would put payload bytes one field
  away from every consumer of the primary parse path, exactly the exposure
  spec §7 exists to avoid. It duplicates a small amount of `parse_packet`'s
  own IPv4/TCP offset arithmetic instead, in a function whose only callers
  are the new TLS detectors.
* `pirewall.capture.pipeline.capture_packets` gained an optional
  `on_tcp_payload: Callable[[PacketMetadata, bytes], None]` callback — a
  plain `Callable`, not an import of anything detection-related, same
  pattern as its existing `on_event` and `FlowAggregator.on_new_flow`
  (ADDENDUM_2.md B1). Invoked only for already-successfully-parsed TCP
  packets on port 443 (the same 443 heuristic B5 uses) — capture itself
  still never imports `pirewall.detection`.
* **Wiring, end to end:** `pirewall.runtime.core.CoreDaemon._handle_tcp_payload`
  (the actual callback, capture-thread-only) extracts the payload, runs
  `check_heartbleed`, and on a match caches a `_CachedTlsMatch` in a new
  bounded LRU `_tls_evidence` dict keyed by the packet's `FlowKey` — the
  *same* undirected key `pirewall.flow.aggregator.FlowAggregator` uses for
  its own table, guarded by the same `_flow_lock`. A match can't be
  attached to a `ProtocolSignatureEvidence` yet at capture time because
  that model requires `flow_id`, which isn't minted until the flow
  actually completes. When a flow *does* complete, the detection thread's
  `_pop_tls_evidence` looks up (and consumes) any cached match by
  recomputing the same key from the completed `Flow`'s own fields, fills
  in the real `flow_id`, and hands the resulting `ProtocolSignatureEvidence`
  into `FlowPipeline.process` -> `DetectionCoordinator.analyze` (now embeds
  it in `DetectionRecord`) -> `assess_threat` (new
  `protocol_signature_weight=75` contribution, `weight * confidence`, same
  shape as known-attack) -> `ThreatAssessment.protocol_signature_evidence`
  — reusing 100% of the existing evidence/scoring/decision machinery, no
  parallel path.
* **B3 interaction**: a positive `protocol_signature_evidence` was added as
  a third qualifying case under the evidence-maturity gate's path (a) — see
  `pirewall.engine.decision`'s updated module docstring — since it's a
  deterministic structural match, not a raw score, the same category of
  conclusiveness as a completed-flow ML classification.

**Tested:** `tests/unit/test_tls_heartbeat.py` (9 tests) — the literal
CVE-2014-0160 proof-of-concept byte shape detected, a well-formed heartbeat
with correct padding not triggering, Handshake/ApplicationData records not
triggering, and five malformed/truncated/lying-about-its-own-length
variants degrading to `None` without raising. `tests/unit/test_parser.py`
(7 new tests) — `extract_tcp_payload` against valid TCP-with-payload,
bare-SYN, IPv6, UDP, truncated, and a declared `total_length` far exceeding
what was actually captured (proving the bound is against captured bytes,
not the attacker-controlled header field). `tests/integration/
test_capture_pipeline.py` (2 new tests) — `on_tcp_payload` fires for TCP
port 443 only, never for other TCP or UDP traffic, and is safely omittable.

**`tests/integration/test_tls_evidence_wiring.py` (new, 5 tests) — a real,
executable end-to-end test, not just written-and-unverified.** Unlike
`test_core_daemon.py`, this constructs a `CoreDaemon` and calls its
capture-thread/detection-thread methods (`_handle_tcp_payload`,
`_pop_tls_evidence`, `_pipeline.process`) directly, **never** calling
`.start()`/`.stop()` — those are what bind the real `AF_UNIX` RPC socket
this Windows dev session cannot open. Everything this pass's B4 wiring
actually does lives below that socket, in already-constructed subsystems,
so this genuinely runs (and passed) here: a hand-built Heartbleed-signature
packet gets cached by flow key, popped correctly when a matching `Flow`
completes (and consumed — a second pop finds nothing), an unrelated flow's
pop finds nothing, and feeding the result through the real
`FlowPipeline.process` produces a `ThreatAssessment` with
`protocol_signature_evidence` populated, `threat_level` at `HIGH`/
`CRITICAL`, and a `RATE_LIMIT`/`BLOCK` decision (confirming the B3 gate's
path (a) extension actually works end to end). `ruff check .` and
`pyright --strict` clean across the whole repo; full suite 594 passed, 22
skipped, the same 1 pre-existing unrelated failure noted under B1.

**Environment-dependent**: real TLS traffic diversity on real hardware —
this session's traffic is all hand-constructed. The parsing logic itself
is exercised thoroughly (above); what's unverified is how real-world TLS
implementations' heartbeat/record framing behaves in practice (e.g.
multiple records coalesced into one TCP segment, or a heartbeat split
across segments — both are simply not detected by design, since detection
only inspects a single captured TCP payload slice at a time; documented as
a known limitation, not a crash risk, since malformed/incomplete input
already degrades to `None`).

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

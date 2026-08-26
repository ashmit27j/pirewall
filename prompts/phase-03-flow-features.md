# Phase 3 — Flow aggregation & canonical feature extraction

Read `CLAUDE.md` and `docs/MASTER_SPEC.md` sections 8, 11 before starting.
Confirm Phase 2 is marked complete in `docs/PROGRESS.md`.

**Addendum A5 (IPv4-only v1 scope):** the flow aggregator and feature schema
target IPv4 flows for the adaptive pipeline. IPv6 packets from Phase 2 may
still be counted in capture/flow statistics, but do not build IPv6 flows
into the feature-extraction path that feeds ML/threat-scoring — document
this boundary clearly in `pirewall/features/schema.py`'s docstring so it's
unambiguous to later phases.

## Goal

Turn a stream of `PacketMetadata` into bounded, bidirectional `Flow` objects,
then deterministically turn each `Flow` into a `FeatureVector` using the one
canonical extractor that training (Phase 4) and runtime inference (Phase 5)
will both call — no duplicated feature math anywhere else, ever.

## Deliverables

1. **`pirewall/flow/key.py`** — flow-key construction from (source IP,
   destination IP, source port, destination port, protocol) with consistent
   bidirectional normalization (spec §8) — i.e. A→B and B→A packets land in
   the same flow, with a defined "forward" direction (e.g. the direction of
   the first packet).

2. **`pirewall/flow/state.py`** — the flow table: bounded size (configurable
   max via Phase 1's config), eviction policy when full, per-flow accumulated
   state (first/last timestamp, duration, packet/byte counts split
   forward/backward, TCP flag counts, packet-size statistics, inter-arrival
   statistics) matching spec §8.

3. **`pirewall/flow/timeout.py`** — active timeout and inactive timeout logic
   (configurable), flow completion detection (e.g. FIN/RST for TCP).

4. **`pirewall/flow/aggregator.py`** — the orchestrator: consumes
   `PacketMetadata` (from Phase 2, or a `FakePacketCapture` in tests), routes
   into the flow table via `key.py`, applies timeouts, emits completed
   `Flow` objects (Phase 1's model), supports graceful shutdown (flush
   in-progress flows per spec §43 semantics, even though full shutdown
   orchestration is a later phase).

5. **`pirewall/features/schema.py`** — the canonical, versioned feature
   schema: an explicit ordered list of features with name, type, unit,
   description, and a `schema_version` string/int. This is the single source
   of truth — no other module may define its own feature list.

6. **`pirewall/features/extractor.py`** — `Flow → FeatureVector`,
   deterministic (same `Flow` in, same `FeatureVector` out, every time), and
   driven entirely by `schema.py`'s definition. This is the module Phase 4's
   dataset adapters and Phase 5's runtime inference will both import — do not
   let either of those phases reimplement this logic later.

## Explicit non-goals for this phase

No ML, no dataset adapters, no detection/threat logic. Stop at
`FeatureVector`.

## Tests (`tests/unit/`)

- Flow key normalization: A→B and B→A packets produce the same flow key and
  correct forward/backward attribution.
- Bounded flow table: feeding more flows than the configured max triggers
  eviction, table size never exceeds the bound (a flood test using
  `FakePacketCapture` with thousands of distinct flows).
- Active and inactive timeout both correctly complete/evict flows.
- Feature extraction determinism: running the extractor twice on an
  identical `Flow` produces an identical `FeatureVector`.
- Feature schema versioning: extractor output always carries the current
  `schema_version`.
- Aggregation correctness: known packet sequences produce the expected
  packet/byte counts, TCP flag counts, and duration.

## Definition of done

Everything in `CLAUDE.md` → "Definition of done for a phase". Update
`docs/PROGRESS.md` row for Phase 3.

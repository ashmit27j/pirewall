# pirewall — Canonical Feature Schema (spec §11, §15)

The single source of truth for feature names, order, units, and semantics
is `pirewall.features.schema` (`FEATURE_NAMES`, `SCHEMA_VERSION`,
`FEATURE_DEFINITIONS`). This document is a human-readable rendering of that
module — if the two ever disagree, the code wins; update this file to match
it, not the other way around.

**Current schema version: `1.0.0`.** Bump `SCHEMA_VERSION` only when the
feature names, order, or count change — not for documentation edits.

## Why one canonical schema

CLAUDE.md: "One canonical feature-extraction module. Training-time and
runtime inference call the *same* extractor — never reimplement feature
math twice." Concretely:

- `pirewall.features.extractor.extract_features(flow: Flow) -> FeatureVector`
  is the only code that computes these 28 values, called both by Phase 4's
  dataset adapters (training data) and Phase 5's runtime inference path.
- `pirewall.ml.inference.loader` refuses to load a model artifact whose
  `ModelMetadata.feature_schema_version`/`feature_ordering` don't exactly
  match the runtime `SCHEMA_VERSION`/`FEATURE_NAMES` — a stale or
  differently-trained model fails loudly at load time, not silently at
  inference time (see `docs/ML_PIPELINE.md`).

## IPv4-only scope (ADDENDUM.md A5)

Every feature is defined in terms of `pirewall.core.models.Flow`, whose
`source_ip`/`destination_ip` fields are typed `IPv4Address` (not a union)
— there is no code path by which an IPv6 packet reaches this schema.
`pirewall.flow.aggregator.FlowAggregator` enforces this upstream by never
routing an IPv6 `PacketMetadata` into the flow table at all.

## The 28 features

All values are computed once per completed `Flow`, deterministically (pure
function of the flow's own fields — no wall-clock or other hidden input).

| # | Name | Type | Unit | Description |
|---|------|------|------|-------------|
| 1 | `duration_seconds` | duration | seconds | Time between the flow's first/last packet. |
| 2 | `packet_count` | count | packets | Total packets observed in the flow. |
| 3 | `byte_count` | size | bytes | Total bytes observed in the flow. |
| 4 | `forward_packet_count` | count | packets | Packets in the initiating direction. |
| 5 | `backward_packet_count` | count | packets | Packets in the response direction. |
| 6 | `forward_byte_count` | size | bytes | Bytes in the initiating direction. |
| 7 | `backward_byte_count` | size | bytes | Bytes in the response direction. |
| 8 | `packets_per_second` | rate | packets/second | `packet_count / duration` (0 if duration is 0). |
| 9 | `bytes_per_second` | rate | bytes/second | `byte_count / duration` (0 if duration is 0). |
| 10 | `mean_packet_size` | size | bytes | Mean packet size across the flow. |
| 11 | `std_packet_size` | size | bytes | Std deviation of packet size. |
| 12 | `min_packet_size` | size | bytes | Smallest packet observed. |
| 13 | `max_packet_size` | size | bytes | Largest packet observed. |
| 14 | `mean_inter_arrival_seconds` | duration | seconds | Mean inter-packet time. |
| 15 | `std_inter_arrival_seconds` | duration | seconds | Std deviation of inter-packet time. |
| 16 | `min_inter_arrival_seconds` | duration | seconds | Smallest inter-packet time. |
| 17 | `max_inter_arrival_seconds` | duration | seconds | Largest inter-packet time. |
| 18 | `syn_count` | count | packets | TCP SYN flags observed. |
| 19 | `ack_count` | count | packets | TCP ACK flags observed. |
| 20 | `fin_count` | count | packets | TCP FIN flags observed. |
| 21 | `rst_count` | count | packets | TCP RST flags observed. |
| 22 | `psh_count` | count | packets | TCP PSH flags observed. |
| 23 | `urg_count` | count | packets | TCP URG flags observed. |
| 24 | `forward_backward_byte_ratio` | ratio | ratio | `forward_byte_count / backward_byte_count` (0 if backward is 0). |
| 25 | `destination_port` | port | port | Destination port, or `-1` if none (e.g. ICMP). |
| 26 | `protocol_is_tcp` | flag | boolean | `1.0` if the flow's protocol is TCP, else `0.0`. |
| 27 | `protocol_is_udp` | flag | boolean | `1.0` if the flow's protocol is UDP, else `0.0`. |
| 28 | `protocol_is_icmp` | flag | boolean | `1.0` if the flow's protocol is ICMP, else `0.0`. |

There is a 29th boolean, `protocol_is_other` (`1.0` if the protocol is none
of TCP/UDP/ICMP, else `0.0`) — 28 numbered above plus this one, 29 features
total in `FEATURE_NAMES`. Listed last here to match its position at the end
of the schema table in `pirewall/features/schema.py`.

## Determinism and testing

`tests/unit/test_feature_schema.py` and `tests/unit/test_feature_extractor.py`
(Phase 3) cover: no duplicate names, `FeatureVector.values` always has
exactly `len(FEATURE_NAMES)` entries in schema order, calling
`extract_features` twice on an identical `Flow` produces identical output
(including `computed_at`, derived from `flow.last_seen` — never
`datetime.now()`), and zero-division guards (`packets_per_second`,
`bytes_per_second`, `forward_backward_byte_ratio` all default to `0.0`
rather than raising when their denominator is `0`).

## Dataset-adapter caveats

Real-world datasets don't always carry every raw signal this schema wants.
Documented per-adapter in `pirewall.ml.preprocessing.cicids_adapter`/
`unsw_adapter`'s module docstrings and `docs/PROGRESS.md`'s "Known
deviations" — summarized:

- **CICIDS2017**: has real per-packet-derived stats but reports
  forward/backward packet-size mean/std *separately*; combined into this
  schema's single overall `mean_packet_size`/`std_packet_size` via a
  pooled-variance formula (`pirewall.ml.preprocessing.common.combine_weighted_stats`).
  The published "MachineLearningCVE" release (verified against all 8 real
  files) has **no Source IP, Source Port, Destination IP, or Protocol
  column at all** — `source_ip`/`destination_ip` are a fixed documented
  placeholder (`10.255.255.1`/`.2`), `source_port` is always `None`, and
  `protocol` is *inferred* from TCP flag counts (nonzero -> TCP) with a
  well-known-UDP-port fallback, defaulting to TCP otherwise. Treat
  `protocol_is_tcp`/`protocol_is_udp`/`protocol_is_icmp` trained from this
  adapter as heuristic, not ground truth — see
  `pirewall.ml.preprocessing.cicids_adapter`'s module docstring for the
  exact rule.
- **UNSW-NB15**: the training/testing-partition CSVs have no
  source/destination IP/port columns and no per-packet TCP flag counts.
  `source_ip`/`destination_ip` are a fixed documented placeholder
  (`10.255.255.1`/`.2`), TCP flag counts are always `0`, and packet-size/
  inter-arrival stats only carry a real *mean* (min/max set equal to the
  mean, std set to `0.0`) since this dataset variant reports per-flow means
  only, not per-packet distributions.

Both are documented, honest limitations, not silent data corruption — a
human evaluating model quality trained on either dataset should account for
which fields are real vs. placeholder-derived.

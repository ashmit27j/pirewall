# pirewall — Canonical Feature Schema (spec §11, §15)

The single source of truth for feature names, order, units, and semantics
is `pirewall.features.schema` (`SCHEMA_VERSION`, `FEATURE_NAMES`,
`FEATURE_DEFINITIONS`, and the frozen legacy exports). This document is a
human-readable rendering of that module — if the two ever disagree, the
code wins; update this file to match it, not the other way around.

**Current schema version: `3.0.0`** (23 features). Phase 19 introduced it
for the v2 models trained from pirewall's own pcaps. Version `2.0.0` is
frozen and remains computable only so the shipping v1 models keep working
under `engine = "v1"`.

Bump `SCHEMA_VERSION` whenever feature names, order, count, **or meaning**
change — 2.0.0 is the proof that meaning matters as much as names: see
"Why 2.0.0" below. The model loader refuses an unknown version, a version
the caller did not ask for, or an artifact whose ordering disagrees with
its own declared version, so a mismatched model is simply not loaded
(detection degrades to behavior-only and says so) rather than fed features
it was never trained on.

## Why one canonical schema, and how versions coexist

CLAUDE.md: "One canonical feature-extraction module. Training-time and
runtime inference call the *same* extractor — never reimplement feature
math twice." Concretely:

- `pirewall.features.extractor.extract_features(flow, schema_version=...)`
  is the only code that computes these values, called both by the dataset
  scripts (training data) and runtime inference.
- The primitive math is computed once per flow. A **versioned column
  projection** then selects the ordered names for the requested frozen
  version. 2.0.0 therefore keeps emitting exactly its old vector (including
  the raw `destination_port`), while 3.0.0 emits the coarse
  `destination_port_category` instead. There is no second extractor and no
  duplicated arithmetic.
- `pirewall.ml.inference.loader` validates an artifact against the frozen
  ordering **of its own declared version**, and optionally pins an expected
  version. `pirewall.ml.inference.common.validate_feature_vector` performs
  the equivalent per-call check, so a vector from one version can never
  reach a model trained on another.

Supported versions live in `SUPPORTED_SCHEMA_VERSIONS`:

| Version | Status | Used by |
|---|---|---|
| `3.0.0` | current | v2 D2/D3 models, new dataset builds |
| `2.0.0` | frozen legacy | shipping v1 models under `engine = "v1"` |

## Why 3.0.0

3.0.0 changes exactly one thing relative to 2.0.0: the raw integer
`destination_port` becomes a coarse, documented service category.

Raw ports, IPs, MACs, OUIs, SNI, application names and timestamps are
identity or shortcut features and must never be model inputs
(`docs/ADDENDUM_4.md` D3, `docs/v2/critique_ml.md` §3). A model trained on
raw ports can learn "8080 means Bot" rather than the shape of an attack. The
category keeps the useful service signal (web vs DNS vs SSH vs mail vs
other well-known vs ephemeral) while discarding the exact port. The
shortcut audit reports the model with and without the category; if the
category is doing suspicious work, that ablation shows it.

### Port-category mapping (total over `int | None`)

| Code | Category | Ports |
|---:|---|---|
| 0 | `NONE` | no L4 destination port (e.g. ICMP) |
| 1 | `WEB` | 80, 443, 8080, 8443 |
| 2 | `DNS` | 53 |
| 3 | `SSH` | 22 |
| 4 | `MAIL` | 25, 110, 143, 465, 587, 993, 995 |
| 5 | `OTHER_WELL_KNOWN` | any other port in 0..1023 |
| 6 | `EPHEMERAL` | any port ≥ 1024 not in a named bucket |

The integer is a stable category code, not an ordinal measurement. A tree
model may split on it; no consumer may treat "web > dns" as a magnitude.

## Why 2.0.0 (measured on the real CICIDS2017 CSVs, 2026-10-15)

| 1.0.0 feature(s) | Training (CICFlowMeter CSV) | Runtime (pirewall 1.0.0) | Evidence |
|---|---|---|---|
| all sizes, byte counts, byte rates, byte ratio | **L4 payload** bytes | **IP total length** (payload + 40+ header bytes) | 84% of benign port-443 training flows have a 0-byte minimum packet — impossible for an IP length |
| `std_packet_size`, `std_inter_arrival_seconds` | **sample** std (n−1) | population std (n) | a 2-packet flow of sizes 0 and 7 has CSV std 4.9497 = 7/√2, not 3.5 |
| `syn/ack/fin/rst/psh/urg_count` | effectively 0/1, with no reproducible rule | true per-packet counts | max 1.0 everywhere; SYN "present" on 13% and ACK on 28% of HTTPS flows, though nearly every TCP flow has both |
| `duration_seconds` | ≤ 120 s (CICFlowMeter's flow timeout) | up to 1800 s (`active_timeout_seconds`) | max training duration 119.99997 s |
| inter-arrival times | kernel (pcap) timestamps | Python `datetime.now()` at `recv()` | under any backlog, userspace timestamps compress every gap to loop time |

So every real flow sat in a region the models had never seen. Tree models
answer confidently there: the first real client session logged ordinary
Shopify/Cloudflare/Microsoft traffic as `Bot`/`FTP-Patator` at 99.99%+
(`docs/KNOWN_ISSUES.md` #1), and Isolation Forest flagged essentially all
benign traffic as anomalous (#2). The inter-arrival features the timestamps
distorted carry 47% of the model's gain.

2.0.0 fixes each row:

- sizes are read from `Flow.payload_stats` (L4 payload — `PacketMetadata.payload_length`
  at runtime, the CSV's own columns at training time); IP-level
  `byte_count`/`packet_size_stats` remain on `Flow` for everything that is
  not ML;
- every feature-bearing std is sample std (`RunningStats.sample_std`);
- the six flag counts are removed from the schema (they stay on `Flow` for
  behavior analysis, which uses its own definitions);
- `flow.active_timeout_seconds` defaults to 120, CICFlowMeter's value;
- capture timestamps come from the kernel (`SO_TIMESTAMPNS` on the Python
  path, `TPACKET_V3` block headers on the native path), truncated to whole
  microseconds — the resolution of both `datetime` and CICFlowMeter.

Ethernet padding: CICFlowMeter counts the padding of a wired minimum-size
frame as payload (a bare ACK reports 6 bytes; 14% of benign HTTPS flows have
minimum exactly 6). pirewall computes payload from the IP header's own
length, and the deployment captures Wi-Fi (no padding), so runtime reports 0
for that packet. The adapter normalizes a 1–6 byte *minimum* to 0; sums and
means keep the (≤ 6 bytes per padded packet) inflation, which aggregate
columns cannot undo.

## IPv4-only scope (ADDENDUM.md A5)

Every feature is defined in terms of `pirewall.core.models.Flow`, whose
`source_ip`/`destination_ip` fields are typed `IPv4Address` (not a union)
— there is no code path by which an IPv6 packet reaches this schema.
`pirewall.flow.aggregator.FlowAggregator` (and the native engine, which
mirrors it) never route an IPv6 packet into the flow table.

## The 23 features (3.0.0)

All values are computed once per completed `Flow`, deterministically (pure
function of the flow's own fields — no wall-clock or other hidden input).
"Payload" always means bytes after the TCP/UDP/ICMP header.

| # | Name | Type | Unit | Description |
|---|------|------|------|-------------|
| 1 | `duration_seconds` | duration | seconds | Time between the flow's first/last packet. |
| 2 | `packet_count` | count | packets | Total packets observed in the flow. |
| 3 | `forward_packet_count` | count | packets | Packets in the initiating direction. |
| 4 | `backward_packet_count` | count | packets | Packets in the response direction. |
| 5 | `payload_byte_count` | size | bytes | L4 payload bytes, both directions. |
| 6 | `forward_payload_byte_count` | size | bytes | L4 payload bytes, initiating direction. |
| 7 | `backward_payload_byte_count` | size | bytes | L4 payload bytes, response direction. |
| 8 | `packets_per_second` | rate | packets/second | `packet_count / duration` (0 if duration is 0). |
| 9 | `payload_bytes_per_second` | rate | bytes/second | `payload_byte_count / duration` (0 if 0). |
| 10 | `mean_payload_size` | size | bytes | Mean per-packet payload size. |
| 11 | `std_payload_size` | size | bytes | Sample std (n−1) of per-packet payload size. |
| 12 | `min_payload_size` | size | bytes | Smallest per-packet payload (0 for a bare ACK). |
| 13 | `max_payload_size` | size | bytes | Largest per-packet payload. |
| 14 | `mean_inter_arrival_seconds` | duration | seconds | Mean inter-packet time. |
| 15 | `std_inter_arrival_seconds` | duration | seconds | Sample std (n−1) of inter-packet time. |
| 16 | `min_inter_arrival_seconds` | duration | seconds | Smallest inter-packet time. |
| 17 | `max_inter_arrival_seconds` | duration | seconds | Largest inter-packet time. |
| 18 | `forward_backward_payload_ratio` | ratio | ratio | Forward/backward payload bytes (0 if backward is 0). |
| 19 | `destination_port_category` | category | code | Coarse service bucket; mapping above. |
| 20 | `protocol_is_tcp` | flag | boolean | `1.0` if the flow's protocol is TCP, else `0.0`. |
| 21 | `protocol_is_udp` | flag | boolean | `1.0` if the flow's protocol is UDP, else `0.0`. |
| 22 | `protocol_is_icmp` | flag | boolean | `1.0` if the flow's protocol is ICMP, else `0.0`. |
| 23 | `protocol_is_other` | flag | boolean | `1.0` if the protocol is none of TCP/UDP/ICMP. |

The frozen 2.0.0 list is identical except that row 19 is
`destination_port` (raw port, `-1` for none). `LEGACY_FEATURE_NAMES` and
`LEGACY_FEATURE_DEFINITIONS` expose it; new code must not train on it.

## Determinism and testing

- `tests/unit/test_feature_schema.py`: pinned name/order/version for both
  versions, 3.0.0 excludes the raw port and all identity fields, and the
  port-category mapping is total over every port plus `None`.
- `tests/unit/test_feature_extractor.py`: no duplicate names, schema order,
  determinism, zero-division guards, **the exact 2.0.0 vector is pinned
  unchanged**, an unknown version is refused, a flow without
  `payload_stats` is refused (never zero-filled), and changing only
  IP-level byte counts moves no feature.
- `tests/unit/test_flow_state.py`: payload accumulation and sample std.
- `tests/ml/test_cicids_adapter.py`: CSV payload columns land in
  `payload_stats`, pooled std is the exact sample std, padding
  normalization.
- `tests/unit/test_native_parity.py`: the native engine produces bit-identical
  `Flow`s to the Python aggregator on a mixed 6,700-frame stream — a second
  runtime implementation must not reopen the gap this version closed.
- `tests/integration/test_pcap_to_flows_parity.py`: rows written by
  `scripts/dataset/pcap_to_flows.py --schema 3.0.0` equal the live
  `extract_features(..., schema_version="3.0.0")` vector exactly.

## Dataset-adapter caveats

- **CICIDS2017** (the dataset the shipped v1 models train on): per-direction
  payload mean/std are pooled into one overall sample mean/std
  (`pirewall.ml.preprocessing.common.combine_weighted_sample_stats`). The
  published "MachineLearningCVE" release has no Source IP, Source Port,
  Destination IP or Protocol column — addresses are a documented
  placeholder, `source_port` is `None`, and `protocol` is *inferred* from
  TCP flag counts with a well-known-UDP-port fallback, so treat
  `protocol_is_*` trained from it as heuristic. IP-level `Flow` fields are
  reconstructed (payload + the CSV's L4 header-length columns + 20 bytes of
  IPv4 header per packet) only so the `Flow` is internally consistent; they
  are not features. Phase 19 uses this data only as an external test set,
  never for training.
- **UNSW-NB15**: no IP/port columns, no flag counts, per-flow means only;
  and Argus byte counts include headers with no header-length column, so
  `payload_stats` is an approximation (40 bytes of header assumed per
  packet). Treat UNSW-trained models as experimental.

# pirewall — ML Data & Artifact Audit

Status of this document: **partial.** It records what was independently
verified on 2026-08-29 by running real commands against the real artifacts
in `pirewall/ml/artifacts/`. Every number below was produced by a command
that was actually run, not recalled from a prior session's transcript.

**The dataset-derived half of the audit is BLOCKED** — see
"§B. Blocked: dataset absent". Nothing in this file depends on the dataset;
nothing that does is claimed.

Linked from `docs/ML_PIPELINE.md`.

---

## §A. Findings verified from the real artifacts

### A1. The shipped multiclass model could not run inference at all (FIXED)

`pirewall/detection/known_attack.py` decoded a multiclass booster's output
as if it were one-dimensional:

```python
class_probabilities = {index_to_label[i]: float(raw[i]) for i in range(num_class)}
```

`predict_class_probabilities` returns shape `(1, num_class)` for a
multiclass model — its own docstring says so. `raw[i]` therefore indexes
the leading *batch* axis, so `raw[0]` is the whole 15-element row and
`float()` on it raises:

```
TypeError: only 0-dimensional arrays can be converted to Python scalars
```

Reproduced directly against `lightgbm_model.txt` (v0.2.0, 15 classes)
before the fix, and confirmed resolved after. **Impact: every flow
processed by the live pipeline raised this error — the entire known-attack
evidence path was non-functional with the delivered artifact.** It was
visible in `tests/integration/test_core_daemon.py` as
`unexpected error processing flow ...` followed by a timeout.

**Why it was never caught:** the binary branch (`float(raw[0])` on shape
`(1,)`) is correct, and *every* fixture in `tests/ml/test_known_attack.py`
trained a 2-class model (`BENIGN`/`Attack`). The `num_class > 2` branch —
the one the real artifact uses — had zero test coverage.

Fixed by indexing the row first. Regression test
`test_classify_multiclass_decodes_every_class` builds a 3-class fixture and
was confirmed to fail against the old code and pass against the new.

### A2. `parse_float` does **not** reject NaN/Infinity (open)

`pirewall/ml/preprocessing/common.py:71-81` documents its contract as
preventing "one bad row silently corrupt[ing] the training set with a
NaN/garbage feature". It does not do this. Measured behaviour:

| input | result |
|---|---|
| `'NaN'` | **accepted** as `nan` |
| `'nan'` | **accepted** as `nan` |
| `'Infinity'` | **accepted** as `inf` |
| `'inf'` / `'-inf'` | **accepted** as `inf` / `-inf` |
| `'1e400'` | **accepted** as `inf` (overflow) |
| `''` / `'  '` | `ValueError` (the only rejected cases) |

Only missing/empty values are skipped-and-counted. CICFlowMeter is
specifically known to emit literal `NaN` and `Infinity` in rate-based
columns (`Flow Bytes/s`, `Flow Packets/s`) on zero-duration flows, so
these are the exact strings this dataset produces — and they flow straight
into `Flow` objects, feature extraction, and the training matrix.

This is currently **whatever happened to be there, not a deliberate
choice** — which is precisely what this audit was asked to determine. It
needs an explicit decision (reject-and-count vs. impute) once the dataset
is available to quantify how many rows are affected. **Not changed in this
pass**, because choosing between rejecting and imputing without being able
to measure the affected row count would be guessing.

### A3. Attack-class labels are corrupted by mojibake in the shipped artifact (open)

The delivered model's `class_mapping` contains:

```
'Web Attack \ufffd Brute Force'
'Web Attack \ufffd Sql Injection'
'Web Attack \ufffd XSS'
```

Root cause, reproduced exactly: CICIDS2017's Thursday web-attack labels
contain byte `0x96` — an en dash in cp1252. `cicids_adapter.py:125` opens
the CSVs with `encoding="utf-8", errors="replace"`, which turns `0x96`
into U+FFFD (`\ufffd`). Verified:

```
b'Web Attack \x96 Brute Force'.decode('utf-8', errors='replace')
    == 'Web Attack \ufffd Brute Force'   -> True  (matches the artifact exactly)
b'Web Attack \x96 Brute Force'.decode('cp1252')
    == 'Web Attack – Brute Force'        (the correct label)
```

Two consequences:

1. **This is the recurring "Windows console encoding crash" root cause.**
   U+FFFD is not encodable in cp1252, so printing these labels to a
   Windows console raises `UnicodeEncodeError`. Fixing the *read* encoding
   fixes the crash at its source; writing reports as UTF-8 only treats the
   symptom.
2. It does **not** split one class into several — the substitution is
   deterministic, so all rows of a given class still collapse to one
   consistent (if corrupted) string. Class counts are therefore unaffected.
   The damage is cosmetic-but-real: corrupted class names are baked into a
   shipped artifact and every report derived from it.

Recommended fix: read the CICIDS2017 CSVs as `cp1252` (or `latin-1`), which
is what the files actually are. **Not changed in this pass** — it changes
the class-mapping keys of any future artifact, so it belongs with the
retrain, not ahead of it.

### A4. Label-leakage check: `destination_port` does **not** dominate this model

Engelen et al. ("Troubleshooting an Intrusion Detection Dataset") document
that some raw CICIDS2017 features — destination port in particular — can
trivially predict the label because of how the dataset was generated. Real
gain-based feature importance, read from the delivered booster (1500 trees,
29 features) and mapped through the metadata's `feature_ordering`:

| rank | feature | gain % |
|---|---|---|
| 1 | `min_inter_arrival_seconds` | 23.696% |
| 2 | `std_inter_arrival_seconds` | 12.983% |
| 3 | `mean_inter_arrival_seconds` | 10.290% |
| 4 | `duration_seconds` | 7.134% |
| 5 | `packets_per_second` | 6.054% |
| 6 | `backward_byte_count` | 5.150% |
| 7 | `max_packet_size` | 5.062% |
| 8 | `forward_backward_byte_ratio` | 5.046% |
| 9 | `max_inter_arrival_seconds` | 4.533% |
| 10 | `bytes_per_second` | 3.600% |
| **11** | **`destination_port`** | **3.135%** |
| 12-29 | (remainder) | < 3.1% each |

**`destination_port` ranks 11th of 29 at 3.135% of total gain.** The top
five are all timing/rate behaviour. The likely reason pirewall is less
exposed than the papers' critique implies: its canonical schema
(`pirewall/features/schema.py`) is 29 derived flow features, not
CICFlowMeter's full ~78-column output, so most of the specifically-implicated
raw columns were never ingested.

**Honest limit on this claim:** gain-based importance is evidence, not
proof. It shows the model is not *primarily* riding on destination port; it
does not prove removing the feature would leave performance intact. The
ablation that would settle it (retrain without `destination_port`, compare
macro-F1) requires the dataset and has **not** been run.

Also visible in the same table: `protocol_is_icmp` and `protocol_is_other`
have **exactly zero** gain and zero splits — the model never uses them. Four
more (`protocol_is_tcp`, `fin_count`, `rst_count`, `protocol_is_udp`) round
to 0.000%. Worth revisiting when the schema is next versioned.

### A5. Isolation Forest per-call overhead — independent re-measurement of an already-known finding

Measured per-flow latency through the real runtime call paths
(`detection.known_attack.classify` / `detection.anomaly.detect`), 2000
flows after a 200-flow warm-up:

| path | mean | p50 | p95 | p99 |
|---|---|---|---|---|
| LightGBM (15-class) | 0.272 ms | 0.252 ms | 0.384 ms | 0.524 ms |
| Isolation Forest | 13.066 ms | 12.523 ms | 14.955 ms | 20.724 ms |
| both, per flow | 17.922 ms | 17.563 ms | 20.280 ms | 27.201 ms |

Measured on `macOS-15.7.7-x86_64` — **a dev machine, not a Pi 4.** Treat
these as a lower bound for Pi 4 performance, not a prediction of it.

Root cause of the asymmetry: sklearn's `IsolationForest.score_samples` has
a large *fixed per-call* cost that is nearly independent of batch size
(100 estimators, `max_samples_=256`):

| call shape | total | per row |
|---|---|---|
| `score_samples(X)` with 1 row | 12.536 ms | 12.536 ms |
| `score_samples(X)` with 256 rows | 13.392 ms | **0.052 ms** |

**Batching 256 flows into one call costs ~7% more wall-clock than scoring a
single flow, i.e. ~240x more throughput per flow.**

**This is not a new finding.** A prior session already measured and
documented it — `docs/PROGRESS.md` line 105 (~15.6 ms/call, ~0.088 ms/flow
at batch 200, "~178x faster — the overhead is per-call, not tree
traversal") and the open question at line 1387, which estimates 10-20
flows/s on a Pi 4 and lists remediation options. The numbers here were
measured independently this session and **reproduce that result** on
different hardware (12.5 ms vs 15.6 ms per call; 240x vs 178x gap — same
effect, machine-dependent magnitude). Recorded here as confirmation, and
because it bears directly on the architecture-choice latency budget.

Still open, still for the same reason given there: the remedy changes the
shape of `pirewall.detection.anomaly.detect` and its caller, which is
design work outside the `ml/` + `detection/` + `config/` scope of this
session.

---

## §B. Blocked: dataset absent

Every remaining item of the requested audit — exact per-class counts across
the 8 CICIDS2017 files, NaN/Infinity row counts, exact/near-duplicate flow
detection, train/test leakage from duplicates, the `destination_port`
ablation, label-string consistency across days, and the UNSW-NB15
distribution audit — requires the raw datasets. **They are not present on
this machine.** Verified:

- No `data/` or `datasets/` directory in the repo (both are gitignored).
- A full `find` over `/Users/MyLogin` returned **zero** CICIDS2017 or
  UNSW-NB15 CSVs. The only `.csv` files present are scikit-learn/numpy test
  fixtures inside `.venv`.
- `/Volumes` holds no mounted dataset media.

The prior training runs were performed on a different machine — the task
description references `D:\CodingProjects_D\pirewall`, a Windows path. This
repo is the macOS checkout at
`/Users/MyLogin/Desktop/CodingProjects/pirewall`. The model artifacts are
present here (they were copied or synced), but the data they were trained
on is not.

Consequently the prior session's headline result (**macro-F1 0.1975** and
its per-class recall table) **could not be reproduced or re-derived this
session.** Per this project's honesty rules it is recorded here as
*unverified-this-session*, carried forward from
`pirewall/ml/artifacts/lightgbm_model.txt.metadata.json` and
`docs/PROGRESS.md` rather than confirmed.

### One prior claim that *was* checkable, and is already recorded

The Isolation Forest's real detection metrics were reported as missing
("the prior session's report was LightGBM-only"). They are in fact already
present in `isolation_forest_model.joblib.metadata.json`, from a real run:

```
precision            0.5299949729095682
recall               0.45373469778117825
false_positive_rate  0.09871915576321247
false_negative_rate  0.5462653022188217
```

These are the saved v0.2.0 test-split metrics (contamination 0.10, chosen
by a validation sweep). They are read from the artifact, not recomputed —
recomputation needs the dataset.

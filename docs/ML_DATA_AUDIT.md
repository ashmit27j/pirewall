# pirewall — ML Data & Artifact Audit

Every number in this document was produced by a command that was actually
run against the real artifacts in `pirewall/ml/artifacts/` and the real
CICIDS2017 CSVs in `data/`. Nothing here is recalled from a prior
session's transcript.

Two findings in §A were **corrected** after the dataset arrived and the
claims could be tested directly rather than inferred from reading the
code — A2 (overstated) and A3 (wrong root cause). Both corrections are
written in place rather than quietly edited out, because the earlier
versions were committed and reported.

Scope: §A artifact findings, §B section-1 reproduction, §C class
distribution and the rare-class exclusion policy, §D what remains blocked.

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

### A2. `parse_float` accepts NaN/Infinity — a latent defect this dataset does not trigger

`pirewall/ml/preprocessing/common.py:71-81` documents its contract as
preventing "one bad row silently corrupt[ing] the training set with a
NaN/garbage feature". It does not do that. Measured:

| input | result |
|---|---|
| `'NaN'` / `'nan'` | **accepted** as `nan` |
| `'Infinity'` / `'inf'` / `'-inf'` | **accepted** as `inf` / `-inf` |
| `'1e400'` | **accepted** as `inf` (overflow) |
| `''` / `'  '` | `ValueError` — the only rejected cases |

CICFlowMeter does emit those literals, and this copy of CICIDS2017 contains
them: **2,867 rows across all 8 files** carry `Infinity` or `NaN`.

**But none of them reach the model.** Verified two ways:

1. Every occurrence is in CSV columns 15 and 16 — `Flow Bytes/s` and
   `Flow Packets/s`. Those two columns are **not** in the adapter's
   `_REQUIRED_COLUMNS` and are never read. pirewall derives
   `bytes_per_second` / `packets_per_second` itself from byte/packet counts
   and duration, with an explicit zero-duration guard.
2. The full 2,830,628-row feature matrix built through the real extractor
   contains **zero** non-finite values — 0 NaN, 0 +Inf, 0 -Inf, across all
   29 features. `rows_with_any_nonfinite: 0`.

So the correct characterisation is: **a real latent defect in `parse_float`
that this dataset happens not to exercise**, because the only NaN-bearing
columns are exactly the ones pirewall recomputes rather than ingests. It
would bite a future adapter or dataset that did read a rate column
directly.

**Not changed in this pass.** Tightening `parse_float` to reject
non-finite values is a one-line change, but it alters the documented
skip-and-count contract for every adapter, and with a measured zero
impact on the current training set it belongs in its own reviewed change
rather than bundled into a model-quality pass.

**Separately — 115 rows were skipped**, every one of them for
`last_seen must not precede first_seen`: CICIDS2017 contains rows with a
**negative `Flow Duration`**. All 115 were BENIGN (raw BENIGN 2,273,097 vs
2,272,982 after the adapter). The adapter rejects them correctly and counts
them, which is the intended spec §13 behaviour.

### A3. Attack-class labels carry U+FFFD — corruption is in the published dataset, not in pirewall

The delivered model's `class_mapping` contains:

```
'Web Attack \ufffd Brute Force'
'Web Attack \ufffd Sql Injection'
'Web Attack \ufffd XSS'
```

**Correction to an earlier version of this document.** It first recorded
the cause as pirewall reading a cp1252 en dash (`0x96`) as UTF-8 with
`errors="replace"` at `cicids_adapter.py:125`. That mechanism produces an
identical string, so it looked right — but it is **not** what happened
here. Checking the actual bytes of the source CSV:

```
,Web Attack \xef\xbf\xbd Brute Force
```

`EF BF BD` is the UTF-8 encoding of U+FFFD. **The replacement character is
already in the published dataset file**; `0x96` does not appear at all.
pirewall's `errors="replace"` is a no-op on these rows — it reads
faithfully what the file contains. The corruption happened upstream, when
the dataset was produced or converted.

Two consequences, both different from what the earlier version said:

1. **Re-reading as cp1252 would make it strictly worse**, decoding those
   three bytes to `ï¿½`. That earlier recommendation is withdrawn.
2. The right fix is a **label-normalisation step** mapping the corrupted
   string to a canonical name (e.g. `Web Attack - Brute Force`), not an
   encoding change.

It still does **not** split one class into several: the corrupted bytes are
identical on every row, so each class collapses to one consistent key.
Verified against real counts — exactly 3 distinct `Web Attack` strings,
1,507 / 652 / 21 rows.

It remains true that U+FFFD is unencodable in cp1252 and so raises
`UnicodeEncodeError` when printed to a Windows console. Since the source
text cannot be fixed by changing how it is read, writing reports as
explicit UTF-8 (`pirewall.ml.training.report.write_report`) is the actual
remedy, not a workaround.

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

## §B. Reproducing the delivered artifact (section 1)

The dataset was not on this machine when the audit began; it was provided
mid-session at `./data` (the 8 "MachineLearningCVE" CSVs, ~884 MB). Every
number below is computed from it.

**Load result** — via the real adapter and the canonical extractor
(`load_cicids2017` -> `Flow` -> `pirewall.features.extractor`):

| | |
|---|---|
| rows loaded | **2,830,628** |
| rows skipped | 115 |
| skip reason | **every one** `last_seen must not precede first_seen` |
| non-finite feature values | **0** (0 NaN, 0 +Inf, 0 -Inf across all 29 features) |

The 115 skips are CICIDS2017 rows with a **negative `Flow Duration`**, all
of them BENIGN (raw BENIGN 2,273,097 vs 2,272,982 after the adapter). The
adapter rejects and counts them, which is the intended §13 behaviour.

### B1. The recorded metrics reproduce exactly — once the file order is right

The prior session's `accuracy 0.8899468905663044` / `macro_f1
0.19745193396965163` did **not** reproduce on a first attempt (glob file
order gave 0.8898833005570014 / 0.1972942200360728 — off by 6.4e-5 and
1.6e-4).

The cause is that `split_train_val_test` shuffles a global index list, so
the split is a deterministic function of **the order the 8 CSVs were
concatenated**. Testing candidate orderings by permuting cached blocks:

| file order | accuracy | macro-F1 | |
|---|---|---|---|
| sorted (glob) | 0.8898833005570014 | 0.1972942200360728 | |
| chronological | 0.8900128357611371 | 0.1974704335059114 | |
| **chronological, PortScan before DDos** | **0.8899468905663044** | **0.1974519339696516** | **exact match** |
| reverse sorted | 0.8901588572639809 | 0.1978076251452134 | |
| chronological reversed | 0.8903072339523546 | 0.1976074246910626 | |

Both metrics match to full float precision on exactly one ordering:
Monday, Tuesday, Wednesday, Thursday-WebAttacks,
Thursday-Infilteration, Friday-Morning, **Friday-PortScan,
Friday-DDos**. Section 1 is therefore reproduced, and every evaluation in
this session uses that ordering (`canonical_order.py`).

**Process gap worth fixing:** nothing in the repo recorded which order was
used, so this took a five-way search to recover. `ModelMetadata` should
carry a dataset fingerprint — row count plus an ordered list of source
files, or a hash of the label sequence — so a future session can confirm
it is on the same split instead of inferring it.

### B2. The real per-class table for the delivered artifact

Reproduced on the verified split. **This supersedes the per-class figures
quoted in the task prompt**, which do not match: the prompt cites DDoS
81.34% and "three classes at 0%", against a measured DDoS 43.05% and
**nine** classes at 0.00%. Since accuracy and macro-F1 both match to 16
significant digits, the table below is the artifact's ground truth. (The
prompt's DoS Hulk 86.34% / PortScan 74.31% / SSH-Patator 0.11% are close
to but not equal to the measured 85.51% / 73.95% / 0.00%, so those figures
appear to come from a different run.) `PROGRESS.md`'s own limitations list
— which names eight classes with "zero or near-zero correct predictions" —
agrees with the measurement, not with the prompt.

| class | test n | caught | recall | precision | F1 |
|---|---:|---:|---:|---:|---:|
| BENIGN | 340,947 | 322,329 | 94.54% | 94.41% | 0.9447 |
| DoS Hulk | 34,661 | 29,638 | 85.51% | 67.12% | 0.7520 |
| PortScan | 23,840 | 17,629 | 73.95% | 73.57% | 0.7376 |
| DDoS | 19,204 | 8,267 | 43.05% | 66.62% | 0.5230 |
| FTP-Patator | 1,191 | 4 | 0.34% | 0.63% | 0.0044 |
| Bot | 295 | 0 | 0.00% | 0.00% | 0.0000 |
| DoS GoldenEye | 1,544 | 0 | 0.00% | 0.00% | 0.0000 |
| DoS Slowhttptest | 825 | 0 | 0.00% | 0.00% | 0.0000 |
| DoS slowloris | 869 | 0 | 0.00% | 0.00% | 0.0000 |
| SSH-Patator | 885 | 0 | 0.00% | 0.00% | 0.0000 |
| Web Attack – Brute Force | 226 | 0 | 0.00% | 0.00% | 0.0000 |
| Web Attack – XSS | 98 | 0 | 0.00% | 0.00% | 0.0000 |
| Web Attack – Sql Injection | 3 | 0 | 0.00% | 0.00% | 0.0000 |
| Infiltration | 5 | 0 | 0.00% | 0.00% | 0.0000 |
| Heartbleed | 2 | 0 | 0.00% | 0.00% | 0.0000 |

Binary (any-attack vs BENIGN): precision 0.776178, recall 0.771853,
F1 0.774009, FPR 0.054607, FNR 0.228147 (tp 64,564 / fp 18,618 /
fn 19,084 / tn 322,329).

### B3. Isolation Forest — metrics already existed

The task recorded these as missing ("the prior session's report was
LightGBM-only"). They are in fact already in
`isolation_forest_model.joblib.metadata.json` from a real run:
precision 0.529995, recall 0.453735, FPR 0.098719, FNR 0.546265
(contamination 0.10, chosen by a validation sweep).

---

## §C. Class distribution and the rare-class exclusion policy (sections 2-3)

Real totals, train+val+test combined, all 8 files, 2,830,628 rows:

| class | count | share |
|---|---:|---:|
| BENIGN | 2,272,982 | 80.2996% |
| DoS Hulk | 231,073 | 8.1633% |
| PortScan | 158,930 | 5.6147% |
| DDoS | 128,027 | 4.5229% |
| DoS GoldenEye | 10,293 | 0.3636% |
| FTP-Patator | 7,938 | 0.2804% |
| SSH-Patator | 5,897 | 0.2083% |
| DoS slowloris | 5,796 | 0.2048% |
| DoS Slowhttptest | 5,499 | 0.1943% |
| Bot | 1,966 | 0.0695% |
| Web Attack – Brute Force | 1,507 | 0.0532% |
| Web Attack – XSS | 652 | 0.0230% |
| **Infiltration** | **36** | 0.0013% |
| **Web Attack – Sql Injection** | **21** | 0.0007% |
| **Heartbleed** | **11** | 0.0004% |

Imbalance ratio BENIGN:Heartbleed is **206,635 : 1**.

**Threshold: `MIN_SUPERVISED_TRAINING_EXAMPLES = 100`**, in
`pirewall.ml.labels`. It is read off the distribution, not assumed: the
counts jump from 36 to 652, an **18x gap**, and any cutoff inside that gap
selects exactly the same three classes — so the choice is robust rather
than knife-edge. 100 is also where the 70/15/15 split stops resolving:
below it a class lands single-digit rows in test (Heartbleed gets 2,
Web Attack – Sql Injection 3, Infiltration 5), and a recall figure over 2
rows carries no information.

**Excluded (3):** Heartbleed (11), Web Attack – Sql Injection (21),
Infiltration (36).

**Deliberately kept (per the task's expectation, and the counts agree):**
Bot (1,966), Web Attack – Brute Force (1,507), Web Attack – XSS (652).
These are two to three orders of magnitude above the excluded three; their
0.00% recall in the delivered artifact is an imbalance-handling failure,
not data scarcity, which is what section 4 tests.

Enforced by `is_excluded_from_supervised_training` — the single shared
function both training and evaluation call. `normalize_label` collapses
punctuation and case so an encoding difference (U+FFFD vs hyphen vs en
dash) cannot silently re-admit an excluded class.

## §D. Still blocked

**UNSW-NB15 is not present** — `data/` holds only the 8 CICIDS2017 files,
and a full filesystem search found no `UNSW_NB15_*.csv`. Its class
distribution could not be audited. UNSW-NB15 is documented as having a far
milder imbalance than CICIDS2017 (its published train/test partitions are
deliberately rebalanced), but that is a literature claim, not a
measurement from this machine, and is recorded here as such.

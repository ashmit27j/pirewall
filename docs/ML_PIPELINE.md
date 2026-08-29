# pirewall — ML Pipeline (spec §12-16, Phase 4/5)

Covers: dataset adapters, preprocessing, training, model artifacts, and
runtime inference's schema-compatibility gate. See `docs/FEATURE_SCHEMA.md`
for the canonical feature list both training and inference share.

**See also `docs/ML_DATA_AUDIT.md`** — verified findings about the delivered
artifacts, including a fixed bug that made multiclass inference fail
outright, two open data-hygiene issues (NaN/Infinity acceptance, label
mojibake), a label-leakage check on `destination_port`, and measured
per-flow inference latency for both models.

## Pipeline overview

```text
Raw dataset (CICIDS2017 / UNSW-NB15 CSV)
        |
        v
Dataset adapter (pirewall.ml.preprocessing.{cicids,unsw}_adapter)
        |  maps raw columns -> canonical Flow objects, skips/counts
        |  invalid rows, fails fast on a missing required column
        v
LabeledFlow (Flow + label string)
        |
        v
pirewall.features.extractor.extract_features   <-- the ONE canonical extractor,
        |                                          also used at runtime (Phase 5)
        v
FeatureVector
        |
        v
pirewall.ml.training.{lightgbm,isolation_forest}_trainer
        |
        v
Trained model + pirewall.core.models.ModelMetadata
        |
        v
pirewall.ml.artifacts.metadata.save_metadata   <-- JSON sidecar next to the model file
```

## Dataset adapters (spec §12)

- `pirewall.ml.preprocessing.cicids_adapter.load_cicids2017` — targets the
  specific "MachineLearningCVE" CICFlowMeter CSV column layout (real
  Source/Destination IP and port columns present). A stripped-down mirror
  without those columns fails with a clear missing-column error rather than
  silently degrading.
- `pirewall.ml.preprocessing.unsw_adapter.load_unsw_nb15` — targets
  `UNSW_NB15_training-set.csv`/`testing-set.csv`. See
  `docs/FEATURE_SCHEMA.md`'s "Dataset-adapter caveats" for what's
  placeholder-derived in this variant.
- Both raise `pirewall.core.exceptions.DatasetError` for a missing file or a
  missing *required* column (structural failure — abort the whole load). A
  single row with an unparseable value is different: counted in
  `DatasetLoadResult.skipped_rows`, not aborted (spec §13 "handle missing/
  invalid values explicitly").

**Getting real datasets** (not included in this repo — spec §35 "never
commit raw dataset files"):

- CICIDS2017 ("MachineLearningCVE" CSVs): https://www.unb.ca/cic/datasets/ids-2017.html
- UNSW-NB15 (`UNSW_NB15_training-set.csv`/`testing-set.csv`): https://research.unsw.edu.au/projects/unsw-nb15-dataset

## Training (spec §14)

Two independent models, both consuming the same canonical `FeatureVector`s:

- **LightGBM** — supervised known-attack classifier (binary or multi-class,
  depending on how many distinct labels the dataset carries).
  `pirewall.ml.training.lightgbm_trainer.train_lightgbm`.
- **Isolation Forest** — unsupervised anomaly detector, fit **only on
  normal/benign-labeled rows** of the training split (`is_attack_label`
  filters `x_train` before `.fit()` — the model never receives an attack
  label as a supervised target, but dataset labels do select which rows
  count as the normal baseline). Evaluation still runs over the full
  held-out split (normal + attack). `pirewall.ml.training.isolation_forest_trainer.train_isolation_forest`.

Run via the CLIs in `scripts/train/` (development machine only, spec §4 —
never train on the Pi):

```sh
uv run python -m scripts.train.train_lightgbm \
    --dataset cicids --dataset-path /path/to/cicids2017.csv \
    --model-version 1.0.0 --output-dir pirewall/ml/artifacts

uv run python -m scripts.train.train_isolation_forest \
    --dataset cicids --dataset-path /path/to/cicids2017.csv \
    --model-version 1.0.0 --output-dir pirewall/ml/artifacts
```

Pass `--placeholder --notes "..."` when training on anything other than a
real, complete dataset (CLAUDE.md labeling honesty) — this sets
`ModelMetadata.is_placeholder = true` so nothing downstream can mistake the
resulting metrics for real detection performance. **Never hand-edit a
metadata JSON file** — it must always be the direct output of a real
training run.

## Model artifacts and metadata (spec §15)

Every trained model ships with a JSON metadata sidecar
(`<model-file>.metadata.json`, `pirewall.ml.artifacts.metadata.save_metadata`/
`load_metadata`) carrying, at minimum: `model_version`,
`feature_schema_version`, `feature_ordering` (the exact `FEATURE_NAMES`
tuple used at training time), `is_placeholder`, `notes`, and evaluation
metrics. Model files themselves (`.txt`/`.joblib`) and their metadata
sidecars are gitignored — never committed (spec §12/§35).

## Runtime schema-compatibility gate (spec §15)

`pirewall.ml.inference.loader.load_lightgbm_model`/`load_isolation_forest_model`
are the **only** place a model file is read from disk at runtime, and both
refuse to return a usable model if:

1. `metadata.feature_schema_version != pirewall.features.schema.SCHEMA_VERSION`, or
2. `metadata.feature_ordering != pirewall.features.schema.FEATURE_NAMES`

— raising `pirewall.core.exceptions.ModelInferenceError` in either case.
This is deliberate defense against "the schema changed since this model was
trained" silently producing garbage predictions: a mismatch fails loudly at
load time (startup, spec §42), not silently at inference time on live
traffic. `pirewall.ml.inference.common.validate_feature_vector` performs
the equivalent per-call check on every `FeatureVector` passed to inference,
for the same reason.

## Runtime inference (spec §14, Phase 5)

```text
FeatureVector
     |
     +---> pirewall.detection.known_attack.classify   -> KnownEvidence
     |        (wraps pirewall.ml.inference.lightgbm_predictor)
     |
     +---> pirewall.detection.anomaly.detect           -> AnomalyEvidence
              (wraps pirewall.ml.inference.isolation_forest_predictor)
```

Both wrapper modules' only output is an evidence object — CLAUDE.md "ML
produces evidence, never commands": neither this layer nor anything it
calls may construct a firewall rule, call the firewall backend, or run a
shell command. Evidence flows onward into `pirewall.engine.threat.assess_threat`
(see `docs/FIREWALL.md` for what happens after that).

## Retraining procedure

1. On a development machine (spec §4), obtain a real, current dataset.
2. Run both training CLIs above **without** `--placeholder`, with a new
   `--model-version` (semantic version bump).
3. Inspect the printed metrics (accuracy/macro-F1 for LightGBM; the
   Isolation Forest trainer's own reported metrics) — do not deploy a model
   whose metrics look implausible without investigating why.
4. Copy the new model files + `.metadata.json` sidecars to
   `pirewall/ml/artifacts/` on the target Pi (see `docs/DEPLOYMENT.md` §9
   "secure update procedure").
5. Restart `pirewall-core`. The schema-compatibility gate above will refuse
   to start serving inference from a bad artifact rather than silently
   degrading — check logs/`SecurityEvent`s (`MODEL_ERROR`) if it does.

## Testing

- **Tested**: both dataset adapters (valid-row mapping, skip-and-count,
  missing-column/file failures), both trainers + `ModelMetadata` round-trip,
  both training CLIs, schema-mismatch refusal (load-time and per-call), and
  successful inference — all against small synthetic fixture data
  (`tests/ml/`).
- **Environment-dependent**: real detection accuracy against *live* attack
  traffic on the Pi still needs the spec §34 attack-lab exercise. Held-out
  accuracy on the real CICIDS2017 dataset is no longer environment-dependent
  — see "Current real-data results" below.

## Current real-data results (CICIDS2017, model version 0.4.0)

**Shipped.** `pirewall/ml/artifacts/lightgbm_model.txt` is model version
**0.4.0** (4,039,527 bytes, 2026-08-30 02:28:07, `is_placeholder: false`),
produced by `scripts/train/train_lightgbm.py` over all 8
"MachineLearningCVE" CSVs (2,830,628 flows; 115 rows skipped for negative
`Flow Duration`). Split train 1,981,390 / val 424,585 / test 424,595.
**12 trained classes** — the rare-class exclusion policy is applied.

| metric | v0.2.0 | v0.3.0 | **v0.4.0** |
|---|---:|---:|---:|
| accuracy | 0.889947 | 0.997056 | **0.997146** |
| macro-F1 | 0.197452 (15 cls) | 0.872411 (15 cls) | **0.854589 (12 cls)** |
| binary precision | 0.7762 | 0.992687 | **0.993021** |
| binary recall | 0.7719 | 0.993186 | **0.993329** |
| binary FPR | 0.0546 | 0.001795 | **0.001713** |

**Reading the macro-F1 change honestly.** 0.8546 (12 classes) versus
0.8724 (15) is *not* a like-for-like drop. Recomputing v0.3.0 over the same
12 classes gives **0.857181**, so applying the exclusion policy costs
**-0.002592** — noise. v0.3.0's higher headline came from three classes
with 2, 5 and 3 test rows scoring F1 1.0, 1.0 and 0.8: the 15-class average
was flattering itself. Binary precision and false-positive rate both
*improved*.

### Full per-class table (v0.4.0, held-out test split)

| class | test n | caught | recall | precision | F1 |
|---|---:|---:|---:|---:|---:|
| BENIGN | 340,947 | 340,363 | 99.83% | 99.84% | 0.9983 |
| DDoS | 19,204 | 19,191 | 99.93% | 99.98% | 0.9996 |
| PortScan | 23,840 | 23,837 | 99.99% | 99.32% | 0.9966 |
| DoS Hulk | 34,661 | 34,456 | 99.41% | 99.18% | 0.9929 |
| DoS slowloris | 869 | 863 | 99.31% | 99.88% | 0.9960 |
| FTP-Patator | 1,191 | 1,189 | 99.83% | 100.00% | 0.9992 |
| DoS Slowhttptest | 825 | 821 | 99.52% | 98.44% | 0.9898 |
| SSH-Patator | 885 | 875 | 98.87% | 98.20% | 0.9854 |
| DoS GoldenEye | 1,544 | 1,529 | 99.03% | 96.04% | 0.9751 |
| **Bot** | 295 | 134 | **45.42%** | 90.54% | 0.6050 |
| **Web Attack - Brute Force** | 226 | 114 | **50.44%** | 60.32% | 0.5494 |
| **Web Attack - XSS** | 98 | 11 | **11.22%** | 33.33% | 0.1679 |

Excluded from supervised training (still in the test split, reported for
transparency, **not** in macro-F1):

| class | total examples | test n | caught | recall |
|---|---:|---:|---:|---:|
| Infiltration | 36 | 5 | 0 | 0.00% |
| Web Attack - Sql Injection | 21 | 3 | 0 | 0.00% |
| Heartbleed | 11 | 2 | 0 | 0.00% |

### Rare-class exclusion policy — settled

**Threshold: `MIN_SUPERVISED_TRAINING_EXAMPLES = 100`**
(`pirewall.ml.labels`). Read off the real distribution: counts run
Heartbleed 11, Web Attack - Sql Injection 21, Infiltration 36, then Web
Attack - XSS **652** — an 18x gap. Any cutoff in (36, 652] selects the same
three classes, so the number is not knife-edge; 100 also sits where the
70/15/15 split stops resolving (below it a class lands <=5 test rows).

**First enforced in v0.4.0.** v0.3.0 and every earlier artifact were
trained *with* those rows — 7 Heartbleed, 15 SQL Injection, 26
Infiltration, 48 in total — because the policy function existed and was
unit-tested but had no production caller. The v0.4.0 training split is
1,981,390 rows against v0.3.0's 1,981,438: exactly those 48 removed.
`tests/ml/test_exclusion_is_wired.py` is an integration guard that fails if
the filter ever regresses to defined-but-never-called.

Detection of those three classes now rests entirely on the Isolation Forest
and `pirewall.detection.behavior`, as intended.

### Architecture decision — flat multiclass, on evidence

Full-scale five-way ablation, one fixed split, 1,981,438 training rows:

| configuration | classes | macro-F1 | leak-free macro-F1 |
|---|---:|---:|---:|
| flat multiclass, no exclusion | 15 | 0.8724 | 0.8855 |
| **flat multiclass + exclusion (shipped)** | 12 | **0.8546** | **0.8542** |
| flat multiclass + under/oversampling | 12 | 0.8291 | 0.8310 |
| two-stage (binary gate -> attack-type) | 12 | 0.8217 | 0.8173 |
| flat multiclass + balanced class weighting | 12 | 0.8075 | 0.8150 |

The two-stage architecture **was** built and evaluated at full scale, not
skipped: a binary gate reaching **99.69%** accuracy, then an attack-type
classifier trained on 390,302 attack-only rows over 11 classes, composed on
stage 1's *real* predictions rather than oracle labels. The like-for-like
comparison is both 12-class rows: **flat 0.8546 vs two-stage 0.8217**. Flat
wins by 0.033 while needing one artifact, one inference call and no
composed failure mode. Every imbalance intervention also *costs* macro-F1
once the divergence bug is fixed.

**Runtime**: adopting v0.4.0 required no code change — the
schema-compatibility gate accepts it, `pirewall.detection.known_attack`
classifies against it unmodified, the three excluded classes are absent
from the predictable output set, and per-flow latency is 0.239 ms mean /
0.326 ms p95.

### Train/test leakage — audited, and it does NOT inflate the results

**Method.** "Duplicate" here means **bit-identical across all 29 canonical
features** — `np.unique` over a structured byte view, exact float64
equality, no rounding or normalisation. Near-duplicates are therefore
**not** detected, so every figure below is a lower bound.

**Taxonomy** (2,830,628 rows, 2,402,181 unique vectors, 428,447 duplicate
rows = 15.14%):

| | count |
|---|---:|
| distinct vectors appearing more than once | 123,458 |
| ...spanning **both** train and test — real leakage | **41,959** (34%) |
| ...never spanning train+test — over-representation only | 81,499 (66%) |

Per test row (424,595 total):

| | rows | share |
|---|---:|---:|
| exact twin in the v0.4.0 training split — **real leakage** | 75,079 | **17.68%** |
| duplicated but no train twin — over-representation only | 7,616 | 1.79% |
| wholly unique in the corpus | 341,900 | 80.52% |

So the leakage is real: about a third of duplicate groups straddle the
split, and 17.68% of test rows have a training twin. The split is
per-row, and CICIDS2017 genuinely contains identical flows.

**But it is not inflating the metrics.** Re-evaluating the *shipped
v0.4.0 artifact* — no retraining — against only the 349,516 test rows with
no training twin:

| metric | full test | leakage-free | delta |
|---|---:|---:|---:|
| accuracy | 0.997146 | **0.998137** | +0.00099 |
| macro-F1 (12 classes) | 0.854589 | **0.854239** | **-0.00035** |
| binary precision | 0.993021 | **0.996234** | +0.0032 |
| binary recall | 0.993329 | **0.994116** | +0.0008 |
| binary FPR | 0.001713 | **0.000789** | better |

macro-F1 moves by 0.00035. Accuracy, precision and false-positive rate all
*improve* on the clean subset.

**The two most-duplicated classes specifically**, since they are also two of
the best-scoring:

| class | leak% of its test rows | full-test recall | leakage-free recall (n) |
|---|---:|---:|---:|
| PortScan | 55.12% | 99.99% | **99.97%** (10,699) |
| SSH-Patator | 45.76% | 98.87% | **99.58%** (480) |

PortScan holds at 99.97% on rows with no training twin; SSH-Patator scores
*higher* on its clean subset. Their performance is genuine generalisation,
not memorisation — which is mechanically unsurprising: a port-scan probe is
a near-degenerate flow (a couple of packets, fixed size, no payload), so
identical feature vectors recur naturally rather than indicating a copied
record.

**Conclusion: v0.4.0's reported numbers stand.** No version bump; the
leakage-free column is recorded alongside them (`reports/v040_leakfree.txt`)
rather than replacing them. **Recommended for future retrains**: use a
group-aware split keyed on the feature-vector hash so duplicate groups land
wholly in one split. That is a correctness improvement for the methodology,
not a correction to these numbers.

### Detection coverage for the excluded classes — one real gap

The exclusion policy is justified by "Isolation Forest and behaviour
analysis catch these instead". That was an assumption. Measured, running the
shipped Isolation Forest (v0.2.0) over every real flow of each class:

| class | flows | flagged anomalous | verdict |
|---|---:|---:|---|
| BENIGN (false-positive baseline) | 2,272,982 | **9.93%** | the bar to beat |
| All attacks (baseline) | 557,646 | 45.35% | |
| **Heartbleed** | 11 | **100.00%** | strongly covered |
| **Infiltration** | 36 | **86.11%** | strongly covered |
| **Web Attack - Sql Injection** | 21 | **0.00%** | **no coverage at all** |

Heartbleed and Infiltration are caught far above both baselines, so for
those two the safety story is substantiated with numbers rather than
assumed.

**Web Attack - Sql Injection has no detection coverage anywhere in the
pipeline.** Not from LightGBM (excluded from training by policy, 0% by
construction), and not from the Isolation Forest, which flags **0 of 21** —
below even the 9.93% benign false-positive rate.

**Behaviour analysis does not close this gap either.** All eight
deterministic signals are volume, rate or diversity measures over a source
IP's history: `REPEATED_CONNECTIONS` (>=20 to one destination),
`HIGH_FREQUENCY` (>=2/s), `BURST` (>=10 in 5s), `PERSISTENCE`,
`DESTINATION_DIVERSITY` (>=15 destinations), `SCANNING` (>=10 ports),
`REPEATED_FAILURES` (>=10 unanswered), `TEMPORAL_PATTERN`. CICIDS2017's SQL
injection is 21 protocol-valid HTTP requests to a single web server on a
single port that receive real responses: it hits one destination (so not
`DESTINATION_DIVERSITY`), one port (not `SCANNING`), and completes its TCP
handshakes (not `REPEATED_FAILURES`). `PERSISTENCE` or
`REPEATED_CONNECTIONS` might fire incidentally, but they would fire
identically for a user making twenty requests to one site — nothing here is
specific to SQL injection.

**This is a genuine, currently-undetected coverage gap, recorded rather
than solved.** Closing it needs payload/L7 inspection, which the
flow-level feature schema deliberately does not do. It is *not* an argument
against the exclusion policy: with 21 total examples the supervised
classifier could not learn it reliably either, and v0.3.0 — which did train
on its 15 rows — caught 2 of 3 test rows on a sample far too small to mean
anything.

### The three weak classes — assessment and recommendation

**Bot 45.42%, Web Attack - Brute Force 50.44%, Web Attack - XSS 11.22%.**
These have 1,966 / 1,507 / 652 real examples, so this is not the
data-scarcity problem the excluded classes have.

Where their test flows actually go:

| class | -> BENIGN | -> correct | -> other web attack |
|---|---:|---:|---:|
| Web Attack - XSS | **50.0%** | 11.2% | 36.7% (Brute Force) |
| Bot | **54.6%** | 45.4% | - |
| Web Attack - Brute Force | **44.2%** | 50.4% | 5.3% (XSS) |

**The dominant error is being missed as BENIGN, not confused between attack
types.** That is a detection failure, not a labelling one.

**The obvious lever exists and was measured.** Balanced class weighting
(already implemented, `--class-weighting`) moves recall substantially on
exactly these classes — but at a precision cost that makes it unusable as
the primary classifier:

| class | plain: recall / precision / F1 | weighted: recall / precision / F1 |
|---|---|---|
| Bot | 45.42% / 90.54% / 0.6050 | **98.31%** / **20.47%** / 0.3388 |
| WA - Brute Force | 50.44% / 60.32% / 0.5494 | 63.27% / 23.10% / 0.3385 |
| WA - XSS | 11.22% / 33.33% / 0.1679 | 54.08% / 9.27% / 0.1582 |

Bot recall more than doubles, but 4 in 5 "Bot" alerts become wrong. F1
falls for all three.

**Recommendation: treat this as close to the ceiling for this feature
schema, and do not spend another session on it.** The 29 canonical features
are flow-level only — packet counts, byte counts, timing, TCP flags, port.
They contain **no payload or HTTP semantics whatsoever**, and XSS versus
Brute Force differ almost entirely in payload: same tool, same target, same
port, similar flow shape. The 36.7% XSS->Brute Force confusion is the
expected consequence. Options, none cheap: add payload/L7 features (a
schema change and a scope change, since the design is deliberately
flow-level), or expose the recall/precision trade per-deployment via the
existing `--class-weighting` flag for operators who would rather alert
loudly in SHADOW mode. Neither is worth doing speculatively.

### Retraining used to be memory-bound — fixed by streaming

The full-corpus retrain previously drove **4.2 GB of swap** on an 8 GB
machine and could not finish. An earlier version of this section blamed
`build_feature_matrix`'s `list[list[float]]`, estimating 5-8 GB. **That
attribution was wrong.** Measured per row on the real corpus (2,830,628
rows):

| representation | bytes/row | full corpus |
|---|---:|---:|
| **`LabeledFlow` objects (Pydantic)** | **3,857** | **10.17 GB** |
| `list[list[float]]` | 764 | 2.01 GB |
| `float64` numpy array | 232 | 0.61 GB |
| peak, flows and lists both live | | **12.18 GB** |

The list-of-lists was only 2.01 GB; the Pydantic `Flow` objects are 5x
larger. A numpy-only rewrite would have saved 1.4 GB of 12.18 and crashed
again.

**Fixed by streaming** (`iter_cicids2017` ->
`build_feature_matrix_streaming` -> `train_lightgbm_from_arrays`), so no
flow list is ever materialised. Measured after: **peak RSS 1.23 GB, 237 s**
for the full corpus. The training CLI uses this path; `train_lightgbm` and
`load_cicids2017` keep their old signatures for existing callers and tests.

**The entire difference is one parameter.** v0.2.0 was trained without
`lambda_l2`; under the multiclass softmax the hessian `p*(1-p)` vanishes as
the model gains confidence, and with LightGBM's default `lambda_l2 = 0.0`
leaf values grow unbounded, so boosting *diverged*. Macro-F1 fell from
0.8053 at round 10 to 0.2519 at round 100, and max |raw score| reached
6.4e6. This was **not** an imbalance problem and **not** a data limit —
`docs/ML_DATA_AUDIT.md` §F has the mechanism, the measured before/after,
and the three hypotheses that were wrong.

**Architecture** — chosen by a full-scale five-way ablation on one fixed
split, not assumed:

| configuration | macro-F1 | leak-free macro-F1 |
|---|---:|---:|
| **flat multiclass, plain (kept)** | **0.8724** | **0.8855** |
| flat multiclass + rare-class exclusion | 0.8546 | 0.8542 |
| flat multiclass + under/oversampling | 0.8291 | 0.8310 |
| two-stage (binary gate -> attack-type) | 0.8217 | 0.8173 |
| flat multiclass + balanced class weighting | 0.8075 | 0.8150 |

Every imbalance intervention *costs* macro-F1 once the divergence is fixed.
The two-stage gate is near-perfect on its own (99.69% accuracy) and still
loses end-to-end, so the extra artifact, the extra inference call and the
composed failure mode buy nothing — architecture A stays.

**Known remaining weaknesses — stated plainly:**

- **Web Attack – XSS 15.31% recall** (98 test rows), **Bot 44.75%** (295),
  **Web Attack – Brute Force 51.33%** (226). These are the genuinely weak
  classes now, and no technique tried here fixed them.
- **Heartbleed, Infiltration and Web Attack – Sql Injection are caught
  (2/2, 5/5, 2/3) but on 2-5 test rows each.** Do not read those as
  reliable detection; they have 11, 36 and 21 total examples.
- **17.71% of test rows are exact duplicates of a training row**
  (`docs/ML_DATA_AUDIT.md` §D), so absolute figures carry some
  memorisation. The leak-free column above excludes them. PortScan (55.6%
  leaked) and SSH-Patator (49.7%) are the most affected; DDoS (0.01%) and
  Bot (2.03%) are essentially clean.
- **Trained and evaluated on one 2017 dataset.** Nothing here measures
  performance on this project's actual traffic.

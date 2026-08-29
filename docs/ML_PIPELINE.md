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

## Current real-data results (CICIDS2017, model version 0.3.0)

**Shipped.** `pirewall/ml/artifacts/lightgbm_model.txt` is model version
**0.3.0**, `is_placeholder: false`, produced by
`scripts/train/train_lightgbm.py` on all 8 "MachineLearningCVE" CSVs
(2,830,628 flows; 115 rows skipped for negative `Flow Duration`).
Split 1,981,438 / 424,595 / 424,595; metrics from the untouched test split.

| metric | v0.2.0 | **v0.3.0** |
|---|---:|---:|
| accuracy | 0.8899468905663044 | **0.9970560180878248** |
| multiclass macro-F1 (15 classes) | 0.1974519339696516 | **0.8724113675173262** |
| binary precision | 0.7762 | **0.9927** |
| binary recall | 0.7719 | **0.9932** |
| binary false-positive rate | 0.0546 | **0.0018** |

Per-class recall, v0.2.0 -> v0.3.0 (test n / caught):

| class | test n | v0.2.0 | **v0.3.0** |
|---|---:|---:|---:|
| BENIGN | 340,947 | 94.54% | **99.82%** |
| DoS Hulk | 34,661 | 85.51% | **99.36%** |
| PortScan | 23,840 | 73.95% | **99.97%** |
| DDoS | 19,204 | 43.05% | **99.93%** |
| DoS GoldenEye | 1,544 | 0.00% | **99.03%** |
| FTP-Patator | 1,191 | 0.34% | **99.92%** |
| SSH-Patator | 885 | 0.00% | **98.76%** |
| DoS slowloris | 869 | 0.00% | **99.19%** |
| DoS Slowhttptest | 825 | 0.00% | **99.39%** |
| Bot | 295 | 0.00% | **44.75%** |
| Web Attack - Brute Force | 226 | 0.00% | **51.33%** |
| Web Attack - XSS | 98 | 0.00% | **15.31%** |
| Infiltration | 5 | 0.00% | 100.00% (5/5) |
| Web Attack - Sql Injection | 3 | 0.00% | 66.67% (2/3) |
| Heartbleed | 2 | 0.00% | 100.00% (2/2) |

**The entire difference is one parameter.** v0.2.0 trained without
`lambda_l2`; under the multiclass softmax the hessian `p*(1-p)` vanishes as
the model gains confidence, and with LightGBM's default `lambda_l2 = 0.0`
leaf values grow unbounded, so boosting *diverged* — macro-F1 fell from
0.8053 at round 10 to 0.2519 at round 100, with max |raw score| reaching
6.4e6. This was **not** an imbalance problem and **not** a data limit;
`docs/ML_DATA_AUDIT.md` §F has the mechanism and the wrong hypotheses.

**Architecture** — chosen by a full-scale five-way ablation on one fixed
split, not assumed:

| configuration | macro-F1 | leak-free macro-F1 |
|---|---:|---:|
| **flat multiclass, plain (shipped)** | **0.8724** | **0.8855** |
| flat multiclass + rare-class exclusion | 0.8546 | 0.8542 |
| flat multiclass + under/oversampling | 0.8291 | 0.8310 |
| two-stage (binary gate -> attack-type) | 0.8217 | 0.8173 |
| flat multiclass + balanced class weighting | 0.8075 | 0.8150 |

Every imbalance intervention *costs* macro-F1 once the divergence is fixed.
The two-stage gate is near-perfect alone (99.69% accuracy) and still loses
end-to-end, so the second artifact and second inference call buy nothing.

**Runtime**: no code change was needed to adopt v0.3.0 — the
schema-compatibility gate accepts it, `pirewall.detection.known_attack`
classifies against it unmodified, and measured per-flow latency *improved*
to 0.181 ms mean / 0.242 ms p95 (from 0.272 ms), because L2 yields
shallower trees.

**Known remaining weaknesses — stated plainly:**

- **Web Attack - XSS 15.31%** (98 test rows), **Bot 44.75%** (295),
  **Web Attack - Brute Force 51.33%** (226) are still weak. No technique
  tried here fixed them; XSS is mostly confused with Brute Force and BENIGN.
- **Heartbleed, Infiltration and Web Attack - Sql Injection are caught, but
  on 2, 5 and 3 test rows.** Do not read those as reliable detection; they
  have 11, 36 and 21 total examples.
- **17.71% of test rows are exact duplicates of a training row**
  (`docs/ML_DATA_AUDIT.md` §D), so absolute figures carry some
  memorisation. PortScan (55.6% leaked) and SSH-Patator (49.7%) are worst
  affected; DDoS (0.01%) and Bot (2.03%) are essentially clean.
- **One 2017 dataset.** Nothing here measures performance on real traffic.

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

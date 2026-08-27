# pirewall — ML Pipeline (spec §12-16, Phase 4/5)

Covers: dataset adapters, preprocessing, training, model artifacts, and
runtime inference's schema-compatibility gate. See `docs/FEATURE_SCHEMA.md`
for the canonical feature list both training and inference share.

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
- **Isolation Forest** — unsupervised anomaly detector, trained only on
  (implicitly or explicitly) normal traffic. `pirewall.ml.training.isolation_forest_trainer.train_isolation_forest`.

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
- **Environment-dependent**: real detection *accuracy* against real attacks
  needs the spec §34 attack-lab exercise against a model trained on a real,
  complete dataset — not this repository's synthetic-fixture placeholders.
  See `docs/PROGRESS.md` Phase 4 for exactly what a human needs to do to
  get real numbers.

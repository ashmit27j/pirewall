# Phase 4 — Dataset adapters, preprocessing & ML training (dev-machine side)

Read `CLAUDE.md` and `docs/MASTER_SPEC.md` sections 12, 13, 14, 15, 16 before
starting. Confirm Phase 3 is marked complete in `docs/PROGRESS.md`.

## Important context

This phase's training scripts run on a **development machine**, not the Pi
(spec §4). You will need real CICIDS2017 and UNSW-NB15 dataset files, which
are **not** committed to the repo (spec §12) and are not provided by this
prompt. If the files aren't present under the path configured for them,
**fail clearly and tell the user what to download and where to put it** —
do not fabricate results, do not silently skip training, do not generate
fake metrics to make the phase look complete.

## Goal

Get from raw CICIDS2017/UNSW-NB15 CSVs to trained, versioned LightGBM and
Isolation Forest artifacts with honest evaluation metrics — using the exact
same feature schema and extractor built in Phase 3, not a reimplementation.

## Deliverables

1. **`pirewall/ml/preprocessing/cicids_adapter.py`** and **`unsw_adapter.py`**
   — each: load the source dataset, validate its schema, normalize column
   names, map dataset-specific fields to Phase 3's canonical feature schema,
   derive any features the schema needs that aren't directly present, handle
   missing/invalid values explicitly (documented strategy, not silent
   drops), validate the final schema, and fail loudly with a clear message
   (not a silent skip) if a required canonical feature cannot be produced
   (spec §13). Dataset-specific column names/quirks stay inside these
   adapters — nothing downstream should know which dataset it came from.

2. **`pirewall/ml/training/`** — training scripts (invoked via
   `scripts/train/`) for:
   - LightGBM known-attack classifier: outputs predicted class, class
     probabilities, and is versioned.
   - Isolation Forest anomaly detector: versioned.
   Both must consume features produced through Phase 3's canonical extractor
   applied to the adapters' canonical dataset output — no separate feature
   math.

3. **`pirewall/ml/artifacts/`** — serialization format for trained models
   plus `ModelMetadata` (Phase 1's model): model type, model version,
   training dataset, feature schema version, feature ordering, training
   timestamp, class mapping, preprocessing version, evaluation metrics. Model
   files themselves are gitignored (per Phase 1); only code and metadata
   schema live in the repo.

4. **Evaluation** — for LightGBM: accuracy, precision, recall, F1, confusion
   matrix, per-class metrics. For Isolation Forest: precision, recall,
   false-positive rate, false-negative rate, threshold behavior. Clearly
   label which numbers are training/validation/test-split results — never
   report a single blended number as if it were held-out performance (spec
   §16).

5. **`scripts/train/`** — CLI entry points a human runs on their dev machine
   to reproduce training end-to-end (dataset path in → artifact + metadata
   out).

## Explicit non-goals for this phase

No runtime inference code on the Pi side (that's Phase 5). No behavioral
analysis, no threat engine, no firewall logic.

## Tests (`tests/ml/`)

- Adapters tested against small synthetic fixture CSVs you construct (a
  handful of rows matching each dataset's real column layout) — not the full
  real datasets, which won't be present in CI.
- Missing-value and invalid-value handling produces the documented, tested
  behavior.
- Missing a required canonical feature → adapter raises a clear error rather
  than silently dropping it.
- If real dataset files aren't found at the configured path, the training
  script exits with a clear, actionable error message (test this path
  explicitly, don't just eyeball it).
- `ModelMetadata` produced by a (small, fast, fixture-driven) training run
  has all required fields populated and consistent with the run.

## Definition of done

Everything in `CLAUDE.md` → "Definition of done for a phase". In
`docs/PROGRESS.md`, be explicit: adapters/preprocessing are **Tested** (via
fixtures); actual trained-model quality against the real datasets is
**Environment-dependent** until the user runs `scripts/train/` on their dev
machine with the real CICIDS2017/UNSW-NB15 files and reports back real
metrics — do not put invented numbers in `docs/PROGRESS.md`.

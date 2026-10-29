# Phase 19: ML on feature schema 3.0.0, trained from our own pcaps

**Read first:**
- `CLAUDE.md` (v2 section and the v1 ML rules: ML produces evidence, never commands; one canonical extractor; never run inference on an unfrozen schema), `docs/HANDOFF.md`
- `docs/ADDENDUM_4.md` D4 (ML ⇒ at most MONITOR), D6 (the native engine is the only producer of training rows), D7 (env tags)
- `docs/v2/PLAN_FINAL.md` §4.4–4.5 (features, D2, D3) and §5 (splits, metrics)
- `docs/v2/critique_ml.md` in full (the methodology this phase implements; §10 lists the paper's ML table and figures)
- `docs/FEATURE_SCHEMA.md`, `docs/ML_PIPELINE.md`, `docs/ML_DATA_AUDIT.md`, `docs/KNOWN_ISSUES.md` #1, #2
- `pirewall/features/{schema,extractor}.py`, `pirewall/ml/**`, `scripts/train/**`, `scripts/dataset/pcap_to_flows.py`
- `pirewall/runtime/pipeline_v2.py` and `pirewall/detection/coordinator.py` (how D3 is wired today, and why D2 is not: PROGRESS "Phase 17 details", deviation 4)
- `lab/README.md` and `lab/benign_fp.py` (phase 18; the evaluator takes model artifacts)

**Depends on:** phases 17 and 18. Real results also need `pi-live` benign pcaps and `pi-scripted` attack runs from the Pi (RUNBOOK_PI H0 onwards and campaign #1). **Without them, build and test everything on `mock` data and label it `mock`; do not report a model quality number.**

**Owns:** `pirewall/features/**`, `pirewall/ml/**`, `scripts/train/**`, `scripts/dataset/**` (after 15), `docs/FEATURE_SCHEMA.md`, `docs/ML_PIPELINE.md`, the ML-evidence wiring in `pirewall/runtime/pipeline_v2.py` and `pirewall/detection/coordinator.py`, and this phase's PROGRESS row and section. **`pirewall/runtime/core.py` passes to phase 19 for model loading and D2 wiring only** (V2_CONTRACTS §12); keep any change there minimal and listed as a deviation.

## Goal
D2 (Isolation Forest) and D3 (LightGBM) are retrained on features computed by the runtime engine from this network's own traffic, evaluated with a protocol that cannot leak, and wired as MONITOR/corroboration evidence under `engine = "v2"`. The v1 models keep working for the `engine = "v1"` baseline.

## Deliverables
1. **Feature schema 3.0.0** (`pirewall/features/schema.py`, `docs/FEATURE_SCHEMA.md`). Freeze it in its **own commit**, before any training or inference code uses it.
   - Native-engine features only (the columns `pcap_to_flows` emits). `destination_port` becomes a coarse category (well-known service buckets, documented). Excluded: IP, MAC, OUI, raw ports, SNI, app names, timestamps, and any field that identifies a run.
   - One canonical extractor still: schema 2.0.0 stays computable for v1 (the loader already refuses a model whose schema mismatches). Choose the mechanism (a versioned column projection over the same extractor is the expected shape), document it, and pin it with tests that 2.0.0 vectors are unchanged.
   - `pcap_to_flows.py` gains `--schema 3.0.0` (default stays whatever v1 needs until this phase's DoD), and the parity test proves live == pcap rows for 3.0.0 too.
2. **Dataset builder** `scripts/dataset/build_dataset.py`. Inputs: `pcap_to_flows` output directories + their manifests + `ground_truth.jsonl`. Splits (critique_ml.md):
   - benign: temporal 60 / 15 / ≥ 1 h gap / 25 (train / validation / gap / test);
   - attacks: by run ID, leave-one-tool-out (masscan is held out), parameter variants held out;
   - connection-grouped so one connection never spans splits; rows capped per run so no single run dominates.
   - Each split file has a sha256; the test split is touched **once**, recorded in an append-only access ledger next to the dataset. Env tags carried through; mixing `pi-live`, `pi-scripted` and `mock` in one dataset is refused unless `--allow-mixed-benign pi-live,pi-scripted` (benign only) is given, and that choice is recorded.
3. **D2: Isolation Forest** trained on the benign training block only. Threshold at a **validation per-flow FPR of 1e-3**. Metadata sidecar: schema version, env tag, input manifest hashes, the threshold and how it was chosen, `artifact_sha256` (so `pirewall-start`'s sidecar warning goes away).
4. **D3: LightGBM** binary (benign vs attack), plus a coarse family head (cuttable; first thing to cut after the CIC-IDS2017 test). Isotonic calibration on validation; operating point chosen by benign FPR, not by accuracy. Same sidecar rules.
5. **Shortcut audit, before any number is reported** (`scripts/train/shortcut_audit.py`): per-feature importance, single-feature models, permutation tests, the ablation with and without the port category, and a check that no feature separates runs or capture files on its own. A failed audit blocks the report and says which feature.
6. **Reports** (`reports/` stays gitignored; a short summary goes to PROGRESS with its env tag): PR-AUC, recall at FPR 1e-3 and 1e-4, expected alerts per day at the operating point, the reliability diagram (D3), PSI drift between training and test benign blocks, and benign vs attack score distributions. Write the data behind Table V and Figs 3–5 as JSON/CSV so phase 20 can render them; each carries the env tag.
7. **Runtime wiring under `engine = "v2"`**:
   - load the 3.0.0 models when present (schema checked at load and per call, as today);
   - D2 becomes `AnomalyEvidence` (MONITOR only), D3 becomes `ClassifierEvidence` at its benign-FPR operating point (corroboration only), both through the existing coordinator/`V2Pipeline` path;
   - prove again, with the policy matrix and a mutation test, that no ML output can raise an action above MONITOR alone (D4).
   - `engine = "v1"` keeps loading the 2.0.0 models unchanged.
8. **External test (cuttable, first cut):** CIC-IDS2017 Friday through `pcap_to_flows` as an external test set only, if the human has downloaded it. Never trained on.

## Tests
- Schema 3.0.0 pinned (names, order, version), 2.0.0 unchanged, excluded fields absent, port-category mapping total.
- Splits: temporal gap respected, no connection in two splits, leave-one-tool-out holds the tool out, ledger records each test access, mixed env tags refused.
- Training on the phase-18 mock pcaps end to end (env=mock) produces artifacts with complete sidecars; the loader refuses a schema or hash mismatch.
- Operating points: the D2 threshold yields the requested validation FPR on a constructed sample; calibration is monotonic.
- v2 wiring: mock end-to-end with models loaded; ML-only evidence never exceeds MONITOR in any mode.

## Non-goals
No change to D1, the kernel tier, the policy table's ceilings or guard defaults. No public-dataset training. No paper tables (phase 20). Never fabricate or round a metric that was not computed in this session.

## Definition of done
- Gates green (ruff, pyright strict, pytest as `pw`, netns as root; see `docs/HANDOFF.md`).
- PROGRESS row 19 and "Phase 19 details": pipeline Tested on `mock`; model quality **Environment-dependent** until trained on `pi-live` + `pi-scripted` data (RUNBOOK_PI H28–H30). If real data was available, its numbers carry their `pi-*` tag.
- `docs/FEATURE_SCHEMA.md` and `docs/ML_PIPELINE.md` describe 3.0.0 and the new protocol; KNOWN_ISSUES #1/#2 updated.
- Commit (schema freeze first, then the rest), merge to `main`, push.

# Phase 5 — Runtime ML inference, behavioral analysis & threat assessment

Read `CLAUDE.md` and `docs/MASTER_SPEC.md` sections 14 (inference), 15
(runtime compatibility check), 17, 18 before starting. Confirm Phase 4 is
marked complete in `docs/PROGRESS.md`.

## Goal

On the Pi side: load trained artifacts, run inference through the same
feature schema used in training, add deterministic behavioral analysis, and
combine everything into an explainable `ThreatAssessment`. This phase stops
before any firewall decision is made.

## Deliverables

1. **`pirewall/ml/inference/`** — loads the LightGBM and Isolation Forest
   artifacts + `ModelMetadata` produced in Phase 4. Before running inference,
   validates `runtime feature schema version == model feature schema
   version` (from Phase 3's `schema.py` vs the artifact's `ModelMetadata`);
   if they don't match, **refuse inference** and raise `ModelLoadError` or
   `ModelInferenceError` with a clear message — never silently run a
   mismatched model (spec §15).

2. **`pirewall/detection/known_attack.py`** — wraps LightGBM inference,
   produces a `KnownEvidence` object (Phase 1's model): predicted class,
   confidence, model version, feature schema version.

3. **`pirewall/detection/anomaly.py`** — wraps Isolation Forest inference,
   produces an `AnomalyEvidence` object. Treat an anomaly strictly as
   evidence, not as an automatic verdict (spec §14).

4. **`pirewall/detection/behavior.py`** — deterministic, non-ML behavioral
   analysis over bounded per-source/per-flow state: repeated connections,
   connection frequency, burst behavior, persistence, destination diversity,
   repeated failures, temporal patterns, scanning indicators (spec §17). No
   LLM, no ML model here — plain deterministic logic. State must be bounded
   (max tracked sources/keys, eviction) so it can't be used to exhaust
   memory. Produces `BehaviorAssessment` (Phase 1's model).

5. **`pirewall/engine/scoring.py`** — combines `KnownEvidence` +
   `AnomalyEvidence` + `BehaviorAssessment` into a numeric threat score using
   weights/thresholds pulled from config (Phase 1) — no magic constants
   inline in this module.

6. **`pirewall/engine/threat.py`** — produces the final `ThreatAssessment`
   (Phase 1's model): threat score, one of `ThreatLevel.LOW/MEDIUM/HIGH/
   CRITICAL` (configurable thresholds), a human-readable explanation, and the
   list of contributing evidence objects — this must be genuinely
   explainable, not a black-box number.

## Explicit non-goals for this phase

No `FirewallDecision`, no candidate rules, no firewall backend calls. This
phase's output is `ThreatAssessment` and nothing downstream of it.

## Tests (`tests/unit/` and `tests/ml/`)

- Schema-mismatch between runtime and model metadata → inference refuses and
  raises the correct typed exception (don't run inference anyway).
- Behavioral analysis: scripted packet/flow sequences for a port scan, a
  SYN flood pattern, and a repeated-SSH-connection pattern each produce the
  expected qualitative evidence (e.g. "possible scanning" flag set) using
  `FakePacketCapture`-driven flows from Phase 2/3.
- Behavior state is bounded: feeding many distinct sources doesn't grow
  memory/state unboundedly (a flood test with an assertion on tracked-key
  count).
- Scoring: given fixed evidence inputs and fixed config thresholds, the
  threat score and resulting `ThreatLevel` are deterministic and match hand-
  computed expected values for a few representative cases (benign, weak
  evidence, strong evidence, multiple corroborating evidence types).
- Re-running the same evidence through `threat.py` twice gives identical
  output (determinism).

## Definition of done

Everything in `CLAUDE.md` → "Definition of done for a phase". Update
`docs/PROGRESS.md` row for Phase 5. Label actual detection *accuracy* against
real attacks as **Environment-dependent** (needs the attack-lab testing in
spec §34, which is a later manual step) — this phase is about correct
plumbing and explainability, not claiming a specific detection rate.

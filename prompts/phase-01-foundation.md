# Phase 1 — Foundation: repo scaffolding, configuration, core domain models, interfaces

Read `CLAUDE.md` and `docs/MASTER_SPEC.md` sections 9, 10, 20 (interfaces
pattern only), 35, 36, 37, 44 before starting. Also read `docs/ADDENDUM.md`
items **A1, A2, A5, A6** — this phase lays their groundwork (config fields
and models), even though the logic that uses them comes in Phase 6. Update
`docs/PROGRESS.md` (including the Addendum items table) when done.

## Goal

Stand up the repository skeleton, the configuration system, the typed
exception hierarchy, and every core domain model — with no business logic
behind them yet. This phase produces the typed vocabulary every later phase
builds on, so get the shapes right.

## Deliverables

1. **Repo scaffolding** matching the tree in spec §35 exactly (create every
   directory listed, with `__init__.py` where it's a Python package; empty
   subpackages are fine — they'll be filled in later phases). Root
   `README.md` (brief — one paragraph on what pirewall is, pointer to
   `docs/`), `.gitignore` (Python, uv, datasets, certs, secrets, `__pycache__`,
   model artifacts under `pirewall/ml/artifacts/`).

2. **`pyproject.toml`** — `uv`-managed, Python 3.12+, dependencies limited to
   what's listed in `CLAUDE.md`. Configure `ruff` and `pyright --strict`.
   Configure `pytest` with `tests/` as the root.

3. **`config/default_config.toml`** — every section from spec §37 (`network`,
   `capture`, `flow`, `features`, `detection`, `ml`, `threat`, `firewall`,
   `api`, `authentication`, `admin`, `logging`, `integration`, `security`)
   with documented placeholder values and comments. No real secrets, no
   hardcoded interface names presented as real — use obviously-placeholder
   values like `"eth0"` / `"CHANGE_ME"` with a comment saying so.

4. **`pirewall/config/`** — a config loader: reads TOML, validates into a
   Pydantic v2 settings model (one sub-model per section above), raises
   `ConfigurationError` with a clear message on missing/invalid fields. No
   silent defaults for security-relevant fields (Admin PC IP, auth settings).

5. **`pirewall/core/enums.py`** — `StrEnum`/`Enum` for: `ThreatLevel` (LOW,
   MEDIUM, HIGH, CRITICAL), `FirewallAction` (ALLOW, MONITOR, RATE_LIMIT,
   BLOCK), `RuleStatus` — use the **updated** lifecycle from
   `docs/ADDENDUM.md` (`CANDIDATE, VALIDATING, REJECTED, SHADOWED,
   PENDING_APPROVAL, APPROVED, DEPLOYED, ACTIVE, EXPIRED, DISABLED,
   REMOVED`), `RuleDirection`, `Protocol` (TCP, UDP, ICMP, ICMPv6, ...),
   `SecurityEventType` (matching the list in spec §31), `EventSeverity`,
   `EnforcementMode` (`SHADOW, ASSISTED, ACTIVE` — addendum A1), and
   `FailureMode` (`FAIL_OPEN, FAIL_CLOSED` — addendum A6).

6. **`pirewall/core/exceptions.py`** — the full hierarchy from spec §44
   (`ConfigurationError`, `CaptureError`, `PacketParseError`, `FlowError`,
   `FeatureExtractionError`, `ModelLoadError`, `ModelInferenceError`,
   `ThreatAssessmentError`, `FirewallError`, `RuleValidationError`,
   `AuthenticationError`, `IntegrationError`), all inheriting from one
   `PirewallError` base. Each with a docstring on when it's raised.

7. **`pirewall/core/models/`** — Pydantic v2 domain models for everything in
   spec §9: `Flow`, `FeatureVector`, `KnownEvidence`, `AnomalyEvidence`,
   `BehaviorAssessment`, `ThreatAssessment`, `FirewallDecision`,
   `FirewallRule`, `CandidateRule`, `SecurityEvent`, `ModelMetadata`. Field
   sets should reflect what spec §15, §23, §31 describe even though the
   producing logic doesn't exist yet — this is the frozen shape later phases
   fill in. Strict validation (e.g. IP/CIDR fields use `ipaddress` types or
   Pydantic's IP types, ports are bounded ints, timestamps are timezone-aware
   `datetime`).

8. **`AllowlistEntry` domain model** (addendum A2) — add alongside the other
   models in `pirewall/core/models/`: id, target (IP/CIDR, IPv4 only per A5),
   optional port, optional protocol, reason, created_at, created_by. Strict
   validation like everything else in this phase.

9. **Config additions for the addendum** — extend `config/default_config.toml`
   and the Pydantic settings models with:
   - `firewall.enforcement_mode` (default `"shadow"`, addendum A1)
   - `firewall.assisted_review_threshold` (addendum A7 — used starting
     Phase 6, but the field belongs here)
   - `firewall.max_adaptive_rules_per_window` / `firewall.rate_window_seconds`
     (addendum A3)
   - `firewall.allowlist` seed entries, empty by default (addendum A2)
   - `failure.mode` (default `"fail_open"`, addendum A6)
   All with clear comments explaining what they do and pointing at
   `docs/ADDENDUM.md` by item letter.

10. **`docs/CODING_STANDARDS.md`** — write this now, capturing the rules from
    `CLAUDE.md` in slightly more detail plus any conventions you choose while
    building this phase (naming, module layout, docstring style).

## Explicit non-goals for this phase

No packet capture, no flow logic, no feature extraction logic, no ML, no
firewall backend, no API. If a model needs a field that only makes sense once
later logic exists, add the field with a clear docstring — don't add the
logic.

## Tests (`tests/unit/`)

- Enum values match spec.
- Exception hierarchy (each subclass raised/caught correctly, base class
  catches all).
- Each domain model: valid construction succeeds; invalid construction
  (bad IP, bad CIDR, out-of-range port, negative counts, etc.) raises a
  Pydantic validation error.
- Config loader: valid TOML loads correctly; missing required
  section/field raises `ConfigurationError` with a useful message; malformed
  TOML raises `ConfigurationError` (not a raw parser exception).

## Definition of done

Everything in `CLAUDE.md` → "Definition of done for a phase", applied to this
phase's scope. Update `docs/PROGRESS.md` row for Phase 1.

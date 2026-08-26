# pirewall — Coding Standards

This captures the conventions established while building the project, on
top of the non-negotiable rules already in `CLAUDE.md`. When the two
disagree, `CLAUDE.md` wins.

## Module layout

- One subsystem per file/package, matching `docs/MASTER_SPEC.md` §35's
  repository structure exactly. Don't add new top-level packages without
  updating that structure's rationale in `docs/ARCHITECTURE.md`.
- `pirewall/core/models/` has one file per domain model family (e.g.
  `flow.py`, `rule.py`), plus `common.py` for shared value objects
  (`PirewallModel`, `PacketSizeStats`, ...) reused across several models.
  Re-export everything through `pirewall/core/models/__init__.py` so callers
  can `from pirewall.core.models import Flow` without knowing which file it
  lives in.
- Dependency direction is one-way: `core` → `capture`/`flow`/`features` →
  `detection` → `engine` → `firewall` → `api`/`web`. `pirewall/config/` is
  infrastructure that any layer may import; it never imports back into a
  higher layer.

## Naming

- Modules/functions/variables: `snake_case`. Classes: `PascalCase`. Enum
  members: `UPPER_SNAKE_CASE` with lowercase `snake_case` string values
  (see `pirewall/core/enums.py`) so serialized JSON/config values read
  naturally.
- Test files: `tests/<suite>/test_<module_under_test>.py`, one file per
  logical unit under test (a single model family, a single loader, etc.) —
  split further if a test file starts covering more than one subsystem
  concern.
- Exceptions end in `Error` and live only in `pirewall/core/exceptions.py`.

## Docstrings

- Every public module, class, and function gets a docstring stating its
  *contract* — what it's for and any non-obvious invariant — not a
  restatement of its name. One-line docstrings are fine when there's
  nothing non-obvious to add.
- Reference the spec section or addendum item a piece of code implements
  (e.g. `(spec §24)`, `(ADDENDUM.md A2)`) directly in the docstring so the
  connection back to the requirement survives refactors.
- No inline comments explaining *what* code does (identifiers should do
  that); only *why*, when it's a hidden constraint or a workaround.

## Pydantic v2 models

- All domain models inherit `pirewall.core.models.common.PirewallModel`
  (`extra="forbid"`, not `strict=True`). Domain models sit at the boundary
  of TOML/JSON/dataset-row data, where an `IPv4Address`, an `Enum`, or a
  tuple always arrives as its plain string/list wire encoding — Pydantic's
  default ("lax") validation mode accepts those encodings while still
  enforcing the annotated type and every field constraint; `strict=True`
  would reject the very encodings the boundary needs to parse.
- **Constructing a model with an IP/CIDR/enum field from a raw string in
  Python code (including tests) must go through `Model.model_validate({...})`
  with a plain dict, not the keyword-argument constructor.** Pyright's
  strict mode synthesizes an exact-typed `__init__` for Pydantic models
  (e.g. `source_ip: IPv4Address`), so `Flow(source_ip="10.0.0.5")` is a
  type error under `pyright --strict` even though it validates correctly at
  runtime — `model_validate` accepts `Any` and sidesteps this without
  weakening the runtime check. If you already have a real `IPv4Address`/
  `IPv4Network`/enum instance in hand, the keyword constructor is fine and
  preferred (it's the more precise, more readable option when types already
  line up).
- Cross-field invariants (e.g. `Flow.forward_packet_count +
  backward_packet_count == packet_count`, `ThreatConfig`'s ascending
  thresholds) go in a `@model_validator(mode="after")`, not in the code that
  constructs the model — the model should be unconstructable in an invalid
  state regardless of caller.
- Prefer `tuple[...]` over `list[...]` for domain-model fields that
  represent a fixed collection (evidence, feature names/values, detected
  patterns) — it signals the collection isn't meant to be mutated in place,
  and keeps the model hashable-by-convention.

## Config

- Every config section is its own Pydantic model in `pirewall/config/models.py`
  under `PirewallConfig`. Security-relevant fields (Admin PC IP, TLS paths,
  admin credentials) have **no default value** — a missing field is a
  `ConfigurationError` at load time, never a silent default.
- `pirewall.config.loader.load_config` is the only place allowed to catch
  `tomllib.TOMLDecodeError` / `pydantic.ValidationError` directly; everywhere
  else, a config problem should already have become a `ConfigurationError`.

## Type checking

- `pyright --strict` must be clean, including `tests/`. This project targets
  zero suppressions (`# type: ignore` / `# pyright: ignore`) — if you hit
  one, it usually means the code needs a real type fix (see the
  `model_validate` note above for the one recurring, legitimate exception).
- Any `Any` requires an inline comment explaining why it's unavoidable
  (CLAUDE.md). No module has needed one yet — `pirewall.config.loader`
  passes the dict `tomllib.loads` returns straight into
  `PirewallConfig.model_validate` without ever binding it to an `Any`-typed
  name in our own code.

"""Helpers every lab script shares: env-tag rules, output locations, project hashes.

* **Env tags (ADDENDUM_4.md D7).** A script takes `--env-tag` only where the
  tag cannot be read from an input manifest. It never defaults to a `pi-*`
  tag, and `require_env_tag` refuses a `pi-*` tag off a Raspberry Pi using
  `scripts.deployment.startup.SystemProbe.is_raspberry_pi`, the same check
  `pirewall-start --data-mode` uses (one Pi detector, not two).
* **Outputs never land in the tracked tree.** Inside the repository a
  script may only write under `lab/runs/`, `lab/data/` or a `lab/**/out/`
  directory, all gitignored (`check_output_location`).
* **Project hashes** (`project_provenance`): config, D1 thresholds (and
  whether they are frozen), policy table and model artifacts, for
  manifests.

Stdlib at import time; the project is imported lazily inside the functions
that need it, so `lab/manifest.py` users without the venv never load it.
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from lab.manifest import ENV_TAGS, Hashes, sha256_file

__all__ = [
    "PI_TAGS",
    "REPO_ROOT",
    "LabError",
    "Provenance",
    "check_output_location",
    "new_run_dir",
    "project_provenance",
    "require_env_tag",
]

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
PI_TAGS: Final = frozenset({"pi-live", "pi-scripted"})
_ALLOWED_IN_REPO: Final = ("lab/runs", "lab/data")


class LabError(Exception):
    """A refusal with a message for the operator. Scripts print it and exit 2."""


def require_env_tag(tag: str, *, on_pi: bool | None = None) -> str:
    """`tag` if it is a D7 tag this host may claim. Raises `LabError`.

    `on_pi` overrides the device-tree probe (tests); None asks
    `SystemProbe().is_raspberry_pi()`, which honours
    `PIREWALL_PREFLIGHT_PROC_ROOT` like the rest of preflight.
    """
    if tag not in ENV_TAGS:
        raise LabError(f"env tag {tag!r} is not one of {', '.join(ENV_TAGS)} (ADDENDUM_4.md D7)")
    if tag in PI_TAGS:
        if on_pi is None:
            from scripts.deployment.startup import SystemProbe

            on_pi = SystemProbe().is_raspberry_pi()
        if not on_pi:
            raise LabError(
                f"env tag {tag} claims a Raspberry Pi result, but this host is not a Pi. Only real Pi runs "
                "may carry a pi-* tag (ADDENDUM_4.md D7); use sandbox or mock."
            )
    return tag


def check_output_location(path: Path, repo_root: Path = REPO_ROOT) -> Path:
    """`path` resolved, if it is outside the repo or under a gitignored lab output directory."""
    resolved = path.resolve()
    root = repo_root.resolve()
    if not resolved.is_relative_to(root):
        return resolved
    relative = resolved.relative_to(root).as_posix()
    parts = relative.split("/")
    if any(relative == base or relative.startswith(base + "/") for base in _ALLOWED_IN_REPO):
        return resolved
    if parts[0] == "lab" and "out" in parts[1:]:
        return resolved
    raise LabError(
        f"{path}: inside the repository a lab script writes only under lab/runs/, lab/data/ or a "
        "lab/**/out/ directory (gitignored), never into the tracked tree"
    )


def new_run_dir(parent: Path, name: str, repo_root: Path = REPO_ROOT) -> Path:
    """Create `<parent>/<UTC timestamp>-<name>/` (never reused). Raises `LabError` if it exists."""
    base = check_output_location(parent, repo_root)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    directory = base / f"{stamp}-{name}"
    try:
        directory.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise LabError(f"{directory} already exists; run directories are never reused") from exc
    return directory


@dataclass(frozen=True, slots=True)
class Provenance:
    """What a manifest records about the project's inputs."""

    config_sha256: str | None
    hashes: Hashes
    pipeline_engine: str | None = None
    enforcement_mode: str | None = None
    guard_modes: Mapping[str, str] = field(default_factory=dict[str, str])
    thresholds_path: str | None = None


def _canonical_config_sha256(config_path: Path) -> str:
    """SHA-256 of the *validated* config (defaults filled in), so formatting edits do not change it."""
    from pirewall.config.loader import load_config

    config = load_config(config_path)
    return hashlib.sha256(json.dumps(config.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()


def project_provenance(config_path: Path, repo_root: Path = REPO_ROOT) -> Provenance:
    """Config, thresholds, policy table and model hashes for `config_path`. Raises `LabError`."""
    from pirewall.config.loader import load_config
    from pirewall.core.exceptions import ConfigurationError
    from pirewall.detection_v2.thresholds import load_thresholds

    try:
        config = load_config(config_path)
    except ConfigurationError as exc:
        raise LabError(f"config {config_path}: {exc}") from exc

    def resolve(value: str | Path) -> Path:
        candidate = Path(value)
        return candidate if candidate.is_absolute() else repo_root / candidate

    thresholds_path = resolve(config.d1.thresholds_path)
    thresholds_sha: str | None = None
    frozen: bool | None = None
    if thresholds_path.is_file():
        thresholds_sha = sha256_file(thresholds_path)
        try:
            frozen = load_thresholds(thresholds_path).frozen
        except ConfigurationError:
            frozen = None
    table_path = resolve(config.policy.table_path)
    models: dict[str, str] = {}
    for name, value in (
        ("lightgbm", config.ml.lightgbm_model_path),
        ("isolation_forest", config.ml.isolation_forest_model_path),
    ):
        if resolve(value).is_file():
            models[name] = sha256_file(resolve(value))
    guards = config.guards
    return Provenance(
        config_sha256=_canonical_config_sha256(config_path),
        hashes=Hashes(
            thresholds=thresholds_sha,
            thresholds_frozen=frozen,
            policy_table=sha256_file(table_path) if table_path.is_file() else None,
            models=models,
        ),
        pipeline_engine=config.pipeline.engine.value,
        enforcement_mode=config.firewall.enforcement_mode.value,
        guard_modes={
            "raw": guards.raw_mode.value,
            "input": guards.input_mode.value,
            "forward": guards.forward_mode.value,
        },
        thresholds_path=str(thresholds_path),
    )

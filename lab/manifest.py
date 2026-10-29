"""One manifest schema for every lab artifact: run, capture, dataset, evaluator (PLAN_FINAL §5, G7).

Every directory the harness writes holds a `manifest.json`:

```
{
  "schema": "pirewall-lab-manifest", "version": 1,
  "kind": "run" | "campaign" | "capture" | "dataset" | "evaluator" | "score" | "scripted-benign" | "replay",
  "env_tag": "pi-live" | "pi-scripted" | "sandbox" | "mock",     # exactly one (D7)
  "phase": "dev" | "eval" | null,                                  # campaign runs only
  "created_at": ISO-8601 UTC, "tool": "lab/<script>.py",
  "git": {"sha": str | null, "dirty": bool | null},
  "config_sha256": str | null,
  "hashes": {"thresholds": str | null, "thresholds_frozen": bool | null,
             "policy_table": str | null, "ruleset": str | null, "models": {name: sha256}},
  "pipeline_engine": str | null, "enforcement_mode": str | null,
  "guard_modes": {"raw": .., "input": .., "forward": ..},
  "tool_versions": {tool: version}, "clock_offsets": {host: seconds},
  "extra": {...},                                                  # per-kind details
  "files": {"relative/posix/path": sha256, ...}                    # every file but manifest.json
}
```

`files` covers every file under the directory except `manifest.json`
itself and anything under a sub-directory that holds its own
`manifest.json` (that one seals its own tree). `lab/verify_manifest.py`
recomputes all of it.

**Stdlib only**, so `lab/benign/background.py` can use it on client
devices that have no project venv. The few fields that need the project
(config, thresholds, policy hashes) are filled by callers on the Pi or dev
machine and passed in as plain values.
"""

import hashlib
import json
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

__all__ = [
    "ENV_TAGS",
    "MANIFEST_NAME",
    "SCHEMA",
    "VERSION",
    "Hashes",
    "Manifest",
    "ManifestError",
    "git_state",
    "hash_tree",
    "read_manifest",
    "sha256_file",
    "write_manifest",
]

SCHEMA: Final = "pirewall-lab-manifest"
VERSION: Final = 1
MANIFEST_NAME: Final = "manifest.json"
ENV_TAGS: Final = ("pi-live", "pi-scripted", "sandbox", "mock")
"""ADDENDUM_4.md D7. Spelled here, not imported, so the module stays stdlib-only;
`tests/unit/test_lab_manifest.py` pins it to `pirewall.core.enums.EnvTag`."""

Kind = Literal["run", "campaign", "capture", "dataset", "evaluator", "score", "scripted-benign", "replay"]
KINDS: Final[tuple[Kind, ...]] = (
    "run",
    "campaign",
    "capture",
    "dataset",
    "evaluator",
    "score",
    "scripted-benign",
    "replay",
)
Phase = Literal["dev", "eval"]
Json = str | int | float | bool | None | list["Json"] | dict[str, "Json"]


class ManifestError(Exception):
    """A manifest is missing, malformed, or does not match its directory."""


@dataclass(frozen=True, slots=True)
class Hashes:
    """Hashes of the inputs that decide what a run measures."""

    thresholds: str | None = None
    thresholds_frozen: bool | None = None
    policy_table: str | None = None
    ruleset: str | None = None
    models: Mapping[str, str] = field(default_factory=dict[str, str])

    def as_json(self) -> dict[str, Json]:
        """The `hashes` object."""
        return {
            "thresholds": self.thresholds,
            "thresholds_frozen": self.thresholds_frozen,
            "policy_table": self.policy_table,
            "ruleset": self.ruleset,
            "models": dict(sorted(self.models.items())),
        }


@dataclass(frozen=True, slots=True)
class Manifest:
    """Everything a manifest records except `files`, which `write_manifest` computes."""

    kind: Kind
    env_tag: str
    tool: str
    phase: Phase | None = None
    git_sha: str | None = None
    git_dirty: bool | None = None
    config_sha256: str | None = None
    hashes: Hashes = field(default_factory=Hashes)
    pipeline_engine: str | None = None
    enforcement_mode: str | None = None
    guard_modes: Mapping[str, str] = field(default_factory=dict[str, str])
    tool_versions: Mapping[str, str] = field(default_factory=dict[str, str])
    clock_offsets: Mapping[str, float] = field(default_factory=dict[str, float])
    extra: Mapping[str, Json] = field(default_factory=dict[str, Json])
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def __post_init__(self) -> None:
        if self.env_tag not in ENV_TAGS:
            raise ManifestError(f"env tag {self.env_tag!r} is not one of {', '.join(ENV_TAGS)} (D7)")
        if self.kind not in KINDS:
            raise ManifestError(f"unknown manifest kind {self.kind!r}")
        if self.phase not in (None, "dev", "eval"):
            raise ManifestError(f"phase must be dev or eval, not {self.phase!r}")

    def as_json(self, files: Mapping[str, str]) -> dict[str, Json]:
        """The whole document, with `files` filled in."""
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "kind": self.kind,
            "env_tag": self.env_tag,
            "phase": self.phase,
            "created_at": self.created_at,
            "tool": self.tool,
            "git": {"sha": self.git_sha, "dirty": self.git_dirty},
            "config_sha256": self.config_sha256,
            "hashes": self.hashes.as_json(),
            "pipeline_engine": self.pipeline_engine,
            "enforcement_mode": self.enforcement_mode,
            "guard_modes": dict(sorted(self.guard_modes.items())),
            "tool_versions": dict(sorted(self.tool_versions.items())),
            "clock_offsets": dict(sorted(self.clock_offsets.items())),
            "extra": dict(self.extra),
            "files": dict(sorted(files.items())),
        }


def sha256_file(path: Path) -> str:
    """SHA-256 of a file's bytes, streamed."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_tree(directory: Path) -> dict[str, str]:
    """`{relative posix path: sha256}` for every file this directory's manifest seals.

    Skips `manifest.json` itself and every sub-directory that holds its own
    `manifest.json`. Symlinks are refused: a manifest seals bytes it owns.
    """
    files: dict[str, str] = {}

    def walk(current: Path) -> None:
        for entry in sorted(current.iterdir()):
            if entry.is_symlink():
                raise ManifestError(f"{entry}: symlinks are not sealed by a manifest; copy the file in")
            if entry.is_dir():
                if (entry / MANIFEST_NAME).is_file():
                    continue
                walk(entry)
            elif entry.is_file() and not (current == directory and entry.name == MANIFEST_NAME):
                files[entry.relative_to(directory).as_posix()] = sha256_file(entry)

    walk(directory)
    return files


def write_manifest(directory: Path, manifest: Manifest) -> dict[str, Json]:
    """Seal `directory`: hash its files and write `manifest.json`. Returns the document.

    Refuses to overwrite an existing manifest: run directories are
    append-only (critique_safety_eval.md "Traceability"); a re-run is a new
    directory.
    """
    path = directory / MANIFEST_NAME
    if path.exists():
        raise ManifestError(f"{path} already exists; a sealed directory is never re-sealed")
    document = manifest.as_json(hash_tree(directory))
    path.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8", newline="\n")
    return document


def read_manifest(directory: Path) -> dict[str, Json]:
    """Load and shape-check `directory/manifest.json`. Raises `ManifestError`."""
    path = directory / MANIFEST_NAME
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ManifestError(f"{directory}: no {MANIFEST_NAME}") from exc
    except (OSError, ValueError) as exc:
        raise ManifestError(f"{path}: unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError(f"{path}: not a JSON object")
    document = cast(dict[str, Json], raw)
    if document.get("schema") != SCHEMA or document.get("version") != VERSION:
        raise ManifestError(f"{path}: not a {SCHEMA} v{VERSION} manifest")
    if document.get("env_tag") not in ENV_TAGS:
        raise ManifestError(
            f"{path}: env tag {document.get('env_tag')!r} is not one of {', '.join(ENV_TAGS)}"
        )
    if document.get("kind") not in KINDS:
        raise ManifestError(f"{path}: unknown kind {document.get('kind')!r}")
    if not isinstance(document.get("files"), dict):
        raise ManifestError(f"{path}: `files` is missing")
    return document


def git_state(repo: Path) -> tuple[str | None, bool | None]:
    """(HEAD SHA, whether the tracked tree is dirty), or (None, None) without git."""
    try:
        sha = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None, None
    return sha or None, bool(status.strip())

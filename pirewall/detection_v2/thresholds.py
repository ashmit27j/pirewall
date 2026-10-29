"""D1 thresholds: learned from benign traffic, clamped by security priors, then frozen.

`threshold = clamp(benign P99.9 x margin, floor, ceiling)` per detector and
window (PLAN_FINAL §4.5, critique_redteam item 11). The floors stop a quiet
benign block from producing a hair-trigger threshold; the ceilings are
security priors no benign device crosses (a vertical scan over 100 ports
in 60 s is never benign), so even a poisoned benign soak cannot raise a
threshold above them.

The file (`d1.thresholds_path`, normally `config/d1_thresholds.toml`) is
written by `scripts/train/fit_d1_thresholds.py` and read here. It carries:

* `frozen`: set by `--freeze`; the phase-18 harness refuses campaign #2
  without it.
* `sha256`: a hash over the threshold entries, so a hand edit is visible.
* `[provenance]`: where the numbers came from (input manifest hashes, the
  benign training block's boundaries, env tag), or `source = "floors"` when
  no benign data has been fitted yet.

Until real benign data exists the file ships the floors with
`frozen = false` (phase 17 non-goal: no fitting without data).

No I/O beyond reading and writing that one file; no third-party TOML
writer (CLAUDE.md dependency list), so `dump_thresholds` emits the small,
fixed shape itself.
"""

import hashlib
import json
import math
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from pydantic import Field, ValidationError, model_validator

from pirewall.core.enums import D1Detector
from pirewall.core.exceptions import ConfigurationError
from pirewall.core.models.common import PirewallModel

__all__ = [
    "DEFAULT_PRIORS",
    "THRESHOLD_FILE_VERSION",
    "D1ThresholdFile",
    "Prior",
    "Scope",
    "ThresholdEntry",
    "ThresholdKey",
    "assemble_thresholds",
    "dump_thresholds",
    "entries_sha256",
    "floors_file",
    "load_thresholds",
    "percentile",
    "threshold_from_benign",
]

THRESHOLD_FILE_VERSION: Final = 1

Scope = Literal["device", "destination", "account", "global"]
"""What one threshold counts over: one MAC, one destination, one portal account, or the whole LAN."""


@dataclass(frozen=True, slots=True, order=True)
class ThresholdKey:
    """(detector, scope, window): one threshold. `str()` is the file's `name` field."""

    detector: D1Detector
    scope: Scope
    window_seconds: int

    def __str__(self) -> str:
        return f"{self.detector.value}/{self.scope}/{self.window_seconds}"


@dataclass(frozen=True, slots=True)
class Prior:
    """A detector's security prior: the threshold never goes below `floor` or above `ceiling`."""

    floor: float
    ceiling: float


def _priors() -> dict[ThresholdKey, Prior]:
    d = D1Detector
    table: dict[ThresholdKey, Prior] = {}

    def put(detector: D1Detector, scope: Scope, by_window: Mapping[int, tuple[float, float]]) -> None:
        for window, (floor, ceiling) in by_window.items():
            table[ThresholdKey(detector, scope, window)] = Prior(floor, ceiling)

    # Distinct destination ports on one destination host.
    put(d.VERTICAL_SCAN, "device", {10: (15, 50), 60: (25, 100), 3600: (60, 300)})
    # Distinct destination hosts on one port.
    put(d.HORIZONTAL_SCAN, "device", {10: (20, 64), 60: (40, 128), 3600: (100, 512)})
    # Fraction of connection starts that never got an answer (or got a RST).
    put(d.FAILED_HANDSHAKE, "device", {10: (0.6, 0.95), 60: (0.5, 0.9), 3600: (0.5, 0.9)})
    # Short, similar-size starts to one dst:port among the brute-force ports.
    put(d.BRUTE_FORCE, "device", {10: (10, 30), 60: (20, 60), 3600: (60, 300)})
    # Concurrent slow connections to one destination (ported v1 SLOW_RATE_DOS, default 8).
    put(d.SLOW_RATE_DOS, "device", {10: (8, 50), 60: (8, 50), 3600: (8, 50)})
    # Distinct MACs opening connections to one destination.
    put(d.FAN_IN, "destination", {10: (10, 64), 60: (20, 128), 3600: (40, 256)})
    # New MACs / new leases seen LAN-wide (MAC churn, lease starvation).
    put(d.NEW_MAC_RATE, "global", {10: (5, 20), 60: (10, 30), 3600: (40, 200)})
    put(d.NEW_LEASE_RATE, "global", {10: (5, 20), 60: (10, 30), 3600: (40, 200)})
    # Failed portal logins, per account and LAN-wide.
    put(d.PORTAL_AUTH_FAILURES, "account", {10: (5, 20), 60: (10, 30), 3600: (30, 100)})
    put(d.PORTAL_AUTH_FAILURES, "global", {10: (15, 50), 60: (30, 100), 3600: (100, 400)})
    return table


DEFAULT_PRIORS: Final[Mapping[ThresholdKey, Prior]] = _priors()
"""Documented floors and ceilings, per (detector, scope, window). 3600 s rows apply only if enabled."""


class ThresholdEntry(PirewallModel):
    """One threshold as stored: the value in force, and how it was derived."""

    name: str = Field(min_length=1)
    value: float = Field(ge=0.0)
    floor: float = Field(ge=0.0)
    ceiling: float = Field(ge=0.0)
    # The benign P99.9 and the margin it was multiplied by; None for floors.
    benign_p999: float | None = Field(default=None, ge=0.0)
    margin: float | None = Field(default=None, gt=0.0)
    samples: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _check_clamped(self) -> "ThresholdEntry":
        if self.floor > self.ceiling:
            raise ValueError(f"{self.name}: floor above ceiling")
        if not self.floor <= self.value <= self.ceiling:
            raise ValueError(f"{self.name}: value {self.value} outside [{self.floor}, {self.ceiling}]")
        return self

    @property
    def key(self) -> ThresholdKey:
        """Parse `name` back into its key."""
        return _parse_key(self.name)


class D1ThresholdFile(PirewallModel):
    """The whole thresholds file. `thresholds` maps `str(ThresholdKey)` to its entry."""

    version: int = THRESHOLD_FILE_VERSION
    frozen: bool = False
    sha256: str = Field(min_length=64, max_length=64)
    provenance: dict[str, str | int | float | bool | list[str]] = Field(default_factory=dict)
    thresholds: dict[str, ThresholdEntry]

    @model_validator(mode="after")
    def _check_hash(self) -> "D1ThresholdFile":
        if self.version != THRESHOLD_FILE_VERSION:
            raise ValueError(f"unsupported thresholds file version {self.version}")
        for name, entry in self.thresholds.items():
            if entry.name != name:
                raise ValueError(f"threshold {name!r} names itself {entry.name!r}")
            _parse_key(name)
        expected = entries_sha256(self.thresholds.values())
        if self.sha256 != expected:
            raise ValueError("thresholds sha256 does not match the entries (edited by hand?)")
        return self

    def value(self, key: ThresholdKey) -> float | None:
        """The threshold in force for `key`, or None when the file has no such entry."""
        entry = self.thresholds.get(str(key))
        return None if entry is None else entry.value


def _parse_key(name: str) -> ThresholdKey:
    parts = name.split("/")
    if len(parts) != 3:
        raise ValueError(f"threshold name {name!r} is not detector/scope/window")
    detector, scope, window = parts
    if scope not in ("device", "destination", "account", "global"):
        raise ValueError(f"threshold name {name!r} has an unknown scope")
    try:
        return ThresholdKey(D1Detector(detector), scope, int(window))
    except ValueError as exc:
        raise ValueError(f"threshold name {name!r}: {exc}") from exc


def entries_sha256(entries: Iterable[ThresholdEntry]) -> str:
    """SHA-256 over the entries' canonical JSON, sorted by name (the file's `sha256`)."""
    items = sorted((entry.model_dump(mode="json") for entry in entries), key=lambda item: str(item["name"]))
    return hashlib.sha256(json.dumps(items, sort_keys=True).encode("utf-8")).hexdigest()


def percentile(values: Sequence[float], q: float) -> float:
    """The `q`-quantile (0..1) of `values`, linear interpolation; 0.0 for no values."""
    if not values:
        return 0.0
    ordered = sorted(values)
    position = q * (len(ordered) - 1)
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def threshold_from_benign(values: Sequence[float], margin: float, prior: Prior) -> tuple[float, float]:
    """`(clamp(P99.9(values) x margin, floor, ceiling), P99.9)`."""
    p999 = percentile(values, 0.999)
    return min(max(p999 * margin, prior.floor), prior.ceiling), p999


def floors_file(
    windows: Sequence[int], provenance: Mapping[str, str | int | float | bool | list[str]]
) -> D1ThresholdFile:
    """A thresholds file holding only the floors, for `windows`, `frozen = false`."""
    entries = [
        ThresholdEntry(name=str(key), value=prior.floor, floor=prior.floor, ceiling=prior.ceiling)
        for key, prior in sorted(DEFAULT_PRIORS.items())
        if key.window_seconds in windows
    ]
    return _assemble(entries, frozen=False, provenance={"source": "floors", **provenance})


def _assemble(
    entries: Sequence[ThresholdEntry],
    *,
    frozen: bool,
    provenance: Mapping[str, str | int | float | bool | list[str]],
) -> D1ThresholdFile:
    return D1ThresholdFile(
        frozen=frozen,
        sha256=entries_sha256(entries),
        provenance=dict(provenance),
        thresholds={entry.name: entry for entry in entries},
    )


def assemble_thresholds(
    entries: Sequence[ThresholdEntry],
    *,
    frozen: bool,
    provenance: Mapping[str, str | int | float | bool | list[str]],
) -> D1ThresholdFile:
    """Build a `D1ThresholdFile` (hash included) from fitted entries."""
    return _assemble(entries, frozen=frozen, provenance=provenance)


def load_thresholds(path: str | Path) -> D1ThresholdFile:
    """Read and validate a thresholds file. Raises `ConfigurationError` naming the problem."""
    file_path = Path(path)
    try:
        with file_path.open("rb") as stream:
            raw = tomllib.load(stream)
    except FileNotFoundError as exc:
        raise ConfigurationError(f"D1 thresholds file not found: {file_path}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"D1 thresholds file {file_path} is unreadable: {exc}") from exc
    entries = raw.pop("threshold", [])
    try:
        return D1ThresholdFile.model_validate(
            {**raw, "thresholds": {str(item.get("name")): item for item in entries}}
        )
    except ValidationError as exc:
        raise ConfigurationError(f"D1 thresholds file {file_path} is invalid: {exc}") from exc


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, list):
        items = cast(list[object], value)
        return "[" + ", ".join(_toml_value(item) for item in items) + "]"
    return json.dumps(str(value))  # a JSON string literal is a valid TOML basic string


def dump_thresholds(thresholds: D1ThresholdFile) -> str:
    """Serialise `thresholds` as TOML that `load_thresholds` reads back identically."""
    lines = [
        "# D1 thresholds (ADDENDUM_4.md D4, PLAN_FINAL §4.5). Generated by",
        "# scripts/train/fit_d1_thresholds.py; do not edit by hand (sha256 covers the entries).",
        "# threshold = clamp(benign P99.9 x margin, floor, ceiling).",
        f"version = {thresholds.version}",
        f"frozen = {_toml_value(thresholds.frozen)}",
        f"sha256 = {_toml_value(thresholds.sha256)}",
        "",
        "[provenance]",
    ]
    lines.extend(f"{key} = {_toml_value(value)}" for key, value in sorted(thresholds.provenance.items()))
    for name in sorted(thresholds.thresholds):
        entry = thresholds.thresholds[name]
        lines.extend(["", "[[threshold]]"])
        for field, value in entry.model_dump(mode="json").items():
            if value is not None:
                lines.append(f"{field} = {_toml_value(value)}")
    return "\n".join(lines) + "\n"

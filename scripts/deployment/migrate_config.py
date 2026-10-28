"""CLI: upgrade a 1.x or 2.0 `local_config.toml` to the v2 config schema (ADDENDUM_4.md).

Two steps, each applied only when the file needs it:

* **1.x -> 2.0** (feature schema 2.0.0, docs/DEPLOYMENT.md §3.2), when either
  pinned schema version is still 1.x: both versions become "2.0.0",
  `flow.active_timeout_seconds` becomes 120, `threat.behavior_weight` 80, the
  pre-2026-10-15 `known_attack_weight = 50` / `anomaly_weight = 25` pair
  becomes 60 / 15, and a complete `[threat.behavior_pattern_points]` table is
  added if missing. Previously trained model artifacts stop loading after
  this step, by design; retrain per docs/ML_PIPELINE.md.
* **2.0 -> v2**: appends whichever of `[pipeline]`, `[guards]`, `[antispoof]`,
  `[policy]` and `[lab]` is absent, with the shipped defaults and their
  comments. `antispoof.lease_file` is derived from `network.lan_interface`.
  A section that is already present is never touched; its missing keys take
  their model defaults.

The file is edited as text, line by line, never re-serialised, so every
comment and every hand-tuned value outside the keys above survives. The
result is validated as a real `PirewallConfig` before anything is written.

Usage:

    uv run python -m scripts.deployment.migrate_config --check   # exit 1 if migration is needed
    uv run python -m scripts.deployment.migrate_config --write   # back up, then migrate in place
    ... --config PATH                                            # default config/local_config.toml

Exit codes: 0 up to date (or migrated), 1 migration needed (`--check`),
2 the file cannot be read, parsed or validated.

Like `configure.py`, this writes one config file and nothing else (spec §21).
"""

import argparse
import os
import re
import stat
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from pirewall.config.models import PirewallConfig

DEFAULT_CONFIG_PATH = Path("config/local_config.toml")

EXIT_OK = 0
EXIT_MIGRATION_NEEDED = 1
EXIT_ERROR = 2

FEATURE_SCHEMA_V2_0 = "2.0.0"
V1_ACTIVE_TIMEOUT_SECONDS = 120
V1_BEHAVIOR_WEIGHT = "80.0"
# The weights `configure.py` wrote before 2026-10-15 (docs/DEPLOYMENT.md §3.2).
_OLD_WEIGHTS = (50.0, 25.0)
_NEW_WEIGHTS = ("60.0", "15.0")

_PATTERN_POINTS_BLOCK = """\
# Points per detected behavior pattern, summed and capped at behavior_weight.
# Added by scripts/deployment/migrate_config.py (feature schema 2.0.0).
[threat.behavior_pattern_points]
scanning = 55.0
repeated_failures = 45.0
slow_rate_dos = 45.0
flood = 80.0
burst = 10.0
high_frequency = 10.0
repeated_connections = 5.0
temporal_pattern = 10.0
destination_diversity = 5.0
persistence = 0.0
"""

V2_SECTION_ORDER = ("pipeline", "guards", "antispoof", "policy", "lab")


def v2_section_text(section: str, lan_interface: str) -> str:
    """The text appended for one missing v2 section: shipped defaults plus their comments."""
    blocks = {
        "pipeline": """\
[pipeline]
# ADDENDUM_4.md D4 — "v1" until the v2 policy engine ships; v1 stays the baseline.
engine = "v1"
""",
        "guards": """\
[guards]
# ADDENDUM_4.md D1/D2 — static kernel guards (`table inet pirewall_static`).
# Reviewed static policy, not adaptive rules. "enforce" on raw means enforce
# IF bindings were seeded at startup; otherwise raw is forced to observe.
raw_mode = "enforce"
input_mode = "enforce"
forward_mode = "observe"
# rate and burst are one threshold, fitted together. packets/second, except
# dhcp_per_minute. Template starting values, to be replaced by calibration.
dhcp_per_minute = { rate = 10, burst = 5 }
unbound = { rate = 50, burst = 100 }
syn = { rate = 200, burst = 400 }
icmp = { rate = 50, burst = 100 }
udp_local = { rate = 500, burst = 1000 }
local_pps = { rate = 3000, burst = 6000 }
dns = { rate = 100, burst = 300 }
closed_port = { rate = 20, burst = 40 }
newconn = { rate = 100, burst = 200 }
newconn_dst = { rate = 50, burst = 100 }
udp_fwd = { rate = 20000, burst = 40000 }
global_unbound = { rate = 500, burst = 1000 }
global_syn = { rate = 2000, burst = 4000 }
global_icmp = { rate = 500, burst = 1000 }
global_udp_local = { rate = 3000, burst = 6000 }
global_newconn = { rate = 1000, burst = 2000 }
portal_concurrency = 20
ratelimit = { rate = 20, burst = 40 }
binding_set_size = 1024
meter_set_size = 256
pair_meter_set_size = 4096
offender_set_size = 4096
adaptive_set_size = 4096
""",
        "antispoof": f"""\
[antispoof]
# ADDENDUM_4.md D3 — IP<->MAC bindings: the NetworkManager dnsmasq lease file
# for network.lan_interface, plus [[antispoof.static]] entries.
lease_file = "/var/lib/NetworkManager/dnsmasq-{lan_interface}.leases"
grace_seconds = 60
poll_seconds = 2.0
static = []
""",
        "policy": """\
[policy]
# ADDENDUM_4.md D4 — v2 policy table; read only when [pipeline] engine = "v2".
rate_limit_ttl_seconds = 300
block_ttl_seconds = 300
escalation_ttl_multiplier = 2
max_ttl_seconds = 3600
sustained_polls = 2
""",
        "lab": """\
[lab]
# ADDENDUM_4.md D7 — provenance tag: "pi-live", "pi-scripted", "sandbox" or
# "mock". Never defaults to a pi-* tag; pirewall-start sets it per --data-mode.
env_tag = "sandbox"
victim_netns = "labvictim"
victim_host_interface = "lab0"
victim_network = "10.250.0.0/30"
""",
    }
    return blocks[section]


class MigrationError(Exception):
    """The file cannot be migrated safely: unreadable, not TOML, or not a valid config afterwards."""


@dataclass
class MigrationResult:
    """The migrated text and a human-readable line per change (empty when already up to date)."""

    text: str
    changes: list[str] = field(default_factory=list[str])

    @property
    def needed(self) -> bool:
        """Whether the input differed from the v2 schema."""
        return bool(self.changes)


# --------------------------------------------------------------- text surgery

_HEADER = re.compile(r"^\s*\[\[?\s*([^\[\]]+?)\s*\]\]?\s*(#.*)?$")


def _section_bounds(lines: list[str], section: str) -> tuple[int, int] | None:
    """(header index, end index) of `[section]`, end exclusive at the next header; None if absent."""
    start: int | None = None
    for index, line in enumerate(lines):
        match = _HEADER.match(line)
        if match is None:
            continue
        if start is not None:
            return start, index
        is_array_table = line.lstrip().startswith("[[")
        if not is_array_table and match.group(1) == section:
            start = index
    return None if start is None else (start, len(lines))


def _insertion_point(lines: list[str], start: int, end: int) -> int:
    """Just after the last non-blank line of a section, so a new key stays with its section."""
    index = end
    while index > start + 1 and lines[index - 1].strip() == "":
        index -= 1
    return index


def _set_key(lines: list[str], section: str, key: str, value: str) -> str | None:
    """Set `key = value` in `[section]`, keeping a trailing comment; return the old value text or None."""
    bounds = _section_bounds(lines, section)
    if bounds is None:
        raise MigrationError(f"[{section}] is missing; the file is not a complete pirewall config")
    start, end = bounds
    pattern = re.compile(rf'^(\s*{re.escape(key)}\s*=\s*)("[^"]*"|[^\s#]+)(\s*(#.*)?)$')
    for index in range(start + 1, end):
        match = pattern.match(lines[index].rstrip("\r\n"))
        if match is not None:
            old = match.group(2)
            if old != value:
                lines[index] = f"{match.group(1)}{value}{match.group(3)}\n"
            return old
    lines.insert(_insertion_point(lines, start, end), f"{key} = {value}\n")
    return None


def _ensure_trailing_newline(lines: list[str]) -> None:
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"


def _append_block(lines: list[str], block: str) -> None:
    _ensure_trailing_newline(lines)
    if lines and lines[-1].strip() != "":
        lines.append("\n")
    lines.extend(line + "\n" for line in block.rstrip("\n").split("\n"))


def _insert_block_after_section(lines: list[str], section: str, block: str) -> None:
    bounds = _section_bounds(lines, section)
    if bounds is None:
        _append_block(lines, block)
        return
    start, end = bounds
    at = _insertion_point(lines, start, end)
    new_lines = ["\n", *(line + "\n" for line in block.rstrip("\n").split("\n"))]
    lines[at:at] = new_lines


# --------------------------------------------------------------- migration


def _parse(text: str) -> dict[str, Any]:  # Any: raw TOML document before validation
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise MigrationError(f"not valid TOML: {exc}") from exc


def _section(document: dict[str, Any], name: str) -> dict[str, Any]:  # Any: raw TOML table
    value = document.get(name)
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}  # Any: raw TOML table


def _is_v1x(document: dict[str, Any]) -> bool:  # Any: raw TOML document
    versions = (
        _section(document, "features").get("schema_version"),
        _section(document, "ml").get("feature_schema_version"),
    )
    return any(isinstance(version, str) and version.startswith("1.") for version in versions)


def _migrate_1x_to_2_0(
    lines: list[str],
    document: dict[str, Any],  # Any: raw TOML document
    changes: list[str],
) -> None:
    for section, key in (("features", "schema_version"), ("ml", "feature_schema_version")):
        old = _set_key(lines, section, key, f'"{FEATURE_SCHEMA_V2_0}"')
        if old != f'"{FEATURE_SCHEMA_V2_0}"':
            changes.append(f'[{section}] {key}: {old or "default"} -> "{FEATURE_SCHEMA_V2_0}"')
    old = _set_key(lines, "flow", "active_timeout_seconds", str(V1_ACTIVE_TIMEOUT_SECONDS))
    if old != str(V1_ACTIVE_TIMEOUT_SECONDS):
        changes.append(f"[flow] active_timeout_seconds: {old or 'default'} -> {V1_ACTIVE_TIMEOUT_SECONDS}")
    old = _set_key(lines, "threat", "behavior_weight", V1_BEHAVIOR_WEIGHT)
    if old is None or float(old) != float(V1_BEHAVIOR_WEIGHT):
        changes.append(f"[threat] behavior_weight: {old or 'default'} -> {V1_BEHAVIOR_WEIGHT}")
    threat = _section(document, "threat")
    if (threat.get("known_attack_weight"), threat.get("anomaly_weight")) == _OLD_WEIGHTS:
        _set_key(lines, "threat", "known_attack_weight", _NEW_WEIGHTS[0])
        _set_key(lines, "threat", "anomaly_weight", _NEW_WEIGHTS[1])
        changes.append("[threat] known_attack_weight/anomaly_weight: 50/25 -> 60/15")
    if "behavior_pattern_points" not in threat:
        _insert_block_after_section(lines, "threat", _PATTERN_POINTS_BLOCK)
        changes.append("[threat.behavior_pattern_points]: added (feature schema 2.0.0 defaults)")


def _migrate_2_0_to_v2(
    lines: list[str],
    document: dict[str, Any],  # Any: raw TOML document
    changes: list[str],
) -> None:
    lan_interface = _section(document, "network").get("lan_interface")
    if not isinstance(lan_interface, str) or not lan_interface:
        raise MigrationError("[network] lan_interface is missing; cannot derive antispoof.lease_file")
    for section in V2_SECTION_ORDER:
        if section not in document:
            _append_block(lines, v2_section_text(section, lan_interface))
            changes.append(f"[{section}]: added with v2 defaults")


def migrate_text(text: str) -> MigrationResult:
    """Return `text` upgraded to the v2 schema, validated, plus what changed.

    Raises `MigrationError` when the input is not TOML, is not a complete
    pirewall config, or would not validate after migration. Pure: no I/O.
    """
    document = _parse(text)
    lines = text.splitlines(keepends=True)
    changes: list[str] = []
    if _is_v1x(document):
        _migrate_1x_to_2_0(lines, document, changes)
    _migrate_2_0_to_v2(lines, document, changes)
    migrated = "".join(lines)
    try:
        PirewallConfig.model_validate(_parse(migrated))
    except ValidationError as exc:
        raise MigrationError(f"the migrated config does not validate:\n{exc}") from exc
    return MigrationResult(text=migrated, changes=changes)


def backup_path(path: Path, now: datetime) -> Path:
    """Where `--write` copies the original before replacing it."""
    return path.with_name(f"{path.name}.{now.strftime('%Y%m%dT%H%M%SZ')}.bak")


def _write_with_mode(target: Path, data: bytes, mode: int) -> None:
    # Created 0600 and only then widened to the original's mode: the file
    # holds the admin password hash, so it is never briefly world-readable.
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.chmod(target, mode)


def write_migrated(path: Path, result: MigrationResult, now: datetime) -> Path:
    """Back up `path`, then atomically replace it with `result.text`. Returns the backup path.

    The backup and the new file keep the original's permission bits.
    """
    mode = stat.S_IMODE(path.stat().st_mode)
    backup = backup_path(path, now)
    _write_with_mode(backup, path.read_bytes(), mode)
    staging = path.with_name(f"{path.name}.new")
    _write_with_mode(staging, result.text.encode("utf-8"), mode)
    staging.replace(path)
    return backup


# --------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    """The command-line interface; `--check` and `--write` are mutually exclusive and one is required."""
    parser = argparse.ArgumentParser(
        prog="python -m scripts.deployment.migrate_config",
        description="Upgrade a 1.x or 2.0 local_config.toml to the v2 config schema.",
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="config file to migrate")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="exit 1 if migration is needed; write nothing")
    mode.add_argument("--write", action="store_true", help="back up the file, then migrate it in place")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; returns the process exit code."""
    args = build_parser().parse_args(argv)
    path: Path = args.config
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"migrate_config: cannot read {path}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        result = migrate_text(text)
    except MigrationError as exc:
        print(f"migrate_config: {path}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not result.needed:
        print(f"{path}: already on the v2 config schema")
        return EXIT_OK
    print(f"{path}: migration {'needed' if args.check else 'applied'}:")
    for change in result.changes:
        print(f"  - {change}")
    if args.check:
        print("Run with --write to apply (a timestamped backup is kept).")
        return EXIT_MIGRATION_NEEDED
    try:
        backup = write_migrated(path, result, datetime.now(UTC))
    except OSError as exc:
        print(f"migrate_config: cannot write {path}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Backup of the original: {backup}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

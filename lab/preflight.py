"""Is the Pi ready for a campaign? Every check, then the manifest fields a run will record (PLAN_FINAL §5).

    sudo uv run python lab/preflight.py [--config config/local_config.toml] [--data-mode live] \\
        [--host kali@10.0.0.50 ...] [--max-offset-ms 50] [--out lab/runs] [--min-free-gb 2]

Checks, each printed `ok` / `FAIL` with its reason:

1. `scripts/deployment/pirewall-start --check --data-mode <mode>` exits 0;
2. the lab victim netns (`[lab] victim_netns`) is up;
3. the clock offset (`chronyc tracking`) of this Pi and of every `--host`
   (over SSH) is within `--max-offset-ms`;
4. the D1 thresholds file exists and loads (frozen or not is printed: an
   eval campaign refuses unfrozen thresholds by itself);
5. the adaptive sets are empty: no live RATE_LIMIT/BLOCK rule, no offender
   (core's view over the RPC socket, read-only, `lab/poll_state.py`);
6. at least `--min-free-gb` free where the run directories go.

Then it prints the provenance every run manifest will carry (git state,
config/thresholds/policy/model hashes, engine, modes, env tag and ruleset
hash from `pirewall-start`'s manifest, tool versions, clock offsets).
Exit 0 when every check passes, 2 otherwise. It changes nothing.
"""

import argparse
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # `python lab/preflight.py`

from lab.common import REPO_ROOT, LabError, project_provenance
from lab.manifest import git_state
from lab.poll_state import CoreReader, ReadOnlyCore, sets_empty
from lab.run_campaign import read_start_manifest

PIREWALL_START: Final = REPO_ROOT / "scripts" / "deployment" / "pirewall-start"
_OFFSET: Final = re.compile(r"^System time\s*:\s*([0-9.]+) seconds (slow|fast)", re.MULTILINE)


@dataclass(frozen=True, slots=True)
class Outcome:
    """A command's exit code and output."""

    returncode: int
    output: str


Runner = Callable[[Sequence[str]], Outcome]


def run_command(argv: Sequence[str]) -> Outcome:
    """Run `argv`, capturing output; a missing program is exit 127."""
    try:
        done = subprocess.run(list(argv), capture_output=True, text=True, timeout=120, check=False)
    except FileNotFoundError:
        return Outcome(127, f"{argv[0]}: not found")
    except subprocess.TimeoutExpired:
        return Outcome(124, f"{argv[0]}: timed out")
    return Outcome(done.returncode, done.stdout + done.stderr)


def chrony_offset_seconds(output: str) -> float | None:
    """The signed offset from `chronyc tracking` output (fast is positive), or None."""
    match = _OFFSET.search(output)
    if match is None:
        return None
    value = float(match.group(1))
    return value if match.group(2) == "fast" else -value


@dataclass(slots=True)
class Check:
    """One line of the report."""

    name: str
    ok: bool
    detail: str


@dataclass(slots=True)
class Preflight:
    """Every check, with its side effects injected."""

    config: Path
    data_mode: str
    hosts: Sequence[str]
    max_offset_ms: float
    out: Path
    min_free_gb: float
    run: Runner = run_command
    core: Callable[[], CoreReader] | None = None
    free_bytes: Callable[[Path], int] = lambda path: shutil.disk_usage(path).free
    checks: list[Check] = field(default_factory=list[Check])
    offsets: dict[str, float] = field(default_factory=dict[str, float])

    def add(self, name: str, ok: bool, detail: str) -> None:
        """Record and print one check."""
        self.checks.append(Check(name, ok, detail))
        print(f"  {'ok  ' if ok else 'FAIL'} {name}: {detail}")

    def pirewall_start(self) -> None:
        """`pirewall-start --check` passes."""
        result = self.run(
            [
                "bash",
                str(PIREWALL_START),
                "--check",
                "--data-mode",
                self.data_mode,
                "--config",
                str(self.config),
            ]
        )
        tail = result.output.strip().splitlines()[-1:] or [""]
        self.add("pirewall-start --check", result.returncode == 0, f"exit {result.returncode}: {tail[0]}")

    def victim(self, netns: str) -> None:
        """The lab victim netns exists."""
        result = self.run(["ip", "netns", "list"])
        names = {line.split()[0] for line in result.output.splitlines() if line.strip()}
        self.add(
            "lab victim",
            netns in names,
            f"netns {netns} is up"
            if netns in names
            else f"netns {netns} is not up (sudo scripts/deployment/pirewall-start --lab-victim up)",
        )

    def clocks(self) -> None:
        """Every host's chrony offset within bound."""
        for host in ("local", *self.hosts):
            argv = (
                ["chronyc", "tracking"]
                if host == "local"
                else ["ssh", "-o", "BatchMode=yes", host, "chronyc", "tracking"]
            )
            result = self.run(argv)
            offset = chrony_offset_seconds(result.output) if result.returncode == 0 else None
            if offset is None:
                self.add(f"clock {host}", False, f"no chrony offset (exit {result.returncode})")
                continue
            self.offsets[host] = offset
            within = abs(offset) * 1000.0 <= self.max_offset_ms
            self.add(
                f"clock {host}", within, f"offset {offset * 1000.0:+.2f} ms (bound {self.max_offset_ms:g} ms)"
            )

    def thresholds(self, path: str | None, frozen: bool | None, sha: str | None) -> None:
        """The thresholds file is present and loads."""
        if path is None or sha is None:
            self.add("D1 thresholds", False, f"{path}: missing")
        elif frozen is None:
            self.add("D1 thresholds", False, f"{path}: does not load")
        else:
            self.add("D1 thresholds", True, f"{path} (frozen = {str(frozen).lower()}, sha256 {sha[:12]})")

    def sets(self) -> None:
        """Adaptive sets empty, per core."""
        if self.core is None:
            self.add("adaptive sets empty", False, "no core reader")
            return
        try:
            empty = sets_empty(self.core())
        except Exception as exc:  # any RPC failure is a failed check, reported, not a crash
            self.add("adaptive sets empty", False, f"cannot read core: {exc}")
            return
        self.add(
            "adaptive sets empty",
            empty,
            "no live RATE_LIMIT/BLOCK rule, no offender"
            if empty
            else "rules or offenders are live; wait for their TTLs (never kill-switch)",
        )

    def disk(self) -> None:
        """Enough free space for run directories."""
        target = self.out if self.out.exists() else self.out.parent
        free = self.free_bytes(target) / 1e9
        self.add(
            "disk", free >= self.min_free_gb, f"{free:.1f} GB free under {target} (need {self.min_free_gb:g})"
        )

    @property
    def ok(self) -> bool:
        """True when every check passed."""
        return all(check.ok for check in self.checks)


def main(argv: Sequence[str] | None = None) -> int:
    """0 when ready, 2 otherwise."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--config", type=Path, default=REPO_ROOT / "config" / "local_config.toml")
    parser.add_argument("--data-mode", choices=("live", "scripted"), default="live")
    parser.add_argument("--host", action="append", default=[], help="user@host to check the clock of (SSH)")
    parser.add_argument("--max-offset-ms", type=float, default=50.0)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "lab" / "runs")
    parser.add_argument("--min-free-gb", type=float, default=2.0)
    parser.add_argument("--socket", default="/run/pirewall/core.sock")
    parser.add_argument("--start-manifest", type=Path, default=Path("/var/lib/pirewall/manifest.json"))
    args = parser.parse_args(argv)
    try:
        from pirewall.config.loader import load_config

        config = load_config(args.config)
        provenance = project_provenance(args.config)
    except (LabError, OSError, ValueError) as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 2
    check = Preflight(
        args.config,
        args.data_mode,
        args.host,
        args.max_offset_ms,
        args.out,
        args.min_free_gb,
        core=lambda: ReadOnlyCore(args.socket),
    )
    print("checks:")
    check.pirewall_start()
    check.victim(config.lab.victim_netns)
    check.clocks()
    hashes = provenance.hashes
    check.thresholds(
        provenance.thresholds_path if hashes.thresholds else None, hashes.thresholds_frozen, hashes.thresholds
    )
    check.sets()
    check.disk()

    try:
        start_doc = read_start_manifest(args.start_manifest)
    except LabError:
        start_doc = {}
    sha, dirty = git_state(REPO_ROOT)
    tcpdump = run_command(["tcpdump", "--version"]).output.splitlines()[:1]
    print("\nevery run manifest will record:")
    for key, value in (
        ("git", f"{sha} (dirty: {dirty})"),
        ("env_tag", start_doc.get("env", "UNKNOWN: start pirewall first (pirewall-start writes the tag)")),
        ("ruleset_sha256", start_doc.get("ruleset_sha256")),
        ("config_sha256", provenance.config_sha256),
        ("thresholds", f"{hashes.thresholds} (frozen: {hashes.thresholds_frozen})"),
        ("policy_table", hashes.policy_table),
        ("models", dict(hashes.models) or "none"),
        ("pipeline_engine", provenance.pipeline_engine),
        ("enforcement_mode", provenance.enforcement_mode),
        ("guard_modes", dict(provenance.guard_modes)),
        ("tool_versions", {"tcpdump": tcpdump[0] if tcpdump else "missing"}),
        ("clock_offsets_s", check.offsets),
    ):
        print(f"  {key}: {value}")
    print(
        f"\npreflight {'passed' if check.ok else 'FAILED'}: "
        f"{sum(c.ok for c in check.checks)}/{len(check.checks)} checks"
    )
    return 0 if check.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())

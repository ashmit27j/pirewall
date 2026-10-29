"""Re-check sealed lab directories: hashes, env tags, and the frozen-thresholds rule (G7).

    uv run python lab/verify_manifest.py DIR [DIR ...] [--thresholds config/d1_thresholds.toml]

For every directory holding a `manifest.json`, at any depth under each
`DIR`:

* every file the manifest lists exists and has the recorded SHA-256;
* no file is present that the manifest does not list (a sealed directory is
  append-only: anything added later belongs in a new, separately sealed
  sub-directory);
* the env tag is one of the four D7 tags, and a sub-directory's tag equals
  its parent's (no mixing inside one run);
* an `eval`-phase manifest records `hashes.thresholds_frozen = true`, and,
  when `--thresholds` is given, that file is frozen and hashes to what the
  manifest recorded (critique_ml.md: thresholds are frozen before campaign
  #2 and never change after).

Exit 0 when everything verifies, 1 with one line per problem otherwise.
"""

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # `python lab/verify_manifest.py`

from lab.manifest import MANIFEST_NAME, Json, ManifestError, hash_tree, read_manifest, sha256_file

__all__ = ["Report", "frozen_thresholds_problem", "verify_tree"]


@dataclass(slots=True)
class Report:
    """What verification found."""

    verified: list[Path] = field(default_factory=list[Path])
    problems: list[str] = field(default_factory=list[str])

    @property
    def ok(self) -> bool:
        """True when nothing is wrong."""
        return not self.problems


def frozen_thresholds_problem(path: Path, recorded_sha256: str | None = None) -> str | None:
    """None when `path` is a valid, frozen D1 thresholds file (matching `recorded_sha256` if given)."""
    from pirewall.core.exceptions import ConfigurationError
    from pirewall.detection_v2.thresholds import load_thresholds

    try:
        thresholds = load_thresholds(path)
    except ConfigurationError as exc:
        return str(exc)
    if not thresholds.frozen:
        return (
            f"{path} has frozen = false: freeze the thresholds before an eval campaign "
            "(fit_d1_thresholds.py --freeze, RUNBOOK_PI.md H35)"
        )
    if recorded_sha256 is not None and sha256_file(path) != recorded_sha256:
        return f"{path} does not hash to the thresholds recorded in the manifest"
    return None


def _check_one(directory: Path, document: dict[str, Json], report: Report, thresholds: Path | None) -> None:
    files = document["files"]
    assert isinstance(files, dict)
    try:
        actual = hash_tree(directory)
    except ManifestError as exc:
        report.problems.append(str(exc))
        return
    for name, recorded in sorted(files.items()):
        if name not in actual:
            report.problems.append(f"{directory}: {name} is missing")
        elif actual[name] != recorded:
            report.problems.append(f"{directory}: {name} has changed (sha256 mismatch)")
    for name in sorted(set(actual) - set(files)):
        report.problems.append(f"{directory}: {name} is not in the manifest (added after sealing?)")
    if document.get("phase") == "eval":
        hashes = document.get("hashes")
        recorded = hashes.get("thresholds") if isinstance(hashes, dict) else None
        frozen = hashes.get("thresholds_frozen") if isinstance(hashes, dict) else None
        if frozen is not True:
            report.problems.append(f"{directory}: eval run without frozen D1 thresholds")
        if thresholds is not None:
            problem = frozen_thresholds_problem(thresholds, recorded if isinstance(recorded, str) else None)
            if problem is not None:
                report.problems.append(f"{directory}: {problem}")


def verify_tree(
    root: Path, thresholds: Path | None = None, report: Report | None = None, parent_tag: str | None = None
) -> Report:
    """Verify every sealed directory at or under `root`."""
    report = report if report is not None else Report()
    if not root.is_dir():
        report.problems.append(f"{root}: not a directory")
        return report
    tag = parent_tag
    if (root / MANIFEST_NAME).is_file():
        try:
            document = read_manifest(root)
        except ManifestError as exc:
            report.problems.append(str(exc))
            return report
        tag = str(document["env_tag"])
        if parent_tag is not None and tag != parent_tag:
            report.problems.append(f"{root}: env tag {tag} inside a {parent_tag} directory (D7: never mixed)")
        _check_one(root, document, report, thresholds)
        report.verified.append(root)
    for child in sorted(path for path in root.iterdir() if path.is_dir() and not path.is_symlink()):
        verify_tree(child, thresholds, report, tag)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    """Exit 0 when every sealed directory verifies, 1 otherwise."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("directories", nargs="+", type=Path)
    parser.add_argument("--thresholds", type=Path, help="also check this thresholds file for eval runs")
    args = parser.parse_args(argv)
    report = Report()
    for directory in args.directories:
        verify_tree(directory, args.thresholds, report)
    if not report.verified and report.ok:
        report.problems.append("no manifest.json found under the given directories")
    for problem in report.problems:
        print(f"FAIL {problem}")
    print(f"{len(report.verified)} sealed directories checked, {len(report.problems)} problem(s)")
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

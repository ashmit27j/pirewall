"""Seal a directory the harness did not write itself: a benign capture session (PLAN_v3 §4, G7).

    sudo uv run python lab/seal.py DIR --kind capture --env-tag pi-live \\
        [--lab-macs /var/lib/pirewall-lab/lab_macs.txt] [--note key=value ...]

Writes `DIR/manifest.json` (`lab/manifest.py`): every file's SHA-256, the
env tag, git state, and, for `--kind capture`, `extra.lab_macs`: the MACs
of every attacker and lab device, read from the lab-MAC list (one
`<mac> <anything>` per line, `#` comments; RUNBOOK_PI.md step 6). Later
tools drop those MACs (`lab/benign_fp.py --capture-manifest DIR`); they
are never filtered out at capture time, so the evaluator can see them to
exclude them.

`lab/capture/benign_capture.sh stop` calls this for each session. A
`pi-*` tag is refused off a Pi (`lab.common.require_env_tag`). A sealed
directory is never re-sealed: files added later belong in a new session.
"""

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # `python lab/seal.py`

from lab.common import REPO_ROOT, LabError, require_env_tag
from lab.manifest import Json, Kind, Manifest, ManifestError, git_state, write_manifest

TOOL: Final = "lab/seal.py"
_MAC: Final = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")
_SEALABLE: Final[tuple[Kind, ...]] = ("capture", "dataset")


def read_lab_macs(path: Path) -> list[str]:
    """The MACs in a lab-MAC list, normalised to lowercase `aa:bb:...`. Raises `LabError` on a bad line."""
    macs: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LabError(f"{path}: {exc}") from exc
    for number, line in enumerate(lines, start=1):
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        mac = text.split()[0].lower()
        if not _MAC.match(mac):
            raise LabError(f"{path}:{number}: {mac!r} is not a MAC address")
        normalised = mac.replace("-", ":")
        if normalised not in macs:
            macs.append(normalised)
    return macs


def _notes(items: Sequence[str]) -> dict[str, Json]:
    notes: dict[str, Json] = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise LabError(f"--note {item!r}: expected key=value")
        notes[key] = value
    return notes


def seal(
    directory: Path,
    kind: Kind,
    env_tag: str,
    lab_macs: Path | None,
    notes: dict[str, Json],
    on_pi: bool | None = None,
) -> dict[str, Json]:
    """Seal `directory`. Returns the manifest document. Raises `LabError`."""
    require_env_tag(env_tag, on_pi=on_pi)
    if not directory.is_dir():
        raise LabError(f"{directory}: not a directory")
    extra: dict[str, Json] = dict(notes)
    if kind == "capture":
        extra["lab_macs"] = list[Json](read_lab_macs(lab_macs)) if lab_macs is not None else []
        extra["lab_macs_source"] = str(lab_macs) if lab_macs is not None else None
    sha, dirty = git_state(REPO_ROOT)
    try:
        return write_manifest(
            directory,
            Manifest(kind=kind, env_tag=env_tag, tool=TOOL, git_sha=sha, git_dirty=dirty, extra=extra),
        )
    except ManifestError as exc:
        raise LabError(str(exc)) from exc


def main(argv: Sequence[str] | None = None) -> int:
    """Exit 0 when sealed, 2 on a refusal."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("directory", type=Path)
    parser.add_argument("--kind", choices=_SEALABLE, default="capture")
    parser.add_argument("--env-tag", required=True, help="pi-live, pi-scripted, sandbox or mock (no default)")
    parser.add_argument("--lab-macs", type=Path, help="lab-MAC list (capture only)")
    parser.add_argument("--note", action="append", default=[], help="extra key=value to record")
    args = parser.parse_args(argv)
    kind: Kind = "capture" if args.kind == "capture" else "dataset"
    try:
        document = seal(args.directory, kind, args.env_tag, args.lab_macs, _notes(args.note))
    except LabError as exc:
        print(f"seal: {exc}", file=sys.stderr)
        return 2
    files = document["files"]
    count = len(files) if isinstance(files, dict) else 0
    print(f"sealed {args.directory}: {count} files, env tag {args.env_tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Phase-20 docs reconciliation: the documentation must describe the tree that exists.

Two checks the phase-20 prompt names:

* every repository path named in `docs/HANDOFF.md`'s file map (§5.3) exists, so the
  orientation file cannot quietly rot as modules move;
* every `pirewall-start` flag documented in `docs/SETUP.md` is a flag the script
  actually accepts, so a reader cannot copy a command that refuses.

Both read the real tree and the real script — nothing here is a fixture.
"""

import re
from pathlib import Path
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
HANDOFF: Final = REPO_ROOT / "docs" / "HANDOFF.md"
SETUP: Final = REPO_ROOT / "docs" / "SETUP.md"
PIREWALL_START: Final = REPO_ROOT / "scripts" / "deployment" / "pirewall-start"

#: Top-level directories a backticked token must start with to be read as a repo path.
#: Anything else in the file map is prose, a bare file name relative to a heading, or an
#: nft/systemd object name, and is out of scope for this check.
TRACKED_ROOTS: Final = (
    "benchmarks/",
    "config/",
    "deploy/",
    "docs/",
    "lab/",
    "native/",
    "pirewall/",
    "prompts/",
    "scripts/",
    "tests/",
    "typings/",
)

#: `a/{b,c}.py` in the file map means `a/b.py` and `a/c.py`.
_BRACE = re.compile(r"^(?P<prefix>[^{}]*)\{(?P<options>[^{}]+)\}(?P<suffix>[^{}]*)$")


def _expand(token: str) -> list[str]:
    """Expand one brace group in a file-map token into the paths it names."""
    match = _BRACE.match(token)
    if match is None:
        return [token]
    prefix, suffix = match.group("prefix"), match.group("suffix")
    return [f"{prefix}{option.strip()}{suffix}" for option in match.group("options").split(",")]


def _repo_paths(markdown: str) -> list[str]:
    """Every backticked token in `markdown` that names a path under a tracked root.

    Tokens carrying an ellipsis (`prompts/phase-01…09`) are a human range, not a path,
    and are skipped. A token with a `*` is a glob and is checked as one.
    """
    found: list[str] = []
    for token in re.findall(r"`([^`\n]+)`", markdown):
        candidate = token.strip()
        if not candidate.startswith(TRACKED_ROOTS):
            continue
        if "…" in candidate or "..." in candidate:
            continue
        for expanded in _expand(candidate):
            # `lab/**` and `docs/v2/v2/` name a tree, not a file.
            cleaned = expanded.removesuffix("**").rstrip("/")
            if cleaned and cleaned not in found:
                found.append(cleaned)
    return found


#: Paths the file map may name although the tree never contains them: they are
#: written at deploy time and deliberately gitignored, so requiring them would
#: fail on every clean checkout while saying nothing about documentation drift.
#: Each is named in `.gitignore`, which is what the test checks instead.
RUNTIME_GENERATED: Final = frozenset({"config/local_config.toml"})


def _names_something(path: str) -> bool:
    """True when `path` exists, or — for a glob — matches at least one tracked file.

    A deploy-time path from `RUNTIME_GENERATED` counts as named when
    `.gitignore` still excludes it, so the documentation and the ignore rules
    cannot drift apart unnoticed.
    """
    if path in RUNTIME_GENERATED:
        gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        return any(line.strip().strip("/") == path for line in gitignore.splitlines())
    if "*" in path:
        return any(REPO_ROOT.glob(path))
    return (REPO_ROOT / path).exists()


def test_handoff_file_map_paths_exist() -> None:
    """Every repository path `docs/HANDOFF.md` names must exist in the tree."""
    paths = _repo_paths(HANDOFF.read_text(encoding="utf-8"))
    assert paths, "no repository paths found in HANDOFF.md — the parser or the file map changed"
    missing = sorted(path for path in paths if not _names_something(path))
    assert not missing, (
        "docs/HANDOFF.md names paths that do not exist: " + ", ".join(missing)
    )


def _script_flags() -> set[str]:
    """Every long option `scripts/deployment/pirewall-start` accepts, from its case arms."""
    source = PIREWALL_START.read_text(encoding="utf-8")
    flags: set[str] = set()
    # The option parser is a `case` whose arms look like `-h|--help)` or `--data-mode)`.
    for arm in re.findall(r"^\s*((?:-{1,2}[A-Za-z0-9|-]+)+)\)", source, flags=re.MULTILINE):
        for option in arm.split("|"):
            if option.startswith("--"):
                flags.add(option)
    return flags


def _documented_flags(markdown: str) -> set[str]:
    """Every `--flag` that `docs/SETUP.md` shows as an argument *to* `pirewall-start`.

    Only the text after the command name counts: prose that names another tool's flag
    before mentioning `pirewall-start` ("`configure --set-admin-pc`, then re-run
    `pirewall-start`") documents that other tool, not this one.
    """
    documented: set[str] = set()
    for line in markdown.splitlines():
        _, separator, arguments = line.rpartition("pirewall-start")
        if not separator:
            continue
        for flag in re.findall(r"(--[a-z0-9][a-z0-9-]*)", arguments):
            documented.add(flag)
    return documented


def test_setup_documents_only_real_pirewall_start_flags() -> None:
    """Every `pirewall-start` flag shown in `docs/SETUP.md` is one the script accepts."""
    accepted = _script_flags()
    assert "--check" in accepted, "the pirewall-start option parser no longer parses as expected"
    documented = _documented_flags(SETUP.read_text(encoding="utf-8"))
    assert documented, "no pirewall-start flags found in docs/SETUP.md"
    unknown = sorted(documented - accepted)
    assert not unknown, (
        "docs/SETUP.md documents pirewall-start flags the script does not accept: "
        + ", ".join(unknown)
    )

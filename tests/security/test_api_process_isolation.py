"""Import-graph proof: pirewall-api/web never import capture/firewall.manager/firewall.backend.

ADDENDUM.md A4: `pirewall-api` is a separate OS process from `pirewall-core`
and must reach it only through `pirewall.ipc`'s RPC client — never a direct
import of the packages that actually touch hardware or deploy firewall
rules. This is the concrete mechanism behind spec §45's "a compromised
control panel must not automatically provide unrestricted root access."
"""

import ast
import subprocess
import sys
from pathlib import Path

import pirewall

_FORBIDDEN_PREFIXES = (
    "pirewall.capture",
    "pirewall.firewall.manager",
    "pirewall.firewall.backend",
)


def _forbidden_import(tree: ast.Module) -> str | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for prefix in _FORBIDDEN_PREFIXES:
                    if alias.name == prefix or alias.name.startswith(prefix + "."):
                        return alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for prefix in _FORBIDDEN_PREFIXES:
                if module == prefix or module.startswith(prefix + "."):
                    return module
                # `from pirewall.firewall import manager` / `from pirewall import capture`
                if module in {"pirewall.firewall", "pirewall"}:
                    for alias in node.names:
                        candidate = f"{module}.{alias.name}"
                        if candidate == prefix or candidate.startswith(prefix + "."):
                            return candidate
    return None


def _scan(package_dir: Path, repo_root: Path) -> list[tuple[str, str]]:
    violations: list[tuple[str, str]] = []
    for path in package_dir.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        forbidden = _forbidden_import(tree)
        if forbidden is not None:
            violations.append((path.resolve().relative_to(repo_root).as_posix(), forbidden))
    return violations


def test_api_package_never_imports_capture_or_firewall_internals() -> None:
    package_root = Path(pirewall.__file__).resolve().parent
    repo_root = package_root.parent
    violations = _scan(package_root / "api", repo_root)
    assert violations == [], f"forbidden imports under pirewall/api/: {violations}"


def test_web_package_never_imports_capture_or_firewall_internals() -> None:
    package_root = Path(pirewall.__file__).resolve().parent
    repo_root = package_root.parent
    violations = _scan(package_root / "web", repo_root)
    assert violations == [], f"forbidden imports under pirewall/web/: {violations}"


def test_forbidden_modules_are_not_even_transitively_loaded_in_the_api_process() -> None:
    """The AST checks above only see *direct* imports; this sees what actually gets loaded.

    Regression test for an audit finding: `pirewall/ipc/__init__.py`
    re-exported `CoreRpcDispatcher`, so importing the pirewall-api side
    (`pirewall.ipc.client`) executed that `__init__` and pulled
    `pirewall.firewall.manager` into the API process. Every AST test above
    still passed, because no file under `pirewall/api/` or `pirewall/web/`
    contained a forbidden import *textually* — the leak was transitive.

    ADDENDUM.md A4 requires the separation hold "at the code/dependency
    level, not just by convention", which means the module must not be
    resident in the process at all, however it got there. Runs in a
    subprocess so the parent pytest session's already-imported modules
    (it imports FirewallManager all over the place) can't mask a real leak.
    """
    probe = (
        "import sys\n"
        "import pirewall.api.app\n"
        "import pirewall.web.routes\n"
        f"forbidden = {_FORBIDDEN_PREFIXES!r}\n"
        "leaked = sorted(m for m in sys.modules"
        " if any(m == p or m.startswith(p + '.') for p in forbidden))\n"
        "print(';'.join(leaked))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=True,
        cwd=Path(pirewall.__file__).resolve().parent.parent,
    )
    leaked = [name for name in result.stdout.strip().split(";") if name]
    assert leaked == [], (
        "pirewall-api process transitively loaded forbidden modules "
        f"{leaked} — see ADDENDUM.md A4"
    )

"""Import-graph proof: pirewall-api/web never import capture/firewall.manager/firewall.backend.

ADDENDUM.md A4: `pirewall-api` is a separate OS process from `pirewall-core`
and must reach it only through `pirewall.ipc`'s RPC client — never a direct
import of the packages that actually touch hardware or deploy firewall
rules. This is the concrete mechanism behind spec §45's "a compromised
control panel must not automatically provide unrestricted root access."
"""

import ast
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

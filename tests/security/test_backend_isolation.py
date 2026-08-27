"""Import-graph proof: only `pirewall.firewall.manager` may import the backend package.

CLAUDE.md: "Exactly one authorized code path may deploy to the firewall
backend. Nothing else calls into firewall/backend/." Since Python has no
real module-privacy mechanism, this is enforced by scanning the actual
import graph rather than trusting convention.
"""

import ast
from pathlib import Path

import pirewall

_ALLOWED_IMPORTER = "pirewall/firewall/manager.py"
_BACKEND_PREFIX = "pirewall/firewall/backend/"


def _imports_backend(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.startswith("pirewall.firewall.backend") for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.startswith("pirewall.firewall.backend"):
                return True
            if module == "pirewall.firewall" and any(alias.name == "backend" for alias in node.names):
                return True
    return False


def test_only_manager_imports_the_backend_package() -> None:
    package_root = Path(pirewall.__file__).resolve().parent
    repo_root = package_root.parent
    violations: list[str] = []

    for path in package_root.rglob("*.py"):
        relative = path.resolve().relative_to(repo_root).as_posix()
        if relative == _ALLOWED_IMPORTER or relative.startswith(_BACKEND_PREFIX):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if _imports_backend(tree):
            violations.append(relative)

    assert violations == [], f"unexpected importers of pirewall.firewall.backend: {violations}"


def test_manager_itself_does_import_the_backend_interface_only_via_protocol() -> None:
    """Sanity check the test above isn't vacuous: manager.py imports the Protocol, not a concrete backend."""
    manager_path = Path(pirewall.__file__).resolve().parent / "firewall" / "manager.py"
    tree = ast.parse(manager_path.read_text(encoding="utf-8"), filename=str(manager_path))
    assert not _imports_backend(tree), (
        "manager.py should depend on the FirewallBackend Protocol (pirewall.firewall.interface), "
        "not import a concrete backend module — callers inject the backend instance instead"
    )

"""Import-graph proof: only `pirewall.firewall.manager` may import the backend package.

CLAUDE.md: "Exactly one authorized code path may deploy to the firewall
backend. Nothing else calls into firewall/backend/." Since Python has no
real module-privacy mechanism, this is enforced by scanning the actual
import graph rather than trusting convention.

`pirewall/runtime/core.py` is the one other file permitted to *name* a
concrete backend, because something has to construct the real
`NftablesBackend` and inject it — a composition root cannot itself be
injected. That exemption is deliberately narrow and independently checked:
`test_runtime_core_only_constructs_a_backend_never_calls_one` asserts the
daemon never calls a single `FirewallBackend` method, so the rule the
import ban exists to protect ("only the manager may deploy") still holds
even though the import does.
"""

import ast
from pathlib import Path

import pirewall

# Files allowed to import `pirewall.firewall.backend`. See the module
# docstring for why the composition root is on this list.
_ALLOWED_IMPORTERS = frozenset(
    {
        "pirewall/firewall/manager.py",
        "pirewall/runtime/core.py",
    }
)
_BACKEND_PREFIX = "pirewall/firewall/backend/"

# Every method on the `FirewallBackend` Protocol. Calling any of them from
# outside `FirewallManager` would bypass the validated rule lifecycle.
_BACKEND_METHODS = frozenset({"apply_rule", "remove_rule", "list_active_rule_ids", "health_check"})


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
        if relative in _ALLOWED_IMPORTERS or relative.startswith(_BACKEND_PREFIX):
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


def test_runtime_core_only_constructs_a_backend_never_calls_one() -> None:
    """The composition root's exemption is construction-only (CLAUDE.md).

    `pirewall/runtime/core.py` may name `NftablesBackend` to build one and
    hand it to `FirewallManager`. It must never call a `FirewallBackend`
    method itself — not `apply_rule`/`remove_rule` (that would bypass the
    ten-stage validation chain outright) and not even the read-only
    `health_check` (which is exposed as `FirewallManager.backend_health`
    precisely so the daemon does not need a backend reference at all).
    """
    path = Path(pirewall.__file__).resolve().parent / "runtime" / "core.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    called: list[str] = [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _BACKEND_METHODS
    ]
    assert called == [], (
        f"pirewall/runtime/core.py calls FirewallBackend method(s) {called}; the composition root "
        "may construct a backend but must route every operation through FirewallManager"
    )

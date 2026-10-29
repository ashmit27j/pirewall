"""Import graph (phase 18): nothing under `pirewall/` imports `lab` or `scapy`; only gen_pcaps may use scapy.

Static: every `import` / `from ... import` in the source, including ones
inside functions, read with `ast` (a lazy import is still an import).
"""

import ast
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            found.add(node.module)
        elif isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "import_module" and node.args:
            argument = node.args[0]
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                found.add(argument.value)
    return found


def _top(name: str) -> str:
    return name.split(".", 1)[0]


def test_pirewall_never_imports_lab_or_scapy() -> None:
    offenders = {
        str(path.relative_to(ROOT)): sorted(name for name in _imports(path) if _top(name) in {"lab", "scapy"})
        for path in (ROOT / "pirewall").rglob("*.py")
    }
    assert {path: names for path, names in offenders.items() if names} == {}


def test_only_the_mock_generator_imports_scapy() -> None:
    users = {
        str(path.relative_to(ROOT).as_posix())
        for path in (ROOT / "lab").rglob("*.py")
        if any(_top(name) == "scapy" for name in _imports(path))
    }
    assert users == {"lab/mock/gen_pcaps.py"}


def test_the_lab_core_reader_never_reaches_the_backend_or_capture() -> None:
    forbidden = ("pirewall.firewall.backend", "pirewall.capture")
    for name in ("poll_state.py", "run_campaign.py", "preflight.py", "score_run.py", "aggregate.py"):
        imports = _imports(ROOT / "lab" / name)
        assert not [item for item in imports if item.startswith(forbidden)], name


def test_the_client_side_scripts_are_stdlib_only() -> None:
    import sys

    allowed = set(sys.stdlib_module_names) | {"lab"}
    for name in ("manifest.py", "benign/background.py", "stats.py", "victim_pcap.py"):
        imports = {_top(item) for item in _imports(ROOT / "lab" / name)}
        assert imports <= allowed, (name, sorted(imports - allowed))

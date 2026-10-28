"""The netns test tier (phase 13): real nft rulesets, real traffic, isolated namespaces (env=sandbox).

Every test here is marked `netns` and skipped unless the host has root, `ip`,
`nft`, `hping3`, `curl`, `conntrack`, `os.setns` and a system `python3` with
scapy. It builds the sandbox topology in fresh namespaces, never touches the
host's own namespace or ruleset, and removes every namespace afterwards.

Results are sandbox regression evidence (CLAUDE.md v2 honesty rule), never
Pi results.

`python3-nftables` is Debian's system package. When the venv cannot import
it, the tier exposes *only that package* to this test process (a one-entry
shim directory on `sys.path`), so the libnftables transport is exercised
too. Production gets it through phase 16's `.pth` instead.
"""

import importlib.util
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.netns.testbed import Testbed, in_namespace, tools_missing

_SYSTEM_NFTABLES = Path("/usr/lib/python3/dist-packages/nftables")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "netns: real-kernel netns tests (root, nft, hping3); env=sandbox")
    config.addinivalue_line(
        "markers", "uses_legit_mac: the test acts on the legit client on purpose (exempt from check 3c)"
    )


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    missing = tools_missing()
    for item in items:
        if "tests/netns" not in item.nodeid.replace("\\", "/"):
            continue
        item.add_marker(pytest.mark.netns)
        if missing:
            item.add_marker(pytest.mark.skip(reason=f"netns tier needs: {', '.join(missing)}"))


def _expose_system_nftables() -> None:
    if importlib.util.find_spec("nftables") is not None or not _SYSTEM_NFTABLES.is_dir():
        return
    shim = Path(tempfile.mkdtemp(prefix="pw-nftables-"))
    (shim / "nftables").symlink_to(_SYSTEM_NFTABLES, target_is_directory=True)
    sys.path.insert(0, str(shim))


@pytest.fixture(scope="module")
def testbed(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Testbed]:
    """The running testbed, with this test process inside the router namespace for its lifetime."""
    _expose_system_nftables()
    bed = Testbed(state=tmp_path_factory.mktemp("pwtb"))
    bed.up()
    try:
        with in_namespace("pw_r"):
            yield bed
    finally:
        bed.down()

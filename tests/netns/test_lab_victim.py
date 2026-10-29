"""`pirewall-start --lab-victim up|down` against a real kernel (phase 16; root; env=sandbox).

The script runs inside its own throwaway router namespace (`pw_lr`), so the
victim's veth, its `pirewall_lab` table and its forwarding all land there,
never in the host's namespace or ruleset. A LAN client namespace (`pw_lc`)
checks the victim is reachable through the router's forward path.

Asserts idempotency both ways: `up` twice gives one table, one rule and one
address; `down` twice leaves nothing behind and succeeds when nothing is
left. The victim's services start only where their binaries are installed;
the script warns, not fails, for a missing one.

Sandbox regression evidence only, never a Pi result (CLAUDE.md v2 honesty
rule). Pid files go to the script's fixed `/run/pirewall-lab`.
"""

import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from scripts.deployment import startup

from tests.helpers.config import make_config
from tests.netns.testbed import REPO, sh

ROUTER = "pw_lr"
CLIENT = "pw_lc"
VICTIM_NETNS = "pw_lvictim"
HOST_IF = "pwlab0"
VICTIM_IP = "10.250.0.2"
SCRIPT = REPO / "scripts" / "deployment" / "pirewall-start"


def _ip(*args: str) -> None:
    subprocess.run(["ip", *args], check=True, capture_output=True)


def _netns_exists(name: str) -> bool:
    listed = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True, check=True).stdout
    return name in {line.split()[0] for line in listed.splitlines() if line.strip()}


def _cleanup() -> None:
    for name in (VICTIM_NETNS, CLIENT, ROUTER):
        if _netns_exists(name):
            subprocess.run(["ip", "netns", "del", name], check=False)


@pytest.fixture(scope="module")
def config_path(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    _cleanup()
    _ip("netns", "add", ROUTER)
    _ip("netns", "add", CLIENT)
    _ip("link", "add", "pwlc0", "netns", CLIENT, "type", "veth", "peer", "name", "lan0", "netns", ROUTER)
    _ip("-n", ROUTER, "addr", "add", "192.168.100.1/24", "dev", "lan0")
    _ip("-n", CLIENT, "addr", "add", "192.168.100.10/24", "dev", "pwlc0")
    for ns, dev in ((ROUTER, "lan0"), (CLIENT, "pwlc0"), (ROUTER, "lo"), (CLIENT, "lo")):
        _ip("-n", ns, "link", "set", dev, "up")
    _ip("-n", CLIENT, "route", "add", "default", "via", "192.168.100.1")
    sh(ROUTER, "sysctl -qw net.ipv4.ip_forward=1", check=True)

    config = make_config(
        network={
            "lan_interface": "lan0",
            "protected_network": "192.168.100.0/24",
            "pirewall_lan_ip": "192.168.100.1",
        },
        lab={
            "victim_netns": VICTIM_NETNS,
            "victim_host_interface": HOST_IF,
            "victim_network": "10.250.0.0/30",
        },
    )
    path = tmp_path_factory.mktemp("lab") / "lab_config.toml"
    path.write_text(startup.to_toml(config.model_dump(mode="json")), encoding="utf-8")
    try:
        yield path
    finally:
        _cleanup()


def _lab(config_path: Path, action: str) -> subprocess.CompletedProcess[str]:
    """Run the script in the router's *network* namespace only.

    Not `ip netns exec`: that also gives the script a private mount
    namespace, so the `/run/netns/<victim>` bind mount `ip netns add` makes
    inside it vanishes when the script exits, and the next run finds a dead
    name. On the Pi the script runs in the host's mount namespace, as here.
    """
    return subprocess.run(
        [
            "nsenter",
            f"--net=/run/netns/{ROUTER}",
            "env",
            f"PIREWALL_PYTHON={sys.executable}",
            "bash",
            str(SCRIPT),
            "--config",
            str(config_path),
            "--lab-victim",
            action,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _lab_table() -> str | None:
    result = sh(ROUTER, "nft list table inet pirewall_lab")
    return result.stdout if result.returncode == 0 else None


def test_up_is_idempotent_and_the_victim_is_reachable_through_the_forward_path(config_path: Path) -> None:
    first = _lab(config_path, "up")
    assert first.returncode == 0, first.stdout + first.stderr
    second = _lab(config_path, "up")
    assert second.returncode == 0, second.stdout + second.stderr
    assert "exists" in second.stdout + second.stderr  # the second run skipped, not re-created

    assert _netns_exists(VICTIM_NETNS)
    table = _lab_table()
    assert table is not None
    assert table.count("meta mark set") == 1
    addresses = sh(ROUTER, f"ip -4 -o addr show dev {HOST_IF}", check=True).stdout
    assert addresses.count("inet 10.250.0.1/30") == 1
    assert sh(CLIENT, f"ping -c 1 -W 2 {VICTIM_IP}").returncode == 0


def test_down_is_idempotent_and_removes_everything(config_path: Path) -> None:
    for _ in range(2):
        result = _lab(config_path, "down")
        assert result.returncode == 0, result.stdout + result.stderr

    assert not _netns_exists(VICTIM_NETNS)
    assert _lab_table() is None
    assert sh(ROUTER, f"ip link show {HOST_IF}").returncode != 0
    assert not any(Path("/run/pirewall-lab").glob("*.pid"))
    assert sh(CLIENT, f"ping -c 1 -W 1 {VICTIM_IP}").returncode != 0

"""`lab/attacks/*.sh --dry-run` (phase 18): every attack refuses a target outside the lab.

Runs bash only; no attack tool is ever executed (`--dry-run` prints the
command). Skipped where bash is unavailable (native Windows).
"""

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Final

import pytest

ATTACKS: Final = Path(__file__).resolve().parents[2] / "lab" / "attacks"
BOUNDS: Final = ["--pi-ip", "192.0.2.2", "--victim-net", "10.250.0.0/30", "--protected-net", "192.0.2.0/24"]

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash (POSIX)"
)

# script -> the extra flags it needs to get as far as the target check.
NEEDS: Final[dict[str, list[str]]] = {
    "syn_flood.sh": [],
    "udp_flood.sh": [],
    "icmp_flood.sh": [],
    "spoof_neighbour.sh": ["--spoof-ip", "192.0.2.21"],
    "nmap_vertical.sh": [],
    "masscan.sh": [],
    "hydra_ssh.sh": ["--wordlist", "/nonexistent"],
    "hydra_http.sh": ["--wordlist", "/nonexistent"],
    "portal_bruteforce.sh": [],
    "slowloris.sh": [],
    "arp_poison.sh": ["--spoof-ip", "192.0.2.21", "--iface", "eth0"],
    "mac_churn.sh": ["--iface", "eth0"],
}
PI_ONLY: Final = {"portal_bruteforce.sh", "arp_poison.sh", "mac_churn.sh"}


def _run(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(ATTACKS / script), "--dry-run", *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_every_attack_script_is_covered() -> None:
    scripts = {path.name for path in ATTACKS.glob("*.sh") if not path.name.startswith("_")}
    assert scripts == set(NEEDS) | {"nmap_horizontal.sh"}


@pytest.mark.parametrize("script", sorted(NEEDS))
@pytest.mark.parametrize("target", ["8.8.8.8", "10.250.0.9", "192.0.3.5"])
def test_an_out_of_lab_target_is_refused(script: str, target: str) -> None:
    result = _run(script, "--target", target, *BOUNDS, *NEEDS[script])
    assert result.returncode == 2, result.stdout + result.stderr
    assert "REFUSED" in result.stderr and "DRY-RUN" not in result.stdout


@pytest.mark.parametrize("script", sorted(NEEDS))
def test_an_in_lab_target_prints_the_command_and_runs_nothing(script: str) -> None:
    target = "192.0.2.2" if script in PI_ONLY else "10.250.0.2"
    result = _run(script, "--target", target, *BOUNDS, *NEEDS[script])
    assert result.returncode == 0, result.stderr
    assert "DRY-RUN: timeout" in result.stdout and "TOOL_VERSION=" in result.stdout
    # MAC churn broadcasts DHCP DISCOVERs (the Pi is the LAN's DHCP server), so no address is named.
    assert target in result.stdout if script != "mac_churn.sh" else "mac-churn eth0" in result.stdout


@pytest.mark.parametrize("script", sorted(PI_ONLY))
def test_pi_only_attacks_refuse_the_lab_victim(script: str) -> None:
    result = _run(script, "--target", "10.250.0.2", *BOUNDS, *NEEDS[script])
    assert result.returncode == 2 and "targets the Pi only" in result.stderr


def test_without_lab_bounds_nothing_runs() -> None:
    result = _run("syn_flood.sh", "--target", "192.0.2.2")
    assert result.returncode == 2 and "lab bounds unknown" in result.stderr


def test_free_form_tool_arguments_are_refused() -> None:
    result = _run("syn_flood.sh", "--target", "192.0.2.2", *BOUNDS, "8.8.8.8")
    assert result.returncode == 2 and "unexpected arguments" in result.stderr


def test_a_lab_target_outside_the_protected_network_is_refused() -> None:
    result = _run("syn_flood.sh", "--lab-target", "198.51.100.7", *BOUNDS)
    assert result.returncode == 2
    assert _run("syn_flood.sh", "--lab-target", "192.0.2.77", *BOUNDS).returncode == 0


@pytest.mark.parametrize("net", ["8.8.8.0/24", "192.0.0.0/16", "10.250.0.0/24"])
def test_horizontal_scans_stay_inside_the_lab_ranges(net: str) -> None:
    assert _run("nmap_horizontal.sh", "--scan-net", net, *BOUNDS).returncode == 2
    assert _run("masscan.sh", "--scan-net", net, *BOUNDS).returncode == 2


def test_horizontal_scans_of_lab_ranges_print_their_command() -> None:
    for net in ("10.250.0.0/30", "192.0.2.0/24"):
        result = _run("nmap_horizontal.sh", "--scan-net", net, *BOUNDS)
        assert result.returncode == 0 and net in result.stdout


def test_spoofing_an_address_outside_the_lan_is_refused() -> None:
    result = _run("spoof_neighbour.sh", "--target", "10.250.0.2", "--spoof-ip", "8.8.4.4", *BOUNDS)
    assert result.returncode == 2 and "outside the protected network" in result.stderr

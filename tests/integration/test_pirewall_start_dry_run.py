"""`pirewall-start --dry-run`: the command order of every mode, from the real script (phase 16).

`--dry-run` prints every mutating command instead of running it (`run`),
so the printed sequence *is* the bring-up order. These tests run the
actual bash script, as a normal user, against a throwaway config whose
interfaces are `lo`. The host-dependent preflight probes are pointed at
fixture files through `PIREWALL_PREFLIGHT_*` (`startup.SystemProbe`).

Skipped where bash or the binaries the script requires are missing.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from scripts.deployment import startup

from pirewall.config.models import PirewallConfig
from tests.helpers.config import make_config

_REPO = Path(startup.__file__).resolve().parents[2]
_SCRIPT = _REPO / "scripts" / "deployment" / "pirewall-start"

pytestmark = pytest.mark.skipif(
    os.name != "posix"
    or any(shutil.which(tool) is None for tool in ("bash", "nft", "systemctl", "systemd-tmpfiles", "ip")),
    reason="needs a POSIX host with bash, nft, systemd and iproute2",
)


@pytest.fixture
def setup(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    cert = tmp_path / "pirewall.crt"
    cert.write_text("not a real certificate; the dry run only checks it exists\n")
    config: PirewallConfig = make_config(
        network={
            "wan_interface": "lo",
            "lan_interface": "lo",
            "admin_interface": "lo",
        },
        capture={"interface": "lo"},
        admin={"admin_pc_mac": "02:00:00:00:00:50"},
        api={"tls_cert_path": str(cert), "tls_key_path": str(tmp_path / "pirewall.key")},
        ml={
            "lightgbm_model_path": str(tmp_path / "none.txt"),
            "isolation_forest_model_path": str(tmp_path / "none.joblib"),
        },
        antispoof={"lease_file": str(tmp_path / "leases")},
    )
    config_path = tmp_path / "local_config.toml"
    config_path.write_text(startup.to_toml(config.model_dump(mode="json")), encoding="utf-8")
    proc = tmp_path / "proc"
    flag = proc / "sys" / "net" / "ipv6" / "conf" / "lo" / "disable_ipv6"
    flag.parent.mkdir(parents=True)
    flag.write_text("1\n")
    env = {
        **os.environ,
        "PIREWALL_PYTHON": sys.executable,
        "PIREWALL_PREFLIGHT_PROC_ROOT": str(proc),
        "PIREWALL_PREFLIGHT_NFTABLES_ENABLED": "disabled",
        "PIREWALL_PREFLIGHT_CHRONY": "synced",
        "PIREWALL_PREFLIGHT_TRANSPORT": "libnftables",
    }
    return config_path, env


def _run(config_path: Path, env: dict[str, str], *flags: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(_SCRIPT), "--config", str(config_path), *flags],
        capture_output=True,
        text=True,
        env=env,
        cwd=_REPO,
        timeout=120,
        check=False,
    )


def _commands(result: subprocess.CompletedProcess[str]) -> list[str]:
    assert result.returncode == 0, result.stdout + result.stderr
    return [line.split("$ ", 1)[1] for line in result.stdout.splitlines() if "$ " in line]


def _index(commands: list[str], fragment: str) -> int:
    matches = [index for index, command in enumerate(commands) if fragment in command]
    assert matches, f"no command containing {fragment!r} in:\n" + "\n".join(commands)
    return matches[0]


def _in_order(commands: list[str], *fragments: str) -> None:
    positions = [_index(commands, fragment) for fragment in fragments]
    assert positions == sorted(positions), dict(zip(fragments, positions, strict=True))


def test_a_live_bring_up_follows_the_v2_load_order(setup: tuple[Path, dict[str, str]]) -> None:
    """base -> static -> adaptive -> seed -> guard verdicts -> core -> api -> manifest (PLAN_v3 §6)."""
    commands = _commands(_run(*setup, "--dry-run", "--no-portal"))

    _in_order(
        commands,
        "startup --config",  # render (the first helper step)
        "nft -c -f",
        "base.nft",
        "nft -c -f " + str(_REPO / "deploy/rendered/pirewall_static.nft"),
        "nft -f " + str(_REPO / "deploy/rendered/pirewall_static.nft"),
        "nft -f " + str(_REPO / "deploy/rendered/pirewall_adaptive.nft"),
        " seed",
        " guards --seeded",
        "pirewall-core.service /etc/systemd/system",
        "systemctl restart pirewall-core.service",
        "systemctl restart pirewall-api.service",
        " manifest --out /var/lib/pirewall/manifest.json",
    )
    assert " render" in commands[_index(commands, "startup --config")]
    assert not any("portal" in command for command in commands)
    # With no guard flags, nothing extra is passed: an empty argument (a
    # trailing space here) would be rejected by the helper's argparse.
    assert not [command for command in commands if command.endswith(" ")]


def test_guard_flags_reach_render_guards_and_the_manifest(setup: tuple[Path, dict[str, str]]) -> None:
    commands = _commands(
        _run(*setup, "--dry-run", "--no-portal", "--guards", "observe", "--guard-input", "enforce")
    )

    for step in (" render", " guards --seeded", " manifest"):
        assert "--guards observe --guard-input enforce" in commands[_index(commands, step)]


def test_skip_nft_touches_no_ruleset(setup: tuple[Path, dict[str, str]]) -> None:
    commands = _commands(_run(*setup, "--dry-run", "--no-portal", "--skip-nft"))

    assert not any(command.startswith("nft ") for command in commands)
    assert not any(" seed" in command or " guards " in command for command in commands)
    assert "--no-kernel" in commands[_index(commands, " manifest")]


def test_a_pi_tag_off_a_pi_is_refused(setup: tuple[Path, dict[str, str]]) -> None:
    result = _run(*setup, "--dry-run", "--no-portal", "--data-mode", "scripted")

    assert result.returncode == 2
    assert "pi-scripted" in result.stdout + result.stderr


def test_scripted_mode_on_a_pi_claims_the_tag_and_reminds_about_the_profiles(
    setup: tuple[Path, dict[str, str]],
) -> None:
    config_path, env = setup
    model = Path(env["PIREWALL_PREFLIGHT_PROC_ROOT"]) / "device-tree" / "model"
    model.parent.mkdir(parents=True)
    model.write_text("Raspberry Pi 4 Model B Rev 1.5\x00")

    result = _run(config_path, env, "--dry-run", "--no-portal", "--data-mode", "scripted")

    assert "--data-mode scripted" in _commands(result)[_index(_commands(result), " manifest")]
    assert "background.py" in result.stdout


def test_mock_mode_uses_no_root_no_nft_and_no_systemd(
    setup: tuple[Path, dict[str, str]], tmp_path: Path
) -> None:
    pcap = tmp_path / "mock.pcap"
    pcap.write_bytes(b"")
    run_dir = tmp_path / "run"

    commands = _commands(
        _run(*setup, "--dry-run", "--data-mode", "mock", "--pcap", str(pcap), "--run-dir", str(run_dir))
    )

    _in_order(commands, " mock-config", "pirewall.main", "pirewall.api", " manifest")
    assert "--data-mode mock" in commands[_index(commands, "pirewall.main")]
    assert "--no-kernel" in commands[_index(commands, " manifest")]
    assert not any(command.startswith(("nft", "systemctl", "install ", "useradd")) for command in commands)


def test_mock_mode_refuses_without_a_pcap(setup: tuple[Path, dict[str, str]], tmp_path: Path) -> None:
    result = _run(*setup, "--dry-run", "--data-mode", "mock", "--pcap", str(tmp_path / "absent.pcap"))

    assert result.returncode == 2
    assert "no pcap" in result.stderr


def test_panic_goes_through_the_helper(setup: tuple[Path, dict[str, str]]) -> None:
    commands = _commands(_run(*setup, "--dry-run", "--panic"))

    assert " panic --actor" in commands[-1]


def test_lab_victim_up_creates_the_netns_then_loads_the_lab_table(setup: tuple[Path, dict[str, str]]) -> None:
    commands = _commands(_run(*setup, "--dry-run", "--lab-victim", "up"))

    _in_order(
        commands,
        "ip netns add labvictim",
        "ip link add lab0 type veth peer name lab0p",
        "ip addr add 10.250.0.1/30 dev lab0",
        "ip -n labvictim addr add 10.250.0.2/30 dev lab0p",
        "route replace default via 10.250.0.1",
        " lab-ruleset --out",
        "nft -c -f",
        "nft -f",
    )


def test_lab_victim_down_removes_the_lab_table(setup: tuple[Path, dict[str, str]]) -> None:
    commands = _commands(_run(*setup, "--dry-run", "--lab-victim", "down"))

    _in_order(commands, "nft -c -f", "pirewall_lab-down.nft")


def test_check_refuses_ipv6_on_the_lan_and_changes_nothing(setup: tuple[Path, dict[str, str]]) -> None:
    config_path, env = setup
    flag = Path(env["PIREWALL_PREFLIGHT_PROC_ROOT"]) / "sys" / "net" / "ipv6" / "conf" / "lo" / "disable_ipv6"
    flag.write_text("0\n")

    result = _run(config_path, env, "--check", "--no-portal")

    assert result.returncode == 2
    assert "IPv6 is enabled on the LAN interface lo" in result.stdout


@pytest.mark.parametrize(
    "flags",
    [
        ("--bogus",),
        ("--guards", "sometimes"),
        ("--engine", "v3"),
        ("--lab-victim", "sideways"),
        ("--pcap", "x"),
    ],
)
def test_bad_flags_are_refused(setup: tuple[Path, dict[str, str]], flags: tuple[str, ...]) -> None:
    assert _run(*setup, "--dry-run", *flags).returncode == 2

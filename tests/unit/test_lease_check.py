"""`scripts.deployment.lease_check`: catching a lease-file path that nothing writes.

Portal sign-in needs a binding and bindings come from this file, so the
check has to catch a wrong or stale path, and has to report only paths and
counts, because the file is client-controlled.
"""

import os
import shlex
import sys
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network
from pathlib import Path

import pytest
from scripts.deployment import lease_check
from scripts.deployment.lease_check import LeaseFileState, check_lease_file, dnsmasq_lease_files

LAN = IPv4Network("10.42.0.0/24")
NM_DNSMASQ = [
    "/usr/sbin/dnsmasq",
    "--conf-file=/dev/null",
    "--no-hosts",
    "--keep-in-foreground",
    "--listen-address=10.42.0.1",
    "--dhcp-range=10.42.0.10,10.42.0.254,60m",
    "--dhcp-leasefile=/var/lib/NetworkManager/dnsmasq-wlan0.leases",
    "--pid-file=/run/nm-dnsmasq-wlan0.pid",
]
HOSTILE_HOSTNAME = "evil$(reboot);`id`"


def _lease_line(ip: str = "10.42.0.20", mac: str = "02:00:00:00:00:20", hostname: str = "phone") -> str:
    expiry = int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
    return f"{expiry} {mac} {ip} {hostname} *\n"


def _writer(path: Path) -> list[str]:
    return ["dnsmasq", f"--dhcp-leasefile={path}"]


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (NM_DNSMASQ, ("/var/lib/NetworkManager/dnsmasq-wlan0.leases",)),
        (["dnsmasq", "--dhcp-leasefile", "/a.leases"], ("/a.leases",)),
        (["/usr/sbin/dnsmasq", "-l", "/b.leases"], ("/b.leases",)),
        (["dnsmasq", "-l/c.leases"], ("/c.leases",)),
        (["dnsmasq", "--keep-in-foreground"], ()),
        (["dnsmasq", "-l"], ()),
        (["/usr/bin/python3", "--dhcp-leasefile=/fake.leases"], ()),
        (["dnsmasq-helper", "--dhcp-leasefile=/fake.leases"], ()),
        ([], ()),
    ],
)
def test_lease_files_are_read_from_dnsmasq_command_lines_only(
    argv: list[str], expected: tuple[str, ...]
) -> None:
    assert dnsmasq_lease_files([argv]) == expected


def test_several_dnsmasqs_are_all_reported_once() -> None:
    cmdlines = [_writer(Path("/b.leases")), _writer(Path("/a.leases")), _writer(Path("/a.leases"))]
    assert dnsmasq_lease_files(cmdlines) == ("/a.leases", "/b.leases")


def test_a_file_written_by_a_running_dnsmasq_is_ok(tmp_path: Path) -> None:
    leases = tmp_path / "dnsmasq-wlan0.leases"
    leases.write_text(_lease_line() + _lease_line("10.42.0.21", "02:00:00:00:00:21"), encoding="utf-8")
    result = check_lease_file(str(leases), [_writer(leases)], LAN)
    assert result.state is LeaseFileState.OK
    assert result.leases == 2


def test_an_empty_lease_file_is_still_ok(tmp_path: Path) -> None:
    """No clients yet is normal; the file being written is what matters."""
    leases = tmp_path / "dnsmasq-wlan0.leases"
    leases.write_text("", encoding="utf-8")
    assert check_lease_file(str(leases), [_writer(leases)], LAN).state is LeaseFileState.OK


def test_a_missing_file_names_the_file_dnsmasq_actually_writes(tmp_path: Path) -> None:
    result = check_lease_file(str(tmp_path / "dnsmasq-wlan0.leases"), [NM_DNSMASQ], LAN)
    assert result.state is LeaseFileState.MISSING
    assert "/var/lib/NetworkManager/dnsmasq-wlan0.leases" in result.message


def test_a_file_no_dnsmasq_writes_is_stale(tmp_path: Path) -> None:
    """The LAN moved from wlan0 to wlan1: the old file is still there, and never changes again."""
    old = tmp_path / "dnsmasq-wlan0.leases"
    old.write_text(_lease_line(), encoding="utf-8")
    new = tmp_path / "dnsmasq-wlan1.leases"
    result = check_lease_file(str(old), [_writer(new)], LAN)
    assert result.state is LeaseFileState.OTHER_FILE
    assert str(new) in result.message


def test_a_file_with_no_dnsmasq_running_is_reported(tmp_path: Path) -> None:
    leases = tmp_path / "dnsmasq-wlan0.leases"
    leases.write_text(_lease_line(), encoding="utf-8")
    result = check_lease_file(str(leases), [["/usr/sbin/sshd", "-D"]], LAN)
    assert result.state is LeaseFileState.NO_DNSMASQ


def test_the_same_file_through_another_spelling_matches(tmp_path: Path) -> None:
    leases = tmp_path / "dnsmasq-wlan0.leases"
    leases.write_text("", encoding="utf-8")
    spelled = tmp_path / "sub" / ".." / "dnsmasq-wlan0.leases"
    assert check_lease_file(str(leases), [_writer(spelled)], LAN).state is LeaseFileState.OK


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX permissions, non-root")
def test_an_unreadable_file_is_reported(tmp_path: Path) -> None:
    leases = tmp_path / "dnsmasq-wlan0.leases"
    leases.write_text(_lease_line(), encoding="utf-8")
    leases.chmod(0)
    try:
        assert check_lease_file(str(leases), [_writer(leases)], LAN).state is LeaseFileState.UNREADABLE
    finally:
        leases.chmod(0o600)


def test_hostnames_never_reach_the_message(tmp_path: Path) -> None:
    leases = tmp_path / "dnsmasq-wlan0.leases"
    leases.write_text(_lease_line(hostname=HOSTILE_HOSTNAME), encoding="utf-8")
    for cmdlines in ([_writer(leases)], [], [_writer(tmp_path / "other.leases")]):
        result = check_lease_file(str(leases), cmdlines, LAN)
        assert HOSTILE_HOSTNAME not in result.message
        assert "evil" not in result.message


def test_read_cmdlines_splits_on_nul_and_skips_non_pids(tmp_path: Path) -> None:
    (tmp_path / "123").mkdir()
    (tmp_path / "123" / "cmdline").write_bytes(b"dnsmasq\0--dhcp-leasefile=/x.leases\0")
    (tmp_path / "self").mkdir()
    (tmp_path / "self" / "cmdline").write_bytes(b"ignored\0")
    (tmp_path / "456").mkdir()  # a process that exited mid-scan: no cmdline file
    assert lease_check.read_cmdlines(tmp_path) == [["dnsmasq", "--dhcp-leasefile=/x.leases"]]


def test_shell_output_is_quoted_for_eval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.unit.test_config_loader import MINIMAL_VALID_TOML

    config = tmp_path / "local_config.toml"
    lease_file = tmp_path / "it's here.leases"
    # An apostrophe in the path: the value must survive `eval` in pirewall-start.
    config.write_text(MINIMAL_VALID_TOML + f'\n[antispoof]\nlease_file = "{lease_file}"\n', encoding="utf-8")
    monkeypatch.setattr(lease_check, "read_cmdlines", list)
    assert lease_check.main(["--config", str(config), "--shell"]) == lease_check.EXIT_OK
    values = dict(shlex.split(line)[0].split("=", 1) for line in capsys.readouterr().out.splitlines())
    assert values["LEASE_STATE"] == "missing"
    assert values["LEASE_FILE"] == str(lease_file)


def test_the_cli_exits_non_zero_on_a_problem_and_on_a_bad_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lease_check, "read_cmdlines", list)
    assert lease_check.main(["--config", str(tmp_path / "absent.toml")]) == lease_check.EXIT_CONFIG
    from tests.unit.test_config_loader import MINIMAL_VALID_TOML

    config = tmp_path / "local_config.toml"
    config.write_text(MINIMAL_VALID_TOML, encoding="utf-8")
    assert lease_check.main(["--config", str(config)]) == lease_check.EXIT_PROBLEM

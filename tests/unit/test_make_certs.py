"""`scripts/deployment/make_certs.sh` writes every name it is given as a SAN (KNOWN_ISSUES.md #9).

Runs the real script and parses the certificate with `openssl x509 -text`.
Skipped where that cannot happen: not on POSIX (the script is bash, and
on Windows `bash` may resolve to WSL's launcher, not Git Bash), or without
`bash` or `openssl` on PATH.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "deployment" / "make_certs.sh"

pytestmark = [
    pytest.mark.skipif(os.name != "posix", reason="make_certs.sh is a bash script; run on Linux"),
    pytest.mark.skipif(shutil.which("bash") is None, reason="bash not on PATH"),
    pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not on PATH"),
]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(_SCRIPT), *args], capture_output=True, text=True, check=False, timeout=60
    )


def test_every_ip_and_dns_name_becomes_a_san(tmp_path: Path) -> None:
    result = _run("-o", str(tmp_path), "-d", "30", "192.168.100.1", "10.0.0.2", "pirewall.lan")
    assert result.returncode == 0, result.stderr

    text = subprocess.run(
        ["openssl", "x509", "-in", str(tmp_path / "pirewall.crt"), "-noout", "-text"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "IP Address:192.168.100.1" in text
    assert "IP Address:10.0.0.2" in text
    assert "DNS:pirewall.lan" in text
    assert oct((tmp_path / "pirewall.key").stat().st_mode & 0o777) == oct(0o600)


def test_a_single_ip_still_works(tmp_path: Path) -> None:
    result = _run("-o", str(tmp_path), "192.168.100.1")
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "name",
    ["1.2.3.4,DNS:evil.example", "bad name", "999.1.1.1", "-leading.example", "a..b"],
)
def test_a_name_that_could_inject_or_is_malformed_is_refused(tmp_path: Path, name: str) -> None:
    result = _run("-o", str(tmp_path), "192.168.100.1", name)
    assert result.returncode == 64, result.stderr
    assert not (tmp_path / "pirewall.crt").exists()


def test_the_old_positional_output_dir_is_refused_with_a_hint(tmp_path: Path) -> None:
    result = _run("192.168.100.1", str(tmp_path / "certs"))
    assert result.returncode == 64
    assert "-o" in result.stderr
    assert not (tmp_path / "certs").exists()

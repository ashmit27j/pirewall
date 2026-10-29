"""`pirewall-start --data-mode mock`, for real: core + api as a normal user, a pcap end to end.

Phase 16's CI case (ADDENDUM_4.md D7 `mock`): the actual bash script
starts `pirewall.main --data-mode mock` (pcap replay, in-memory firewall
fakes, no root, no nft) and `pirewall.api` on 127.0.0.1 with a throwaway
certificate, then writes a `mock`-tagged manifest. The test drives both
processes the way an operator would: the core socket, and HTTPS login.

Skipped without bash, openssl or curl, or where `AF_UNIX` is missing, and
when run as root (mock mode refuses root on purpose).
"""

import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from scripts.deployment import startup

from pirewall.capture.pcapio import PcapWriter
from pirewall.core.enums import GuardMode
from pirewall.ipc.client import UnixSocketRpcClient
from tests.helpers.config import make_config
from tests.helpers.traffic import ACK, FIN, PSH, SYN, T0_US, tcp

_REPO = Path(startup.__file__).resolve().parents[2]
_SCRIPT = _REPO / "scripts" / "deployment" / "pirewall-start"

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX")
    or any(shutil.which(tool) is None for tool in ("bash", "openssl", "curl"))
    or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs a non-root POSIX host with bash, openssl and curl",
)

_DEADLINE_SECONDS = 60.0


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_for(condition: Callable[[], bool], what: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + _DEADLINE_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"pirewall-start exited ({process.returncode}) before {what}")
        try:
            if condition():
                return
        except Exception:  # not up yet: the condition is retried until the deadline
            pass
        time.sleep(0.2)
    raise AssertionError(f"timed out waiting for {what}")


def _https_json(url: str, *, body: dict[str, str] | None = None, token: str | None = None) -> object:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # the mock run's throwaway self-signed certificate
    request = urllib.request.Request(url, method="POST" if body is not None else "GET")
    if body is not None:
        request.data = json.dumps(body).encode()
        request.add_header("Content-Type", "application/json")
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, context=context, timeout=10) as response:
        return json.loads(response.read())


def test_mock_mode_runs_core_and_api_as_a_normal_user_and_replays_a_pcap(tmp_path: Path) -> None:
    pcap = tmp_path / "mock.pcap"
    with PcapWriter(pcap) as writer:
        for offset, frame in enumerate(
            [
                tcp("192.168.1.10", "203.0.113.7", 40000, 80, SYN),
                tcp("203.0.113.7", "192.168.1.10", 80, 40000, SYN | ACK),
                tcp("192.168.1.10", "203.0.113.7", 40000, 80, ACK | PSH, b"GET / HTTP/1.1\r\n\r\n"),
                tcp("192.168.1.10", "203.0.113.7", 40000, 80, FIN | ACK),
                tcp("203.0.113.7", "192.168.1.10", 80, 40000, FIN | ACK),
            ]
        ):
            writer.write(frame, T0_US + offset * 1_000)
    source = tmp_path / "source_config.toml"
    source.write_text(startup.to_toml(make_config().model_dump(mode="json")), encoding="utf-8")
    run_dir = tmp_path / "run"
    copy = tmp_path / "copy-manifest.json"
    port = _free_port()
    env = {**os.environ, "PIREWALL_PYTHON": sys.executable, "PIREWALL_MOCK_API_PORT": str(port)}

    process = subprocess.Popen(
        [
            "bash", str(_SCRIPT), "--config", str(source), "--data-mode", "mock",
            "--pcap", str(pcap), "--run-dir", str(run_dir), "--manifest", str(copy),
        ],
        cwd=_REPO,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        # `up` is written last, once core and api are both serving.
        _wait_for(lambda: (run_dir / "up").is_file(), "the stack to come up", process)
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["env"] == "mock"
        assert manifest["data_mode"] == "mock"
        assert json.loads(copy.read_text(encoding="utf-8"))["env"] == "mock"

        core = UnixSocketRpcClient(str(run_dir / "core.sock"))
        _wait_for(lambda: len(core.list_flows()) == 1, "the replayed session", process)
        assert core.get_guard_modes().forward is GuardMode.OBSERVE
        assert core.get_engine_stats().backend == "replay"
        assert all(rule.status.value != "active" for rule in core.list_rules())  # SHADOW (A1)

        password = (run_dir / "admin-password").read_text(encoding="utf-8").strip()
        login = _https_json(
            f"https://127.0.0.1:{port}/api/v1/auth/login", body={"username": "admin", "password": password}
        )
        assert isinstance(login, dict)
        token: object = cast("dict[str, object]", login)["token"]
        assert isinstance(token, str)
        guards = _https_json(f"https://127.0.0.1:{port}/api/v1/guards", token=token)
        assert isinstance(guards, dict) and guards["input"] == "enforce"
        assert oct((run_dir / "admin-password").stat().st_mode & 0o777) == oct(0o600)
    finally:
        os.killpg(process.pid, signal.SIGTERM)
        output, _ = process.communicate(timeout=30)
    assert "env tag: mock" in output
    assert not (run_dir / "core.sock").exists(), "core should have shut down cleanly"

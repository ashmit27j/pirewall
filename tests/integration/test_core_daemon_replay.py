"""`CoreDaemon` on a pcap replay: no root, no NIC, no nft (ADDENDUM_4.md D7 `mock`).

The whole daemon (every thread, the real RPC socket, the pipeline,
`FirewallManager` over `FakeFirewallBackend`) with `build_replay_capture`
standing in for live capture, injected the way phase 16's capture
selection will choose it. Runs on the native path where the extension is
built and on the Python path otherwise.

Skipped where `AF_UNIX` is unavailable.
"""

import socket
import tempfile
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pirewall.capture.pcapio import PcapWriter
from pirewall.capture.replay import ReplayCapture, ReplayPacketCapture, build_replay_capture
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.flow.native import native_engine_available
from pirewall.ipc.client import UnixSocketRpcClient
from pirewall.runtime.core import CoreDaemon
from pirewall.runtime.watchdog import SystemdNotifier
from tests.helpers.config import make_config
from tests.helpers.traffic import ACK, FIN, PSH, SYN, T0_US, tcp

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="platform has no AF_UNIX support")

_DEADLINE_SECONDS = 10.0


@pytest.fixture
def workdir() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="pw-") as directory:
        yield Path(directory)


def _wait_for(condition: Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + _DEADLINE_SECONDS
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


@pytest.mark.parametrize("native", [True, False], ids=["native", "python"])
def test_core_runs_a_replay_end_to_end_without_root_or_nft(
    workdir: Path, native: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    if native and not native_engine_available():
        pytest.skip("pirewall_native not built")
    if not native:
        monkeypatch.setattr("pirewall.capture.replay.native_engine_available", lambda: False)
    src, dst = "203.0.113.7", "192.168.1.10"
    body = b"GET / HTTP/1.1\r\n\r\n"
    capture_file = workdir / "mock.pcap"
    with PcapWriter(capture_file) as writer:
        for offset, frame in enumerate(
            [
                tcp(src, dst, 40000, 80, SYN),
                tcp(dst, src, 80, 40000, SYN | ACK),
                tcp(src, dst, 40000, 80, ACK | PSH, body),
                tcp(src, dst, 40000, 80, FIN | ACK),
                tcp(dst, src, 80, 40000, FIN | ACK),
            ]
        ):
            writer.write(frame, T0_US + offset * 1_000)

    socket_path = str(workdir / "core.sock")
    config = make_config(
        api={"rpc_socket_path": socket_path, "history_size": 50},
        firewall={"allowlist_store_path": str(workdir / "allowlist.json")},
        capture={"interface": "eth1", "backend": "replay", "replay_path": str(capture_file)},
    )
    capture, aggregator = build_replay_capture(config, rebase_to=datetime.now(UTC))
    assert isinstance(capture, ReplayCapture if native else ReplayPacketCapture)
    backend = FakeFirewallBackend()
    daemon = CoreDaemon(
        config,
        capture=capture,
        backend=backend,
        notifier=SystemdNotifier(notify_socket=None),
        native_aggregator=aggregator,
    )
    daemon.start()
    try:
        client = UnixSocketRpcClient(socket_path)
        _wait_for(lambda: len(client.list_flows()) == 1, "the replayed session over RPC")
        flow = client.list_flows()[0]
        assert (str(flow.source_ip), str(flow.destination_ip)) == (src, dst)
        assert flow.payload_stats is not None
        assert flow.payload_stats.forward_bytes == len(body)
        _wait_for(lambda: len(client.list_threats()) == 1, "the flow's assessment")
        # Rebased onto the wall clock, so core's own timers make sense of it.
        assert abs((flow.first_seen - datetime.now(UTC)).total_seconds()) < 60
    finally:
        daemon.stop()
    assert backend.list_active_rule_ids() == frozenset()  # SHADOW (A1): evidence only

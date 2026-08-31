"""Regression: `CoreDaemon._detection_loop` must re-drain `_new_flow_queue` after waking
from a blocking `_flow_queue.get()`, not rely solely on its top-of-loop drain.

**The bug this guards against, found on a real POSIX run of
`tests/integration/test_core_daemon.py::test_scanning_visible_through_a_completing_flow_while_scan_flows_stay_open`**
(that whole file is `AF_UNIX`-gated and skipped on Windows, which is why
this file exists separately and runs `_detection_loop` directly instead):
`CoreDaemon.start()` spawns the detection thread *before* the capture
thread. On the very first loop iteration the detection thread's
top-of-loop `_drain_new_flow_signals()` legitimately finds nothing (the
capture thread hasn't run yet) and falls into a blocking
`_flow_queue.get(timeout=...)`. The capture thread is a single sequential
producer: for a burst of new connections followed by one completing flow,
it pushes every `NewFlowSignal` for that burst strictly before it pushes
the completed `Flow` (program order on one thread). When that flow lands
in `_flow_queue`, it immediately unblocks the detection thread's `get()`
— *before* that thread has drained the burst of signals that arrived
while it was blocked. The completing flow's own `BehaviorAssessment` then
reflects only itself, not the sibling connections already sitting in the
queue, unseen — which is exactly the `detected_patterns=()` failure that
was observed. The fix is a second `_drain_new_flow_signals()`/
`_drain_slow_clusters()` call immediately after `_flow_queue.get()`
returns, before `FlowPipeline.process` runs. This test reproduces the race
for real (a genuine background thread genuinely blocked inside
`queue.Queue.get()`, not just an inspection of the code) and would fail
without that second drain.

Runs `_detection_loop` in a bare `threading.Thread`, never calling
`CoreDaemon.start()`/`.stop()` — those bind the real `AF_UNIX` RPC socket,
same reasoning `tests/integration/test_tls_evidence_wiring.py` documents.
`_detection_loop` itself never touches that socket.
"""

import threading
import time
from datetime import UTC, datetime

from pirewall.capture.fake import FakePacketCapture
from pirewall.core.models.common import TcpFlags
from pirewall.core.models.flow import Flow
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.runtime.core import CoreDaemon
from pirewall.runtime.watchdog import SystemdNotifier
from tests.helpers.config import make_config
from tests.helpers.flows import make_packet

NOW = datetime(2026, 1, 1, tzinfo=UTC)

_SRC, _DST = "203.0.113.60", "192.168.1.10"
_WAIT_DEADLINE_SECONDS = 5.0
_WAIT_POLL_SECONDS = 0.02


def _daemon() -> CoreDaemon:
    missing: dict[str, object] = {
        "lightgbm_model_path": "/nonexistent/pirewall-test/lightgbm_model.txt",
        "isolation_forest_model_path": "/nonexistent/pirewall-test/isolation_forest.joblib",
    }
    config = make_config(ml=missing, detection={"scanning_port_threshold": 5})
    return CoreDaemon(
        config,
        capture=FakePacketCapture("test0", []),
        backend=FakeFirewallBackend(),
        notifier=SystemdNotifier(notify_socket=None),
    )


def test_detection_loop_redrains_new_flow_signals_after_waking_from_a_blocking_get() -> None:
    daemon = _daemon()
    thread = threading.Thread(target=daemon._detection_loop, daemon=True)  # pyright: ignore[reportPrivateUsage]
    thread.start()
    try:
        # Let the detection thread reach its first, empty-queues blocking
        # `_flow_queue.get()` call before anything is produced -- mirrors
        # CoreDaemon.start() spawning capture *after* detection.
        time.sleep(0.05)

        # The capture thread's burst: six new connections to distinct
        # ports, landing in `_new_flow_queue` while the detection thread
        # is already inside its blocking `get()`.
        with daemon._flow_lock:  # pyright: ignore[reportPrivateUsage]
            for port in range(6000, 6006):
                daemon._aggregator.process_packet(  # pyright: ignore[reportPrivateUsage]
                    make_packet(
                        source_ip=_SRC,
                        destination_ip=_DST,
                        source_port=51000 + port,
                        destination_port=port,
                        timestamp=NOW,
                    )
                )

            # The flow that "unblocks" the detection thread's `get()`.
            completed: list[Flow] = []
            for packet in [
                make_packet(
                    source_ip=_SRC, destination_ip=_DST, source_port=60000,
                    destination_port=443, timestamp=NOW, tcp_flags=TcpFlags(syn=True),
                ),
                make_packet(
                    source_ip=_DST, destination_ip=_SRC, source_port=443,
                    destination_port=60000, timestamp=NOW, tcp_flags=TcpFlags(syn=True, ack=True),
                ),
                make_packet(
                    source_ip=_SRC, destination_ip=_DST, source_port=60000,
                    destination_port=443, timestamp=NOW, tcp_flags=TcpFlags(fin=True, ack=True),
                ),
                make_packet(
                    source_ip=_DST, destination_ip=_SRC, source_port=443,
                    destination_port=60000, timestamp=NOW, tcp_flags=TcpFlags(fin=True, ack=True),
                ),
            ]:
                completed.extend(daemon._aggregator.process_packet(packet))  # pyright: ignore[reportPrivateUsage]

        assert len(completed) == 1, "expected exactly one completed flow from the FIN-closing session"
        daemon._flow_queue.put_nowait(completed[0])  # pyright: ignore[reportPrivateUsage]

        deadline = time.monotonic() + _WAIT_DEADLINE_SECONDS
        while time.monotonic() < deadline and len(daemon._state.threats) < 1:  # pyright: ignore[reportPrivateUsage]
            time.sleep(_WAIT_POLL_SECONDS)
    finally:
        daemon._stop.set()  # pyright: ignore[reportPrivateUsage]
        thread.join(timeout=2.0)

    assert len(daemon._state.threats) == 1, "the completing flow's assessment never arrived"  # pyright: ignore[reportPrivateUsage]
    assessment = daemon._state.threats[0]  # pyright: ignore[reportPrivateUsage]
    assert assessment.behavior_assessment is not None
    assert "scanning" in [p.value for p in assessment.behavior_assessment.detected_patterns], (
        "the six-port scan burst was not visible in the completing flow's own assessment -- "
        "the detection loop failed to re-drain _new_flow_queue after waking from its blocking "
        "get(); see this module's docstring"
    )

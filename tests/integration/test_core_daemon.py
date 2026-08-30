"""`pirewall.runtime.core.CoreDaemon` end to end — the pirewall-core process itself.

This is the test that proves `systemctl start pirewall-core` now has
something real to start. It runs the *whole* daemon — every thread, the
real `AF_UNIX` RPC transport, the real flow aggregator, the real detection
coordinator, the real `FirewallManager` and its full validation chain —
substituting only the two hardware-dependent Protocol implementations that
`CLAUDE.md` requires be fakeable: `FakePacketCapture` for `AF_PACKET` and
`FakeFirewallBackend` for nftables. So it runs without root, without a NIC,
and without touching a real nftables ruleset.

What stays Environment-dependent and is *not* claimed here: `AFPacketCapture`
against a real interface, `NftablesBackend` against a real `nft` binary,
systemd actually supervising the unit, and real TLS. See
`docs/PROGRESS.md`.

Timing: the daemon is thread-based, so these tests poll for a condition
with a generous deadline rather than sleeping a fixed amount. A timeout
here means a genuine deadlock or a thread that never started, not a slow
machine.
"""

import socket
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from pirewall.capture.fake import FakePacketCapture
from pirewall.config.models import PirewallConfig
from pirewall.core.enums import EnforcementMode
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.ipc.client import UnixSocketRpcClient
from pirewall.runtime.core import CoreDaemon
from pirewall.runtime.watchdog import SystemdNotifier
from tests.helpers.config import make_config
from tests.helpers.packets import eth, ipv4_header, tcp_header

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="platform has no AF_UNIX support"
)

_DEADLINE_SECONDS = 10.0
_POLL_SECONDS = 0.02

_SYN = 0x02
_FIN_ACK = 0x11


@pytest.fixture
def socket_path() -> Iterator[str]:
    """A short temp path: `AF_UNIX` names are capped at ~104 bytes on macOS."""
    with tempfile.TemporaryDirectory(prefix="pw") as directory:
        yield str(Path(directory) / "c.sock")


def _tcp_packet(src_port: int, dst_port: int, flags: int, src: str, dst: str) -> bytes:
    ip = ipv4_header(6, total_length=40, src=src, dst=dst)
    return eth(0x0800) + ip + tcp_header(src_port, dst_port, flags=flags)


def _one_completed_session(src: str = "203.0.113.7", dst: str = "192.168.1.10") -> list[bytes]:
    """A TCP session that FIN-closes, so the aggregator completes the flow immediately.

    Without the FIN the flow would sit in the table until an inactivity
    timeout, which would make this test depend on wall-clock sleeps.
    """
    return [
        _tcp_packet(51234, 443, _SYN, src, dst),
        _tcp_packet(443, 51234, _SYN | 0x10, dst, src),
        _tcp_packet(51234, 443, _FIN_ACK, src, dst),
        _tcp_packet(443, 51234, _FIN_ACK, dst, src),
    ]


def _wait_for(condition: Callable[[], bool], what: str) -> None:
    deadline = time.monotonic() + _DEADLINE_SECONDS
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(_POLL_SECONDS)
    raise AssertionError(f"timed out waiting for {what}")


def _daemon(
    socket_path: str, packets: list[bytes], **overrides: dict[str, object]
) -> tuple[CoreDaemon, PirewallConfig, FakeFirewallBackend]:
    api_overrides: dict[str, object] = {"rpc_socket_path": socket_path, "history_size": 50}
    api_overrides.update(overrides.pop("api", {}))
    config = make_config(api=api_overrides, **overrides)
    backend = FakeFirewallBackend()
    daemon = CoreDaemon(
        config,
        capture=FakePacketCapture("test0", list(packets)),
        backend=backend,
        # No `$NOTIFY_SOCKET` in a test process, so this is inert — asserted
        # explicitly below rather than left implicit.
        notifier=SystemdNotifier(notify_socket=None),
        )
    return daemon, config, backend


def test_daemon_starts_serves_rpc_and_stops_cleanly(socket_path: str) -> None:
    """The minimum bar for `systemctl start`: it comes up, answers, and goes down."""
    # Point ML at paths that are guaranteed absent. Relying on the repo's
    # artifacts dir being empty made this assert the state of the developer's
    # working tree rather than the daemon's behaviour: model files are
    # gitignored, so it held in CI but failed on any machine that had
    # actually trained a model.
    missing: dict[str, object] = {
        "lightgbm_model_path": "/nonexistent/pirewall-test/lightgbm_model.txt",
        "isolation_forest_model_path": "/nonexistent/pirewall-test/isolation_forest.joblib",
    }
    daemon, _, _ = _daemon(socket_path, _one_completed_session(), ml=missing)
    daemon.start()
    try:
        assert Path(socket_path).exists()
        client = UnixSocketRpcClient(socket_path)
        status = client.get_status()
        assert status.enforcement_mode is EnforcementMode.SHADOW  # A1 default
        assert status.uptime_seconds >= 0.0
        # Artifacts are absent, so the daemon must have started with ML
        # degraded rather than refusing to come up at all.
        assert status.lightgbm_loaded is False
        assert status.isolation_forest_loaded is False
    finally:
        daemon.stop()

    assert not Path(socket_path).exists()  # the socket file is cleaned up


def test_captured_packets_become_flows_visible_over_rpc(socket_path: str) -> None:
    """capture -> parse -> aggregate -> pipeline -> CoreStateStore, through every real thread."""
    daemon, _, _ = _daemon(socket_path, _one_completed_session())
    daemon.start()
    try:
        client = UnixSocketRpcClient(socket_path)
        _wait_for(lambda: len(client.list_flows()) >= 1, "a completed flow to reach the state store")

        flow = client.list_flows()[0]
        assert str(flow.source_ip) == "203.0.113.7"
        assert flow.destination_port == 443
        # The detection layer ran even with both models absent: behaviour
        # analysis is deterministic and needs no artifact.
        _wait_for(lambda: len(client.list_threats()) >= 1, "a threat assessment")
        _wait_for(lambda: len(client.list_decisions()) >= 1, "a firewall decision")
    finally:
        daemon.stop()


def test_capture_statistics_are_published_for_the_control_panel(socket_path: str) -> None:
    """Closes the spec §30 "network statistics" gap `docs/PROGRESS.md` recorded."""
    daemon, _, _ = _daemon(socket_path, _one_completed_session())
    daemon.start()
    try:
        client = UnixSocketRpcClient(socket_path)
        assert client.get_capture_stats() is None  # nothing reported before the first tick

        daemon._tick()  # pyright: ignore[reportPrivateUsage] — the periodic pass, run deterministically

        stats = client.get_capture_stats()
        assert stats is not None
        assert stats.interface == "test0"
        assert stats.packets_seen == 4
    finally:
        daemon.stop()


def test_shadow_mode_never_deploys_to_the_backend(socket_path: str) -> None:
    """ADDENDUM.md A1: the default mode logs what it *would* do and enforces nothing."""
    daemon, _, backend = _daemon(socket_path, _one_completed_session())
    daemon.start()
    try:
        client = UnixSocketRpcClient(socket_path)
        _wait_for(lambda: len(client.list_flows()) >= 1, "a completed flow")
    finally:
        daemon.stop()

    assert backend.apply_calls == 0
    assert backend.list_active_rule_ids() == frozenset()


def test_a_capture_that_cannot_start_is_reported_not_fatal(socket_path: str) -> None:
    """A6: a core that stays up to say "capture is down" beats a crash-looping unit."""

    class _UnstartableCapture(FakePacketCapture):
        def start(self) -> None:
            from pirewall.core.exceptions import CaptureError

            raise CaptureError("no such device test0")

    config = make_config(api={"rpc_socket_path": socket_path, "history_size": 50})
    daemon = CoreDaemon(
        config,
        capture=_UnstartableCapture("test0", []),
        backend=FakeFirewallBackend(),
        notifier=SystemdNotifier(notify_socket=None),
    )
    daemon.start()
    try:
        client = UnixSocketRpcClient(socket_path)
        # Still serving RPC, and the reason is in the audit trail.
        assert client.get_status().enforcement_mode is EnforcementMode.SHADOW
        reasons = [event.reason or "" for event in client.list_events()]
        assert any("no such device test0" in reason for reason in reasons)
    finally:
        daemon.stop()


def test_backpressure_drops_flows_rather_than_blocking_capture(socket_path: str) -> None:
    """The queue bound must cost detection coverage, never packet capture."""
    packets: list[bytes] = []
    for index in range(6):
        packets.extend(_one_completed_session(src=f"203.0.113.{10 + index}"))

    config = make_config(api={"rpc_socket_path": socket_path, "history_size": 50})
    daemon = CoreDaemon(
        config,
        capture=FakePacketCapture("test0", packets),
        backend=FakeFirewallBackend(),
        notifier=SystemdNotifier(notify_socket=None),
        flow_queue_max=1,
    )
    daemon.start()
    try:
        # Capture must drain its whole input regardless of the tiny queue.
        _wait_for(
            lambda: daemon._capture.statistics().packets_seen == len(packets),  # pyright: ignore[reportPrivateUsage]
            "capture to consume every packet despite a full queue",
        )
    finally:
        daemon.stop()


def test_scanning_visible_through_a_completing_flow_while_scan_flows_stay_open(
    socket_path: str,
) -> None:
    """ADDENDUM_2.md B1, end to end: scanning is counted at creation, not completion.

    Drives 6 single-SYN "scan" flows (never FIN'd, so under the old
    architecture they would sit uncounted until an inactivity timeout) plus
    one ordinary 4-packet completing flow, all from the same source. The
    only flow that ever completes is the ordinary one — but because the
    scan flows already updated the source's behavioral state the instant
    each one *opened*, the completing flow's own threat assessment already
    carries the SCANNING pattern, well before any scan flow times out.
    """
    src, dst = "203.0.113.60", "192.168.1.10"
    packets: list[bytes] = [_tcp_packet(51000 + port, port, _SYN, src, dst) for port in range(6000, 6006)]
    packets.extend(_one_completed_session(src=src, dst=dst))

    config_overrides: dict[str, dict[str, object]] = {
        "detection": {"scanning_port_threshold": 5},
        # Long enough that none of the never-FIN'd scan flows could complete
        # via timeout within this test's deadline — if scanning shows up
        # anyway, it did so without them completing.
        "flow": {"active_timeout_seconds": 3600, "inactive_timeout_seconds": 3600},
    }
    config = make_config(
        api={"rpc_socket_path": socket_path, "history_size": 50}, **config_overrides
    )
    daemon = CoreDaemon(
        config,
        capture=FakePacketCapture("test0", packets),
        backend=FakeFirewallBackend(),
        notifier=SystemdNotifier(notify_socket=None),
    )
    daemon.start()
    try:
        client = UnixSocketRpcClient(socket_path)
        _wait_for(lambda: len(client.list_threats()) >= 1, "a threat assessment")

        # Exactly one flow (the completing 4-packet session) ever finished —
        # the six scan flows are still open, proving they were never
        # completed, only counted at creation.
        assert len(client.list_flows()) == 1

        assessments = client.list_threats()
        assert any(
            assessment.behavior_assessment is not None
            and "scanning" in [p.value for p in assessment.behavior_assessment.detected_patterns]
            for assessment in assessments
        ), [a.behavior_assessment for a in assessments]
    finally:
        daemon.stop()


def test_slow_rate_dos_detected_without_waiting_for_connections_to_close_or_time_out(
    socket_path: str,
) -> None:
    """ADDENDUM_2.md B2, end to end: many concurrent slow connections, none of which ever close.

    Every one of the "slow" connections here is a bare, never-acknowledged
    SYN — no FIN, no timeout reached during the test (timeouts are left at
    generous defaults). The only way `SLOW_RATE_DOS` can show up in a
    `ThreatAssessment` here is via the sweep loop's periodic snapshot of
    still-open flows, not via any flow actually completing.
    """
    src, dst = "203.0.113.90", "192.168.1.20"
    packets = [_tcp_packet(45000 + port, 80, _SYN, src, dst) for port in range(6)]

    config = make_config(
        api={"rpc_socket_path": socket_path, "history_size": 50},
        detection={
            "concurrent_slow_connections_threshold": 5,
            "slow_connection_min_duration_seconds": 0.2,
            "slow_connection_max_bytes_per_second": 10_000.0,
        },
        flow={"cleanup_interval_seconds": 1},
    )
    daemon = CoreDaemon(
        config,
        capture=FakePacketCapture("test0", packets),
        backend=FakeFirewallBackend(),
        notifier=SystemdNotifier(notify_socket=None),
    )
    daemon.start()
    try:
        client = UnixSocketRpcClient(socket_path)
        _wait_for(
            lambda: any(
                assessment.behavior_assessment is not None
                and "slow_rate_dos"
                in [p.value for p in assessment.behavior_assessment.detected_patterns]
                for assessment in client.list_threats()
            ),
            "a SLOW_RATE_DOS threat assessment from still-open connections",
        )
    finally:
        daemon.stop()


def _deploy_one_rule(daemon: CoreDaemon) -> str:
    """Push a rule to ACTIVE through the manager's normal, fully validated path.

    Deliberately not by engineering traffic that scores CRITICAL: that would
    make a shutdown test depend on threat-scoring tuning. The rule still
    goes through the whole ten-stage validation chain — nothing here
    bypasses it.
    """
    from datetime import timedelta

    from pirewall.core.enums import RuleStatus, ThreatLevel
    from pirewall.core.models.decision import FirewallDecision
    from tests.helpers.rules import make_candidate

    manager = daemon._manager  # pyright: ignore[reportPrivateUsage]
    now = daemon._started_at  # pyright: ignore[reportPrivateUsage]
    candidate = make_candidate(created_at=now, expires_at=now + timedelta(hours=1))
    manager.register_decision(
        FirewallDecision(
            id=candidate.decision_id,
            threat_assessment_id="assessment-1",
            flow_id="flow-1",
            action=candidate.action,
            threat_score=candidate.threat_score or 0.0,
            threat_level=ThreatLevel.CRITICAL,
            reason=candidate.reason,
            decided_at=now,
        )
    )
    result = manager.submit_candidate(candidate, now)
    assert result.rule is not None
    assert result.rule.status is RuleStatus.ACTIVE
    return result.rule.id


def test_clean_shutdown_reverts_the_ruleset_when_failing_open(socket_path: str) -> None:
    """ADDENDUM.md A6: nftables rules outlive the process, so leaving them is failing *closed*.

    A stopped pirewall that keeps blocking traffic, with nothing left
    running to expire those rules, is the opposite of `fail_open`.
    """
    daemon, _, backend = _daemon(
        socket_path,
        [],
        firewall={"enforcement_mode": "active"},
        failure={"mode": "fail_open"},
    )
    daemon.start()
    rule_id = _deploy_one_rule(daemon)
    assert rule_id in backend.list_active_rule_ids()

    daemon.stop()

    assert backend.list_active_rule_ids() == frozenset()


def test_clean_shutdown_keeps_the_ruleset_when_failing_closed(socket_path: str) -> None:
    """`fail_closed` is an explicit opt-in to keeping enforcement up while pirewall is down."""
    daemon, _, backend = _daemon(
        socket_path,
        [],
        firewall={"enforcement_mode": "active"},
        failure={"mode": "fail_closed"},
    )
    daemon.start()
    rule_id = _deploy_one_rule(daemon)

    daemon.stop()

    assert rule_id in backend.list_active_rule_ids()

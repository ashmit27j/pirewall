"""D1 detectors on synthetic connection-start streams (ADDENDUM_4.md D4, PLAN_FINAL §4.5; phase 17).

Attack shapes (nmap, masscan, hydra, slowloris) must fire; benign shapes (a
busy page load, a phone waking up, an OS update, P2P) must stay under the
documented floors (`config/d1_thresholds.toml` as shipped). Synthetic
streams, env=mock: these are regression checks of the detector logic, not
measurements of any real network.
"""

import random
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Final

import pytest

from pirewall.config.models import D1Config
from pirewall.core.enums import BindingSource, D1Detector, Protocol
from pirewall.core.models.identity import Binding
from pirewall.detection_v2.d1 import (
    ConnectionStart,
    D1State,
    start_from_features,
    start_from_record,
    start_from_signal,
)
from pirewall.detection_v2.thresholds import load_thresholds
from tests.helpers.flows import make_flow

NOW: Final = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
MAC: Final = "02:00:00:00:00:66"
SRC: Final = IPv4Address("192.168.1.66")
SHIPPED: Final = Path(__file__).resolve().parents[2] / "config" / "d1_thresholds.toml"


def _state(**overrides: object) -> D1State:
    return D1State(D1Config.model_validate(overrides), load_thresholds(SHIPPED))


def _start(
    dst: str,
    port: int,
    at: datetime,
    *,
    failed: bool = False,
    duration: float = 1.0,
    size: int = 900,
    mac: str = MAC,
) -> ConnectionStart:
    return ConnectionStart(mac, SRC, IPv4Address(dst), port, at, failed, duration, size)


def _feed(state: D1State, starts: Iterable[ConnectionStart]) -> datetime:
    last = NOW
    for start in starts:
        state.observe(start)
        last = max(last, start.at)
    return last


def _fired(state: D1State, at: datetime, mac: str = MAC) -> set[D1Detector]:
    return {item.detector for item in state.evaluate_device(mac, at)}


# ---------------------------------------------------------------- attack shapes


def test_an_nmap_like_syn_scan_is_a_vertical_scan_and_mostly_failed() -> None:
    state = _state()
    at = _feed(
        state,
        (
            _start("192.168.1.10", port, NOW + timedelta(milliseconds=5 * port), failed=True)
            for port in range(1, 1001)
        ),
    )

    fired = _fired(state, at)
    assert D1Detector.VERTICAL_SCAN in fired
    assert D1Detector.FAILED_HANDSHAKE in fired


def test_a_masscan_like_sweep_is_a_horizontal_scan() -> None:
    state = _state()
    at = _feed(
        state,
        (
            _start(f"10.20.{i // 250}.{i % 250 + 1}", 443, NOW + timedelta(milliseconds=10 * i), failed=True)
            for i in range(500)
        ),
    )

    assert D1Detector.HORIZONTAL_SCAN in _fired(state, at)


def test_a_hydra_like_ssh_brute_force_is_brute_force() -> None:
    state = _state()
    rng = random.Random(7)
    at = _feed(
        state,
        (
            _start(
                "192.168.1.10",
                22,
                NOW + timedelta(seconds=1.5 * i),
                duration=1.2,
                size=2_100 + rng.randint(-40, 40),
            )
            for i in range(40)
        ),
    )

    fired = _fired(state, at)
    assert D1Detector.BRUTE_FORCE in fired
    assert D1Detector.VERTICAL_SCAN not in fired


def test_a_slowloris_like_cluster_is_slow_rate_dos() -> None:
    state = _state()
    state.observe_slow_cluster(MAC, SRC, IPv4Address("192.168.1.10"), 40, NOW)

    assert D1Detector.SLOW_RATE_DOS in _fired(state, NOW)


# ---------------------------------------------------------------- benign shapes


def test_a_busy_page_load_stays_under_the_floors() -> None:
    state = _state()
    hosts = [f"151.101.{i}.1" for i in range(12)]
    at = _feed(
        state,
        (
            _start(
                hosts[i % 12],
                443 if i % 5 else 80,
                NOW + timedelta(milliseconds=150 * i),
                duration=4.0,
                size=30_000 + 977 * i,
            )
            for i in range(40)
        ),
    )

    assert _fired(state, at) == set()


def test_a_phone_waking_up_stays_under_the_floors() -> None:
    state = _state()
    rng = random.Random(3)
    starts = [
        _start(
            f"17.{rng.randint(0, 250)}.{rng.randint(0, 250)}.{rng.randint(1, 250)}",
            rng.choice([443, 443, 443, 5223, 80]),
            NOW + timedelta(milliseconds=400 * i),
            duration=rng.uniform(0.3, 30.0),
            size=rng.randint(500, 80_000),
        )
        for i in range(25)
    ]

    assert _fired(state, _feed(state, starts)) == set()


def test_an_os_update_stays_under_the_floors() -> None:
    state = _state()
    cdn = ["23.1.1.1", "23.1.1.2", "23.1.1.3"]
    at = _feed(
        state,
        (
            _start(cdn[i % 3], 443, NOW + timedelta(seconds=7 * i), duration=45.0, size=40_000_000)
            for i in range(8)
        ),
    )

    assert _fired(state, at) == set()


def test_p2p_traffic_stays_under_the_floors() -> None:
    state = _state()
    rng = random.Random(11)
    starts = [
        _start(
            f"{rng.randint(1, 220)}.{rng.randint(0, 250)}.{rng.randint(0, 250)}.{rng.randint(1, 250)}",
            rng.randint(10_000, 65_000),
            NOW + timedelta(milliseconds=900 * i),
            failed=rng.random() < 0.35,
            duration=rng.uniform(0.1, 60.0),
            size=rng.randint(100, 500_000),
        )
        for i in range(60)
    ]

    assert _fired(state, _feed(state, starts)) == set()


# ---------------------------------------------------------------- other detectors


def test_fan_in_toward_one_destination_names_no_device() -> None:
    state = _state()
    for i in range(30):
        state.observe(
            _start("192.168.1.10", 80, NOW + timedelta(milliseconds=100 * i), mac=f"02:00:00:00:10:{i:02x}")
        )

    found = state.evaluate_destination(IPv4Address("192.168.1.10"), NOW + timedelta(seconds=3))
    assert {item.detector for item in found} == {D1Detector.FAN_IN}
    assert all(item.mac is None for item in found)


def test_mac_churn_and_lease_bursts_are_global_rates() -> None:
    state = _state()
    state.observe_bindings([], NOW)  # seed: nothing known yet
    for i in range(40):
        state.observe(
            _start("8.8.8.8", 443, NOW + timedelta(milliseconds=50 * i), mac=f"02:00:00:00:20:{i:02x}")
        )
    state.observe_bindings(
        [
            Binding(
                ip=IPv4Address(f"192.168.1.{100 + i}"),
                mac=f"02:00:00:00:20:{i:02x}",
                source=BindingSource.LEASE,
                expires_at=NOW + timedelta(hours=1),
            )
            for i in range(40)
        ],
        NOW + timedelta(seconds=2),
    )

    detectors = {item.detector for item in state.evaluate_global(NOW + timedelta(seconds=3))}
    assert {D1Detector.NEW_MAC_RATE, D1Detector.NEW_LEASE_RATE} <= detectors


def test_the_first_binding_snapshot_is_not_a_lease_burst() -> None:
    state = _state()
    state.observe_bindings(
        [
            Binding(
                ip=IPv4Address(f"192.168.1.{100 + i}"),
                mac=f"02:00:00:00:30:{i:02x}",
                source=BindingSource.LEASE,
                expires_at=NOW + timedelta(hours=1),
            )
            for i in range(60)
        ],
        NOW,
    )

    assert D1Detector.NEW_LEASE_RATE not in {item.detector for item in state.evaluate_global(NOW)}


def test_portal_failures_from_one_device_name_it_and_a_spread_names_none() -> None:
    state = _state()
    for i in range(15):
        state.observe_portal_failure("alice", MAC, NOW + timedelta(seconds=i))
    for i in range(15):
        state.observe_portal_failure("bob", f"02:00:00:00:40:{i:02x}", NOW + timedelta(seconds=i))

    found = [
        item
        for item in state.evaluate_global(NOW + timedelta(seconds=20))
        if item.detector is D1Detector.PORTAL_AUTH_FAILURES
    ]
    alice = [item for item in found if "account=alice" in item.id]
    bob = [item for item in found if "account=bob" in item.id]
    assert alice and all(item.mac == MAC for item in alice)
    assert bob and all(item.mac is None for item in bob)


# ---------------------------------------------------------------- identity and bounds


def test_evidence_ids_are_stable_within_a_window_bucket() -> None:
    state = _state()
    at = _feed(state, (_start("192.168.1.10", port, NOW, failed=True) for port in range(1, 200)))

    first = {item.id for item in state.evaluate_device(MAC, at)}
    again = {item.id for item in state.evaluate_device(MAC, at + timedelta(milliseconds=1))}
    assert first and first == again


def test_state_is_bounded_and_evictions_are_counted() -> None:
    state = _state(max_tracked_macs=8, max_events_per_mac=16, max_tracked_destinations=4)
    for i in range(50):
        for port in range(20):
            state.observe(_start(f"10.0.0.{i}", port + 1, NOW, mac=f"02:00:00:00:50:{i:02x}"))

    assert state.tracked_macs() == 8
    assert state.counters.macs_evicted == 42
    assert state.counters.events_dropped > 0
    assert state.counters.destinations_evicted == 46
    assert len(state.destinations()) == 4


def test_a_broadcast_or_missing_mac_never_identifies_a_device() -> None:
    for mac in (None, "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "00:00:00:00:00:00"):
        assert (
            start_from_signal(
                source_mac=mac,
                source_ip=SRC,
                destination_ip=IPv4Address("1.1.1.1"),
                destination_port=443,
                protocol=Protocol.TCP,
                at=NOW,
            )
            is None
        )


def test_udp_signals_are_never_connection_starts() -> None:
    assert (
        start_from_signal(
            source_mac=MAC,
            source_ip=SRC,
            destination_ip=IPv4Address("1.1.1.1"),
            destination_port=53,
            protocol=Protocol.UDP,
            at=NOW,
        )
        is None
    )


def test_a_record_and_its_signal_do_not_double_count_a_scan() -> None:
    """Signals and records feed the same cardinality: seeing a connection twice changes nothing."""
    by_signal, by_both = _state(), _state()
    for port in range(1, 41):
        at = NOW + timedelta(milliseconds=port)
        signal = start_from_signal(
            source_mac=MAC,
            source_ip=SRC,
            destination_ip=IPv4Address("192.168.1.10"),
            destination_port=port,
            protocol=Protocol.TCP,
            at=at,
        )
        assert signal is not None
        by_signal.observe(signal)
        by_both.observe(signal)
        by_both.observe(_start("192.168.1.10", port, at, failed=True))

    key = next(
        key
        for key in by_signal.measure_device(MAC, NOW + timedelta(seconds=1))
        if key.detector is D1Detector.VERTICAL_SCAN
    )
    assert (
        by_signal.measure_device(MAC, NOW + timedelta(seconds=1))[key]
        == by_both.measure_device(MAC, NOW + timedelta(seconds=1))[key]
        == 40
    )


@pytest.mark.parametrize(
    ("backward", "packets", "payload", "failed"),
    [(0, 1, 0, True), (1, 2, 0, True), (1, 3, 0, True), (4, 10, 1200, False), (2, 4, 0, False)],
    ids=["filtered", "closed-port-rst", "syn-scan-rst", "normal", "empty-but-handshaken"],
)
def test_the_handshake_outcome_comes_from_the_canonical_features(
    backward: int, packets: int, payload: float, failed: bool
) -> None:
    features = {
        "packet_count": float(packets),
        "backward_packet_count": float(backward),
        "payload_byte_count": payload,
        "duration_seconds": 0.5,
    }
    start = start_from_features(
        is_start=True,
        source_mac=MAC,
        source_ip=SRC,
        destination_ip=IPv4Address("1.1.1.1"),
        destination_port=443,
        first_seen=NOW,
        features=features,
    )

    assert start is not None and start.failed is failed


def test_a_live_record_goes_through_the_feature_extractor() -> None:
    flow = make_flow(
        source_ip="192.168.1.66",
        destination_port=22,
        packet_count=12,
        forward_packet_count=7,
        backward_packet_count=5,
        duration_seconds=1.0,
    ).model_copy(update={"source_mac": MAC})

    start = start_from_record(flow, is_start=True)
    assert start is not None and start.failed is False and start.byte_count is not None
    assert start_from_record(flow, is_start=False) is None

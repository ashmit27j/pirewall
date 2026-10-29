"""Tier K: the kernel offender poller (phase 17 deliverable 1), over `FakeSetBackend` (Mocked).

The poller reads through `FirewallManager`'s read-only views, exactly as
core wires it, with the kernel side simulated by the fake's test hooks.
Real `@offenders`/counter reads are covered by tests/netns (root, real nft).
"""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Final

import pytest

from pirewall.core import nft_names
from pirewall.core.enums import EventSeverity, GuardMode, GuardName
from pirewall.core.nft_names import OffenderCode
from pirewall.detection_v2.kernel import KernelPoller
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.runtime.core import _ManagerKernelReader  # pyright: ignore[reportPrivateUsage]
from tests.helpers.config import make_config

MAC: Final = "02:00:00:00:00:66"
T0: Final = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


class _Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


def _setup(
    clock: Callable[[], datetime], **guard_modes: GuardMode
) -> tuple[FakeSetBackend, FirewallManager, KernelPoller]:
    modes = {GuardName(name): mode for name, mode in guard_modes.items()}
    sets = FakeSetBackend(clock, adaptive_size=10, guard_modes=modes or None)
    manager = FirewallManager(make_config(), FakeFirewallBackend(), set_backend=sets)
    poller = KernelPoller(_ManagerKernelReader(manager), sustained_polls=2, set_fill_warning_ratio=0.8)
    return sets, manager, poller


def test_an_offender_becomes_evidence_with_its_guard_mode_and_sustained_polls(clock: _Clock) -> None:
    sets, _, poller = _setup(clock, forward=GuardMode.ENFORCE)
    sets.record_offender(MAC, OffenderCode.NEWCONN)

    first = poller.poll(clock.now)
    clock.now += timedelta(seconds=1)
    second = poller.poll(clock.now)

    (one,) = first.evidence
    (two,) = second.evidence
    assert (one.guard, one.guard_mode, one.sustained_polls) == (GuardName.FORWARD, GuardMode.ENFORCE, 1)
    assert two.sustained_polls == 2
    assert one.id != two.id  # crossing policy.sustained_polls is new evidence
    assert second.started_at[two.id] == T0
    clock.now += timedelta(seconds=1)
    assert poller.poll(clock.now).evidence[0].id == two.id  # the same sustained episode: same evidence


def test_the_mode_is_the_one_at_poll_time(clock: _Clock) -> None:
    sets, manager, poller = _setup(clock, forward=GuardMode.OBSERVE)
    sets.record_offender(MAC, OffenderCode.NEWCONN_DST)
    observed = poller.poll(clock.now).evidence[0]

    manager.set_guard_mode(GuardName.FORWARD, GuardMode.ENFORCE, "test", clock.now)
    enforced = poller.poll(clock.now + timedelta(seconds=1)).evidence[0]

    assert observed.guard_mode is GuardMode.OBSERVE
    assert enforced.guard_mode is GuardMode.ENFORCE
    assert observed.id != enforced.id


def test_an_expired_element_ends_the_episode(clock: _Clock) -> None:
    sets, _, poller = _setup(clock)
    sets.record_offender(MAC, OffenderCode.SYN_PPS, timeout_seconds=2)
    poller.poll(clock.now)
    clock.now += timedelta(seconds=1)
    poller.poll(clock.now)
    clock.now += timedelta(seconds=5)
    assert poller.poll(clock.now).evidence == ()

    sets.record_offender(MAC, OffenderCode.SYN_PPS)
    assert poller.poll(clock.now).evidence[0].sustained_polls == 1


def test_broadcast_macs_and_unknown_codes_are_not_evidence(clock: _Clock) -> None:
    sets, _, poller = _setup(clock)
    sets.record_offender("ff:ff:ff:ff:ff:ff", OffenderCode.SYN_PPS)
    sets.record_offender(MAC, 999)

    result = poller.poll(clock.now)
    assert result.evidence == ()
    assert result.offender_count == 2


def test_meter_membership_is_never_evidence(clock: _Clock) -> None:
    sets, _, poller = _setup(clock)
    meter = sorted(nft_names.STATIC_METER_SETS)[0]
    sets._set(nft_names.INET_FAMILY, nft_names.STATIC_TABLE, meter).elements[MAC] = None  # pyright: ignore[reportPrivateUsage]

    assert poller.poll(clock.now).evidence == ()


def test_guard_counters_are_reported_as_per_poll_deltas(clock: _Clock) -> None:
    sets, _, poller = _setup(clock)
    sets.bump_counter("c_verdict_raw", 100)
    poller.poll(clock.now)
    sets.bump_counter("c_verdict_raw", 40)
    sets.bump_counter("c_verdict_forward", 7)

    hits = poller.poll(clock.now).guard_hits
    assert hits[GuardName.RAW] == 40
    assert hits[GuardName.FORWARD] == 7


def test_a_set_above_80_percent_warns_once_until_it_drains(clock: _Clock) -> None:
    sets, _, poller = _setup(clock)
    for i in range(9):
        sets.record_offender(f"02:00:00:00:01:{i:02x}", OffenderCode.NEWCONN, timeout_seconds=3)

    first = poller.poll(clock.now)
    assert [alert.severity for alert in first.alerts] == [EventSeverity.WARNING]
    assert "offenders" in first.alerts[0].reason
    assert first.max_set_fill_ratio == pytest.approx(0.9)
    assert poller.poll(clock.now).alerts == ()
    clock.now += timedelta(seconds=10)
    assert poller.poll(clock.now).alerts == ()
    for i in range(9):
        sets.record_offender(f"02:00:00:00:02:{i:02x}", OffenderCode.NEWCONN)
    assert len(poller.poll(clock.now).alerts) == 1  # re-armed after draining


def test_a_missing_static_table_skips_the_reads(clock: _Clock) -> None:
    sets, manager, poller = _setup(clock)
    sets.record_offender(MAC, OffenderCode.SYN_PPS)
    manager.panic("test", clock.now)

    result = poller.poll(clock.now)
    assert result.table_present is False
    assert result.evidence == ()

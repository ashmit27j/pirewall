"""The six v2 RPC operations on `CoreRpcDispatcher` (docs/V2_CONTRACTS.md §9, phase 16).

Through `LoopbackRpcClient`, so the typed client methods, the wire format
and the handlers are exercised together, over `FakeSetBackend`.
"""

from datetime import UTC, datetime
from ipaddress import IPv4Address

import pytest

from pirewall.core import nft_names
from pirewall.core.enums import (
    BindingSource,
    EnforcementMode,
    EventSeverity,
    GuardMode,
    GuardName,
    SecurityEventType,
)
from pirewall.core.exceptions import RpcError
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.identity import Binding
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.firewall.manager import FirewallManager
from pirewall.ipc.dispatcher import CoreRpcDispatcher
from pirewall.ipc.loopback import LoopbackRpcClient
from pirewall.ipc.portal_dispatcher import PortalRpcDispatcher
from pirewall.ipc.protocol import RpcOperation
from pirewall.ipc.protocol_v2 import V2_OPERATIONS, EngineStats
from pirewall.ipc.snapshots import V2Snapshots
from pirewall.ipc.state import CoreStateStore
from tests.helpers.config import make_config

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
_BOUND = Binding(ip=IPv4Address("192.168.1.20"), mac="02:00:00:00:00:20", source=BindingSource.STATIC)


class _Core:
    """A dispatcher over fake kernel sets, with every emitted event captured."""

    def __init__(self, *, with_sets: bool = True, with_snapshots: bool = True) -> None:
        self.config = make_config(firewall={"enforcement_mode": "active"})
        self.sets = FakeSetBackend(lambda: NOW) if with_sets else None
        self.manager = FirewallManager(self.config, FakeFirewallBackend(), set_backend=self.sets)
        self.state = CoreStateStore(max_history=20, started_at=NOW)
        self.events: list[SecurityEvent] = []
        self.snapshots = V2Snapshots(lambda: (_BOUND,)) if with_snapshots else None
        if self.snapshots is not None and with_sets:
            self.snapshots.publish_guard_modes(self.manager.guard_modes(NOW))
        self.dispatcher = CoreRpcDispatcher(
            self.state,
            self.manager,
            self.config,
            now_fn=lambda: NOW,
            snapshots=self.snapshots,
            on_event=self.events.append,
        )
        self.client = LoopbackRpcClient(self.dispatcher)


def test_the_operation_names_are_the_frozen_contract() -> None:
    names = {operation.value for operation in RpcOperation}
    assert set(V2_OPERATIONS) <= names
    assert {operation.value for operation in CoreRpcDispatcher.LOCK_FREE_OPERATIONS} == {
        "get_guard_modes",
        "list_offenders",
        "list_bindings",
        "get_engine_stats",
    }


def test_get_guard_modes_serves_the_published_snapshot() -> None:
    core = _Core()

    modes = core.client.get_guard_modes()

    assert (modes.raw, modes.input, modes.forward) == (
        GuardMode.ENFORCE,
        GuardMode.ENFORCE,
        GuardMode.OBSERVE,
    )


def test_get_guard_modes_reports_why_it_has_none() -> None:
    core = _Core()
    assert core.snapshots is not None
    core.snapshots.publish_guard_modes(None, "pirewall_static is not loaded")

    with pytest.raises(RpcError, match="pirewall_static is not loaded"):
        core.client.get_guard_modes()


def test_set_guard_mode_flips_the_kernel_chain_audits_and_republishes() -> None:
    core = _Core()
    assert core.sets is not None and core.snapshots is not None

    modes = core.client.set_guard_mode(GuardName.FORWARD, GuardMode.ENFORCE, "alice")

    assert modes.forward is GuardMode.ENFORCE
    assert core.sets.guard_mode(GuardName.FORWARD) is GuardMode.ENFORCE
    published = core.snapshots.guard_modes
    assert published is not None and published.forward is GuardMode.ENFORCE
    assert len(core.events) == 1
    assert "guard forward set to enforce by alice" in (core.events[0].reason or "")


@pytest.mark.parametrize(
    ("params", "message"),
    [
        ({"guard": "sideways", "mode": "enforce", "actor": "a"}, "invalid guard"),
        ({"guard": "raw", "mode": "maybe", "actor": "a"}, "invalid mode"),
        ({"guard": "raw", "mode": "enforce", "actor": "  "}, "actor"),
        ({"guard": "raw", "mode": "enforce"}, "actor"),
    ],
)
def test_set_guard_mode_refuses_bad_parameters_and_changes_nothing(
    params: dict[str, object], message: str
) -> None:
    from pirewall.ipc.protocol import RpcRequest

    core = _Core()
    assert core.sets is not None

    response = core.dispatcher.handle(RpcRequest(operation=RpcOperation.SET_GUARD_MODE, params=params))

    assert not response.ok
    assert message in (response.error or "")
    assert core.sets.guard_mode(GuardName.RAW) is GuardMode.ENFORCE
    assert core.events == []


def test_panic_deletes_only_the_v2_tables_and_audits_at_critical() -> None:
    core = _Core()
    assert core.sets is not None and core.snapshots is not None

    result = core.client.panic("alice")

    assert result.actor == "alice"
    assert result.deleted_tables == tuple(f"{family} {table}" for family, table in nft_names.PANIC_TABLES)
    assert core.sets.table_exists(nft_names.INET_FAMILY, nft_names.BASE_TABLE)
    assert core.sets.table_exists(nft_names.INET_FAMILY, nft_names.PORTAL_TABLE)
    assert not core.sets.table_exists(nft_names.INET_FAMILY, nft_names.STATIC_TABLE)
    assert core.manager.enforcement_mode is EnforcementMode.SHADOW
    assert [event.severity for event in core.events] == [EventSeverity.CRITICAL]
    assert core.snapshots.guard_modes is None
    assert "panic" in (core.snapshots.guard_modes_error or "")


def test_panic_without_the_set_backend_is_a_clear_error() -> None:
    core = _Core(with_sets=False)

    with pytest.raises(RpcError, match="panic failed"):
        core.client.panic("alice")
    assert core.events == []


def test_bindings_offenders_and_engine_stats_come_from_the_snapshots() -> None:
    core = _Core()
    assert core.snapshots is not None
    stats = EngineStats(
        backend="native",
        has_packet_ring=True,
        frames_seen=10,
        kernel_drops=1,
        flows_shed=2,
        new_flow_signals_shed=3,
        panics_caught=4,
        read_at=NOW,
    )

    with pytest.raises(RpcError, match="not been published"):
        core.client.get_engine_stats()
    core.snapshots.publish_engine_stats(stats)

    assert core.client.list_bindings() == (_BOUND,)
    assert core.client.list_offenders() == ()
    assert core.client.get_engine_stats() == stats


def test_without_snapshots_the_reads_say_v2_is_unavailable() -> None:
    core = _Core(with_snapshots=False)

    for call in (core.client.get_guard_modes, core.client.list_bindings, core.client.get_engine_stats):
        with pytest.raises(RpcError, match="v2 status is not available"):
            call()


def test_api_reported_events_go_through_the_event_sink_to_wazuh() -> None:
    """Phase 12 deviation 4: `record_event` used to stop at `CoreStateStore`."""
    core = _Core()
    event = SecurityEvent(
        timestamp=NOW,
        severity=EventSeverity.WARNING,
        event_type=SecurityEventType.AUTHENTICATION_FAILURE,
        subsystem="api.auth",
        reason="bad password",
    )

    core.client.record_event(event)

    assert core.events == [event]


def test_the_kill_switch_writes_an_audit_entry() -> None:
    core = _Core()

    core.client.kill_switch()

    assert len(core.events) == 1
    assert core.events[0].event_type is SecurityEventType.SYSTEM_WARNING


def test_the_portal_dispatcher_has_none_of_the_v2_operations() -> None:
    """C1: guard flips and panic must never be reachable from the LAN-facing process."""
    handled = set(PortalRpcDispatcher._HANDLERS)  # pyright: ignore[reportPrivateUsage]
    assert not handled & {RpcOperation(name) for name in V2_OPERATIONS}

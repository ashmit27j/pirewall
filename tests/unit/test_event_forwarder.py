"""`pirewall.runtime.forwarder.EventForwarder` (spec §26, §31, §32).

The one sink every `SecurityEvent` in pirewall-core passes through. Its
critical property is that a forwarding failure is contained: these calls
happen on the flow-processing path, so an unreachable Wazuh collector on
the Admin PC must not propagate an exception into packet capture.
"""

from datetime import UTC, datetime

from pirewall.core.enums import EventSeverity, SecurityEventType
from pirewall.core.models.event import SecurityEvent
from pirewall.integration.fake import FakeWazuhTransport
from pirewall.integration.wazuh import WazuhForwarder
from pirewall.ipc.state import CoreStateStore
from pirewall.runtime.forwarder import EventForwarder

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _broken_forwarder() -> WazuhForwarder:
    """A Wazuh collector that is down — the ordinary case on a fresh deployment."""
    return WazuhForwarder(FakeWazuhTransport(fail=True), enabled=True)


def _event(reason: str = "test") -> SecurityEvent:
    return SecurityEvent(
        timestamp=NOW,
        severity=EventSeverity.WARNING,
        event_type=SecurityEventType.THREAT_DETECTED,
        subsystem="test",
        reason=reason,
    )


def _store() -> CoreStateStore:
    return CoreStateStore(max_history=50, started_at=NOW)


def test_events_are_recorded_in_the_bounded_store() -> None:
    state = _store()
    EventForwarder(state).emit(_event())
    assert [event.reason for event in state.events] == ["test"]


def test_forwarder_is_callable_so_it_can_be_passed_as_an_on_event_sink() -> None:
    """`capture.pipeline` and `detection.coordinator` both take a bare callable."""
    state = _store()
    forwarder = EventForwarder(state)
    forwarder(_event("via __call__"))
    assert [event.reason for event in state.events] == ["via __call__"]


def test_events_reach_wazuh_when_enabled() -> None:
    transport = FakeWazuhTransport()
    forwarder = EventForwarder(_store(), WazuhForwarder(transport, enabled=True))
    forwarder.emit(_event("forwarded"))
    assert len(transport.sent_messages) == 1
    assert "forwarded" in transport.sent_messages[0]


def test_a_down_collector_never_propagates_into_the_capture_path() -> None:
    state = _store()
    forwarder = EventForwarder(state, _broken_forwarder())
    forwarder.emit(_event())  # must not raise
    assert forwarder.forward_failures == 1


def test_the_first_forwarding_failure_becomes_a_locally_visible_warning() -> None:
    """A silently dropped forward would make a dead collector indistinguishable from a quiet network."""
    state = _store()
    forwarder = EventForwarder(state, _broken_forwarder())

    forwarder.emit(_event())

    types = [event.event_type for event in state.events]
    assert types == [SecurityEventType.THREAT_DETECTED, SecurityEventType.SYSTEM_WARNING]
    assert "Wazuh forwarding failed (1 total)" in (list(state.events)[-1].reason or "")


def test_repeated_forwarding_failures_are_counted_but_not_flooded() -> None:
    state = _store()
    forwarder = EventForwarder(state, _broken_forwarder())

    for _ in range(10):
        forwarder.emit(_event())

    assert forwarder.forward_failures == 10
    warnings = [
        event for event in state.events if event.event_type is SecurityEventType.SYSTEM_WARNING
    ]
    assert len(warnings) == 1  # first failure only, until the 50th

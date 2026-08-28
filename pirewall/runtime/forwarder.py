"""`EventForwarder`: the single sink every `SecurityEvent` in pirewall-core passes through.

Subsystems that emit events (`pirewall.capture.pipeline`,
`pirewall.detection.coordinator`, `pirewall.firewall.manager`) all take an
`on_event`-shaped callable rather than owning a destination of their own.
This is the one implementation of that callable in the running process, and
it fans each event out to three places:

1. `CoreStateStore` — the bounded in-memory history pirewall-api reads over
   RPC (`/api/v1/events`, the control panel's audit trail).
2. The process log, at a level derived from the event's own severity.
3. `WazuhForwarder` — off unless `integration.wazuh_enabled` (spec §32).

**A forwarding failure is never allowed to propagate.** These calls happen
on the packet/flow processing path; an unreachable Wazuh collector on the
Admin PC must not take down packet capture (spec §26, ADDENDUM.md A6). A
failed send is logged and counted, and — so a dead collector is visible
rather than silent — the *first* failure and every Nth after it also become
a `SYSTEM_WARNING` event in the local store, which is always reachable.

Note on where formatting lives: the JSON shaping for Wazuh is
`pirewall.integration.wazuh.format_event`, and the StatsD shaping is
`pirewall.integration.netdata.snapshot_to_metrics`. Both already exist and
are tested; this module deliberately adds no third serializer.
"""

import logging
import threading
from contextlib import AbstractContextManager

from pirewall.core.enums import EventSeverity, SecurityEventType
from pirewall.core.exceptions import IntegrationError
from pirewall.core.models.event import SecurityEvent
from pirewall.integration.wazuh import WazuhForwarder
from pirewall.ipc.state import CoreStateStore

_logger = logging.getLogger(__name__)
_SUBSYSTEM = "runtime.forwarder"

_LOG_LEVEL_BY_SEVERITY = {
    EventSeverity.INFO: logging.INFO,
    EventSeverity.WARNING: logging.WARNING,
    EventSeverity.ERROR: logging.ERROR,
    EventSeverity.CRITICAL: logging.CRITICAL,
}

# Same reasoning as the detection coordinator's inference-failure interval:
# a down collector fails for every event, so reporting every failure would
# flood the very store that has to stay readable.
_FORWARD_FAILURE_EVENT_INTERVAL = 50


class EventForwarder:
    """Records, logs, and optionally forwards every `SecurityEvent` pirewall-core emits."""

    def __init__(
        self,
        state: CoreStateStore,
        wazuh: WazuhForwarder | None = None,
        lock: AbstractContextManager[bool] | None = None,
    ) -> None:
        self._state = state
        self._wazuh = wazuh
        # `AbstractContextManager[bool]` rather than `threading.RLock`:
        # `threading.RLock` is a factory *function*, not a type, so it cannot
        # appear in an annotation. `with lock:` is the entire contract used.
        # Shared with `CoreDaemon`: the RPC thread reads `CoreStateStore`
        # concurrently with the capture/detection threads writing to it.
        self._lock = lock or threading.RLock()
        self._forward_failures = 0

    @property
    def forward_failures(self) -> int:
        """How many Wazuh sends have failed since startup."""
        return self._forward_failures

    def __call__(self, event: SecurityEvent) -> None:
        """Callable form, so this can be passed directly as an `on_event` sink."""
        self.emit(event)

    def emit(self, event: SecurityEvent) -> None:
        """Record `event` locally, log it, and forward it. Never raises."""
        with self._lock:
            self._state.record_event(event)
        _logger.log(
            _LOG_LEVEL_BY_SEVERITY.get(event.severity, logging.INFO),
            "event %s %s [%s] %s",
            event.event_type.value,
            event.severity.value,
            event.subsystem,
            event.reason or "",
        )
        self._forward(event)

    def _forward(self, event: SecurityEvent) -> None:
        if self._wazuh is None:
            return
        try:
            self._wazuh.forward(event)
        except IntegrationError as exc:
            self._note_forward_failure(event, exc)

    def _note_forward_failure(self, event: SecurityEvent, exc: IntegrationError) -> None:
        self._forward_failures += 1
        count = self._forward_failures
        _logger.warning("failed to forward event %s to Wazuh: %s", event.id, exc)
        if count != 1 and count % _FORWARD_FAILURE_EVENT_INTERVAL != 0:
            return
        warning = SecurityEvent(
            timestamp=event.timestamp,
            severity=EventSeverity.WARNING,
            event_type=SecurityEventType.SYSTEM_WARNING,
            subsystem=_SUBSYSTEM,
            reason=f"Wazuh forwarding failed ({count} total): {exc}",
        )
        with self._lock:
            self._state.record_event(warning)

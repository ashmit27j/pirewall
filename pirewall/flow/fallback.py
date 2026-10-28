"""Surviving native engine panics (ADDENDUM_4.md D6).

The engine is built with `panic = "unwind"` and catches every panic at its
Python boundary, so a panic arrives here as `NativeEngineError` with the
engine already recovered. The policy for what happens next lives here, in
one place, for every caller that feeds frames:

* each panic is counted, costs only the frame or batch in flight, and is
  reported as a `CAPTURE_ERROR` event (WARNING);
* `max_panics_per_minute` of them within any 60 s means the engine is not
  recovering. The native path is abandoned for the Python one
  (`parse_packet` + `FlowAggregator`, held to identical output by
  `tests/unit/test_native_parity.py`), with a CRITICAL `CAPTURE_ERROR`
  event. Whatever the native engine still holds is salvaged on the way out
  (its pending output, and its open flows, closed early); what cannot be
  salvaged is counted.

`FallbackFlowEngine` applies that policy to frame feeding (pcap replay and
`scripts/dataset/pcap_to_flows.py`). `NativePanicBudget` is the counting
half on its own, for the live ring path, whose switch to `AFPacketCapture`
is a capture swap that `pirewall-core` performs (phase 16 wires it).
"""

import logging
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from typing import Literal

from pirewall.capture.interfaces import TcpPayload
from pirewall.capture.parser import extract_tcp_payload, parse_packet
from pirewall.config.models import FlowConfig
from pirewall.core.enums import EventSeverity, Protocol, SecurityEventType
from pirewall.core.exceptions import NativeEngineError, PacketParseError
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.flow import Flow
from pirewall.flow.aggregator import FlowAggregator
from pirewall.flow.native import (
    NativeBatch,
    NativeFlowAggregator,
    from_microseconds,
    native_engine_available,
)

_logger = logging.getLogger(__name__)

_SUBSYSTEM = "flow.fallback"
_WINDOW_SECONDS = 60.0
_TLS_PORT = 443

EventSink = Callable[[SecurityEvent], None]


class NativePanicBudget:
    """Counts caught panics; says when there have been too many in a minute.

    `record()` returns True once `max_per_minute` panics fall within any
    trailing 60 s window, and stays True from then on (`exhausted`): a
    fallback is not undone by a quiet minute afterwards.
    """

    def __init__(self, max_per_minute: int, clock: Callable[[], float] = time.monotonic) -> None:
        if max_per_minute <= 0:
            raise ValueError("max_per_minute must be positive")
        self._max = max_per_minute
        self._clock = clock
        self._recent: deque[float] = deque()
        self.total = 0
        self.exhausted = False

    @property
    def max_per_minute(self) -> int:
        """Panics within 60 s that exhaust the budget."""
        return self._max

    def record(self) -> bool:
        """Count one caught panic. True if the budget is now (or already was) exhausted."""
        now = self._clock()
        self.total += 1
        self._recent.append(now)
        while self._recent and now - self._recent[0] >= _WINDOW_SECONDS:
            self._recent.popleft()
        if len(self._recent) >= self._max:
            self.exhausted = True
        return self.exhausted


def _tls_candidate(raw: bytes, source: IPv4Address, destination: IPv4Address,
                   sport: int | None, dport: int | None, at: datetime) -> TcpPayload | None:
    """The native engine's TLS prefilter, in Python: only a heartbeat or a ClientHello."""
    payload = extract_tcp_payload(raw)
    if not payload:
        return None
    if payload[0] == 24 or (payload[0] == 22 and len(payload) >= 6 and payload[5] == 1):
        return TcpPayload(source, destination, sport, dport, at, payload)
    return None


class FallbackFlowEngine:
    """A frame-fed flow engine: native while it behaves, Python after too many panics.

    The interface is `NativeFlowAggregator`'s feeding half (`feed_us`,
    `drain`, `sweep_timeouts`, `flush`, `counters`), so a replay or dataset
    run does not care which path is live. `backend` says which one is.
    """

    def __init__(
        self,
        config: FlowConfig,
        protected_network: IPv4Network | None = None,
        max_panics_per_minute: int = 5,
        on_event: EventSink | None = None,
        prefer_native: bool = True,
        native: NativeFlowAggregator | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """`native` may be supplied (tests inject one); otherwise one is built when available."""
        self._config = config
        self._protected = protected_network
        self._on_event = on_event
        self.budget = NativePanicBudget(max_panics_per_minute, clock)
        self._native: NativeFlowAggregator | None = native
        if self._native is None and prefer_native and native_engine_available():
            self._native = NativeFlowAggregator(config, protected_network)
        self._python: FlowAggregator | None = None
        # Output produced outside a native drain (Python path, salvage). Its
        # lists are only ever mutated in place: the Python aggregator holds
        # `new_flows.append` as its new-flow sink.
        self._pending = NativeBatch([], [], [])
        self._seen_offset = 0
        self._malformed_offset = 0
        self._python_seen = 0
        self._python_malformed = 0
        self.flows_lost_to_panics = 0
        self.batches_lost_to_panics = 0
        if self._native is None:
            self._start_python()

    @property
    def backend(self) -> Literal["native", "python"]:
        """Which path frames currently go through."""
        return "native" if self._native is not None else "python"

    # ------------------------------------------------------------ feeding

    def feed_us(self, raw: bytes, ts_us: int) -> None:
        """Feed one frame captured at `ts_us` (Unix microseconds). Never raises on a panic."""
        native = self._native
        if native is not None:
            try:
                native.feed_us(raw, ts_us)
            except NativeEngineError as exc:
                self._panicked("feed", exc, "the frame was dropped")
            return
        self._feed_python(raw, ts_us)

    def drain(self) -> NativeBatch:
        """Everything produced since the last drain (same order contract as `NativeBatch`)."""
        batch = self._take_pending()
        native = self._native
        if native is not None:
            try:
                fresh = native.drain()
            except NativeEngineError as exc:
                self.batches_lost_to_panics += 1
                self._panicked("drain", exc, "that batch of output was lost")
                return self._merge(batch, self._take_pending())
            return self._merge(batch, fresh)
        return batch

    def sweep_timeouts(self, now: datetime) -> list[Flow]:
        """Same contract as `FlowAggregator.sweep_timeouts`; a panicking sweep returns nothing."""
        native = self._native
        if native is not None:
            try:
                return native.sweep_timeouts(now)
            except NativeEngineError as exc:
                self._panicked("sweep", exc, "flows it would have closed stay open")
                return []
        assert self._python is not None
        return self._python.sweep_timeouts(now)

    def flush(self) -> list[Flow]:
        """Close every open flow (end of a replay)."""
        native = self._native
        if native is not None:
            try:
                return native.flush()
            except NativeEngineError as exc:
                self._panicked("flush", exc, "the open flows were lost")
                return []
        assert self._python is not None
        return self._python.flush()

    def counters(self) -> tuple[int, int]:
        """`(frames seen, frames malformed or unsupported)`, cumulative across both paths."""
        native = self._native
        if native is not None:
            try:
                return native.counters()
            except NativeEngineError:
                return self._seen_offset, self._malformed_offset
        return self._seen_offset + self._python_seen, self._malformed_offset + self._python_malformed

    # -------------------------------------------------------------- panics

    def _panicked(self, where: str, exc: NativeEngineError, cost: str) -> None:
        exhausted = self.budget.record()
        _logger.warning("native engine panic in %s (%d so far): %s; %s", where, self.budget.total, exc, cost)
        self._emit(
            EventSeverity.WARNING,
            f"native engine panicked in {where} and recovered ({self.budget.total} so far); {cost}: {exc}",
        )
        if exhausted and self._native is not None:
            self._fall_back()

    def _fall_back(self) -> None:
        """Abandon the native engine, salvaging what it still holds."""
        native = self._native
        assert native is not None
        self._native = None
        salvaged = 0
        try:
            drained = native.drain()
            self._pending.completed.extend(drained.completed)
            self._pending.new_flows.extend(drained.new_flows)
            self._pending.tls_payloads.extend(drained.tls_payloads)
            closed = native.flush()
            self._pending.completed.extend(closed)
            salvaged = len(closed)
            self._seen_offset, self._malformed_offset = native.counters()
            _panics, lost = native.panic_stats()
            self.flows_lost_to_panics += lost
        except NativeEngineError as exc:
            _logger.error("native engine panicked again while being abandoned: %s", exc)
        reason = (
            f"native engine panicked {self.budget.max_per_minute} time(s) within 60 s "
            f"({self.budget.total} in all); falling back to the Python flow path "
            f"({salvaged} open flow(s) closed early on the way out)"
        )
        _logger.critical("%s", reason)
        self._emit(EventSeverity.CRITICAL, reason)
        self._start_python()

    def _emit(self, severity: EventSeverity, reason: str) -> None:
        if self._on_event is None:
            return
        self._on_event(
            SecurityEvent(
                timestamp=datetime.now(UTC),
                severity=severity,
                event_type=SecurityEventType.CAPTURE_ERROR,
                subsystem=_SUBSYSTEM,
                reason=reason,
            )
        )

    # -------------------------------------------------------------- python

    def _start_python(self) -> None:
        self._python = FlowAggregator(
            self._config, on_new_flow=self._pending.new_flows.append, protected_network=self._protected
        )

    def _feed_python(self, raw: bytes, ts_us: int) -> None:
        assert self._python is not None
        self._python_seen += 1
        at = from_microseconds(ts_us)
        try:
            packet = parse_packet(raw, at)
        except PacketParseError:
            self._python_malformed += 1
            return
        if (
            packet.protocol is Protocol.TCP
            and _TLS_PORT in (packet.source_port, packet.destination_port)
            and isinstance(packet.source_ip, IPv4Address)
            and isinstance(packet.destination_ip, IPv4Address)
        ):
            candidate = _tls_candidate(
                raw, packet.source_ip, packet.destination_ip, packet.source_port, packet.destination_port, at
            )
            if candidate is not None:
                self._pending.tls_payloads.append(candidate)
        self._pending.completed.extend(self._python.process_packet(packet))

    def _take_pending(self) -> NativeBatch:
        taken = NativeBatch(
            list(self._pending.completed), list(self._pending.new_flows), list(self._pending.tls_payloads)
        )
        self._pending.completed.clear()
        self._pending.new_flows.clear()
        self._pending.tls_payloads.clear()
        return taken

    @staticmethod
    def _merge(first: NativeBatch, second: NativeBatch) -> NativeBatch:
        return NativeBatch(
            first.completed + second.completed,
            first.new_flows + second.new_flows,
            first.tls_payloads + second.tls_payloads,
        )


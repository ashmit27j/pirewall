"""Surviving native engine panics (ADDENDUM_4.md D6): count, drop, report, fall back.

Two layers. A Python stand-in for the engine that raises
`NativeEngineError` on demand proves the policy everywhere. Where the
extension was built with the test-only `panic-injection` cargo feature, the
real engine is made to panic inside Rust, so the whole chain (catch_unwind,
poison recovery, `pirewall_native.NativeEngineError`, translation,
fallback) is exercised for real; those tests skip on a normal build.
"""

import importlib
from datetime import datetime
from ipaddress import IPv4Network

import pytest

from pirewall.capture.parser import parse_packet
from pirewall.config.models import FlowConfig
from pirewall.core.enums import EventSeverity, SecurityEventType
from pirewall.core.exceptions import CaptureError, NativeEngineError, PacketParseError
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.flow import Flow
from pirewall.flow.aggregator import FlowAggregator
from pirewall.flow.fallback import FallbackFlowEngine, NativePanicBudget
from pirewall.flow.native import NativeBatch, NativeFlowAggregator, from_microseconds, native_engine_available
from tests.helpers.traffic import ACK, FIN, SYN, T0_US, mixed_stream, tcp

CONFIG = FlowConfig(active_timeout_seconds=120, inactive_timeout_seconds=60, max_flows=64)
PROTECTED = IPv4Network("192.168.100.0/24")


def _has_panic_injection() -> bool:
    if not native_engine_available():
        return False
    module = importlib.import_module("pirewall_native")
    flag: bool = module.HAS_PANIC_INJECTION
    return flag


needs_injection = pytest.mark.skipif(
    not _has_panic_injection(), reason="pirewall_native not built with the panic-injection feature"
)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class PanickyNative(NativeFlowAggregator):
    """Stands in for the native engine; panics on the frames and calls it is told to."""

    def __init__(self) -> None:  # deliberately not calling super(): no extension needed
        self._inner = FlowAggregator(CONFIG, on_new_flow=lambda _signal: None, protected_network=PROTECTED)
        self._completed: list[Flow] = []
        self.panic_on_feed: set[int] = set()
        self.panic_drain = False
        self._fed = 0
        self._malformed = 0

    def feed_us(self, raw: bytes, ts_us: int) -> None:
        self._fed += 1
        if self._fed in self.panic_on_feed:
            raise NativeEngineError(f"native engine panicked in feed: frame {self._fed}")
        try:
            packet = parse_packet(raw, from_microseconds(ts_us))
        except PacketParseError:
            self._malformed += 1
            return
        self._completed.extend(self._inner.process_packet(packet))

    def drain(self) -> NativeBatch:
        if self.panic_drain:
            raise NativeEngineError("native engine panicked in drain")
        out, self._completed = self._completed, []
        return NativeBatch(out, [], [])

    def flush(self) -> list[Flow]:
        return self._inner.flush()

    def counters(self) -> tuple[int, int]:
        return self._fed, self._malformed

    def panic_stats(self) -> tuple[int, int]:
        return len(self.panic_on_feed), 0


def _session(sport: int, at: int) -> list[tuple[bytes, int]]:
    c, s = "192.168.100.5", "203.0.113.7"
    return [
        (tcp(c, s, sport, 80, SYN), at),
        (tcp(s, c, 80, sport, SYN | ACK), at + 1),
        (tcp(c, s, sport, 80, FIN | ACK), at + 2),
        (tcp(s, c, 80, sport, FIN | ACK), at + 3),
    ]


def test_the_budget_counts_within_a_trailing_minute_and_stays_exhausted() -> None:
    clock = Clock()
    budget = NativePanicBudget(3, clock)
    assert [budget.record() for _ in range(2)] == [False, False]
    clock.now = 61.0  # both have aged out
    assert budget.record() is False
    clock.now = 70.0
    assert budget.record() is False
    assert budget.record() is True  # three within 60 s
    clock.now = 500.0
    assert budget.record() is True  # sticky
    assert budget.total == 6
    with pytest.raises(ValueError):
        NativePanicBudget(0)


def test_native_engine_error_is_a_capture_error() -> None:
    assert issubclass(NativeEngineError, CaptureError)


def test_a_panic_drops_one_frame_reports_it_and_carries_on() -> None:
    events: list[SecurityEvent] = []
    native = PanickyNative()
    native.panic_on_feed = {2}
    engine = FallbackFlowEngine(
        CONFIG, PROTECTED, max_panics_per_minute=5, on_event=events.append, native=native, clock=Clock()
    )
    for raw, ts in _session(40000, T0_US) + _session(40001, T0_US + 10):
        engine.feed_us(raw, ts)
    assert engine.backend == "native"
    completed = engine.drain().completed
    # The first session lost its SYN|ACK but still completed; the second is whole.
    assert [f.packet_count for f in completed] == [3, 4]
    assert len(events) == 1
    assert events[0].event_type is SecurityEventType.CAPTURE_ERROR
    assert events[0].severity is EventSeverity.WARNING
    assert "frame was dropped" in str(events[0].reason)


def test_too_many_panics_in_a_minute_fall_back_to_python_salvaging_open_flows() -> None:
    events: list[SecurityEvent] = []
    native = PanickyNative()
    frames = mixed_stream(seed=11, sessions=200)
    native.panic_on_feed = {100, 101, 102}
    engine = FallbackFlowEngine(
        CONFIG, PROTECTED, max_panics_per_minute=3, on_event=events.append, native=native, clock=Clock()
    )
    completed: list[Flow] = []
    for index, (raw, ts) in enumerate(frames, start=1):
        engine.feed_us(raw, ts)
        if index == 101:
            assert engine.backend == "native"
        if index % 50 == 0:
            completed.extend(engine.drain().completed)
    completed.extend(engine.drain().completed)
    completed.extend(engine.flush())
    assert engine.backend == "python"
    assert [e.severity for e in events] == [EventSeverity.WARNING] * 3 + [EventSeverity.CRITICAL]
    assert "falling back to the Python flow path" in str(events[-1].reason)
    assert engine.budget.exhausted
    # Every frame was counted by one path or the other.
    assert engine.counters()[0] == len(frames)
    assert len(completed) > 50
    # Every completed flow is a real, extractable record (nothing torn).
    assert all(f.payload_stats is not None for f in completed)


def test_a_panicking_drain_loses_that_batch_and_is_counted() -> None:
    events: list[SecurityEvent] = []
    native = PanickyNative()
    engine = FallbackFlowEngine(CONFIG, PROTECTED, on_event=events.append, native=native, clock=Clock())
    for raw, ts in _session(40000, T0_US):
        engine.feed_us(raw, ts)
    native.panic_drain = True
    assert engine.drain().completed == []
    assert engine.batches_lost_to_panics == 1
    assert "batch of output was lost" in str(events[0].reason)


def test_without_the_extension_or_by_request_it_runs_the_python_path() -> None:
    engine = FallbackFlowEngine(CONFIG, PROTECTED, prefer_native=False)
    assert engine.backend == "python"
    for raw, ts in _session(40000, T0_US):
        engine.feed_us(raw, ts)
    batch = engine.drain()
    assert [f.packet_count for f in batch.completed] == [4]
    assert len(batch.new_flows) == 1
    assert engine.counters() == (4, 0)


# ------------------------------------------------------- the real engine, panicking in Rust


@needs_injection
def test_a_real_rust_panic_surfaces_as_native_engine_error_and_the_engine_recovers() -> None:
    native = NativeFlowAggregator(CONFIG, PROTECTED)
    for raw, ts in _session(40000, T0_US)[:2]:
        native.feed_us(raw, ts)
    assert len(native) == 1
    native.engine._arm_test_panic("feed", 1)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(NativeEngineError, match="injected test panic"):
        native.feed_us(*_session(40001, T0_US + 5)[0])
    # The panic poisoned the engine lock mid-feed; the next call recovers it
    # by discarding the (possibly torn) table, and counts what that cost.
    assert len(native) == 0
    assert native.panic_stats() == (1, 1)
    native.engine._arm_test_panic("drain", 1)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(NativeEngineError, match="in drain"):
        native.drain()
    native.engine._arm_test_panic("sweep", 1)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(NativeEngineError, match="in sweep"):
        native.sweep_timeouts(datetime.now().astimezone())
    for raw, ts in _session(40002, T0_US + 10):
        native.feed_us(raw, ts)
    assert [f.packet_count for f in native.drain().completed] == [4]
    assert native.panic_stats()[0] == 3


@needs_injection
def test_real_rust_panics_drive_the_fallback_to_python() -> None:
    events: list[SecurityEvent] = []
    native = NativeFlowAggregator(CONFIG, PROTECTED)
    engine = FallbackFlowEngine(
        CONFIG, PROTECTED, max_panics_per_minute=2, on_event=events.append, native=native, clock=Clock()
    )
    frames = mixed_stream(seed=12, sessions=100)
    native.engine._arm_test_panic("feed", 2)  # pyright: ignore[reportPrivateUsage]
    for raw, ts in frames:
        engine.feed_us(raw, ts)
    assert engine.backend == "python"
    assert [e.severity for e in events] == [
        EventSeverity.WARNING,
        EventSeverity.WARNING,
        EventSeverity.CRITICAL,
    ]
    assert engine.counters()[0] == len(frames)
    completed = engine.drain().completed + engine.flush()
    assert len(completed) > 20

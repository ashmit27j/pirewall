"""`capture.backend = "replay"`: pcaps through the live flow path, no root, no NIC (ADDENDUM_4.md D7).

Two captures, one per path `pirewall-core` already runs:

* `ReplayCapture` is a `FlowCapture`. Its `poll` feeds frames into a frame
  sink, normally the same `NativeFlowAggregator` (and so the same Rust
  `FlowEngine.feed`) that live capture feeds from the kernel ring. Core
  drains that aggregator exactly as it drains a live one.
* `ReplayPacketCapture` is a `PacketCapture`, for when the extension is not
  built: it yields `CapturedPacket`s for the Python parse/aggregate loop.

`build_replay_capture(config)` picks between them the way `CoreDaemon`'s
capture selection picks between the live paths, and returns the same
`(capture, native_aggregator | None)` pair, so core can run a replay by
injection today; selecting it from `capture.backend` is phase 16's.

**Speed** (`capture.replay_speed`): `"max"` feeds as fast as the sink takes
frames; `"realtime"` and `"<N>x"` pace delivery on the wall clock by the
gaps between capture timestamps (divided by N). Pacing never changes the
timestamps themselves, so every flow statistic is the same at every speed:
the replay runs on a *virtual clock*, the capture's own (`virtual_now_us`).

**Rebasing.** `rebase_to` shifts every timestamp by one constant (so the
first frame lands at `rebase_to`), which keeps every gap, and so every
feature, bit-identical. Core selects a config replay rebased to "now", so
its timestamps — and the rule expiry derived from them — sit in the
present; it then sweeps and evaluates on the virtual clock, which at
`"max"` speed runs ahead of the wall clock. Offline tools
(`scripts/dataset/pcap_to_flows.py`) do not rebase and sweep on the
virtual clock instead.

A directory is replayed as one continuous capture, its files in name order.
"""

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from pirewall.capture.interfaces import CapturedPacket
from pirewall.capture.pcapio import PcapReader, PcapStats, capture_files
from pirewall.config.models import PirewallConfig
from pirewall.core.exceptions import CaptureError, ConfigurationError
from pirewall.core.models.capture_stats import CaptureStatistics
from pirewall.flow.native import (
    NativeFlowAggregator,
    from_microseconds,
    native_engine_available,
    to_microseconds,
)

REPLAY_INTERFACE = "replay"
# Frames fed per `poll` at "max" speed before control returns to the caller
# to drain: the same role as the native ring's per-poll packet cap.
_MAX_FRAMES_PER_POLL = 5_000


class FrameSink(Protocol):
    """Where `ReplayCapture` feeds frames: `NativeFlowAggregator` or `FallbackFlowEngine`."""

    def feed_us(self, raw: bytes, ts_us: int) -> None:
        """Parse and aggregate one frame captured at `ts_us` (Unix microseconds)."""
        ...

    def counters(self) -> tuple[int, int]:
        """`(frames seen, frames malformed or unsupported)`, cumulative."""
        ...


def parse_replay_speed(text: str) -> float | None:
    """`"max"` -> None (unpaced); `"realtime"` -> 1.0; `"<N>x"` -> N (must be positive)."""
    if text == "max":
        return None
    if text == "realtime":
        return 1.0
    if text.endswith("x"):
        try:
            factor = float(text[:-1])
        except ValueError:
            factor = 0.0
        if factor > 0:
            return factor
    raise ConfigurationError(f'replay speed must be "max", "realtime" or "<N>x" with N > 0, not {text!r}')


@dataclass(frozen=True, slots=True)
class ReplayFrame:
    """One frame due for delivery: its bytes and its (possibly rebased) capture time."""

    data: bytes
    ts_us: int


class _PacedFrames:
    """Frames of every capture file under `source`, rebased, with wall-clock due times."""

    def __init__(
        self,
        source: Path | str,
        speed: float | None,
        rebase_to_us: int | None,
        clock: Callable[[], float],
    ) -> None:
        self.files = capture_files(source)
        self.stats: list[tuple[Path, PcapStats]] = []
        self._speed = speed
        self._rebase_to_us = rebase_to_us
        self._clock = clock
        self._frames = self._iterate()
        self._lookahead: ReplayFrame | None = None
        self._offset_us: int | None = None
        self._wall_start = 0.0
        self._virtual_start_us = 0
        self.exhausted = False

    def _iterate(self) -> Iterator[ReplayFrame]:
        for path in self.files:
            reader = PcapReader(path)
            self.stats.append((path, reader.stats))
            for record in reader:
                if self._offset_us is None:
                    self._offset_us = (
                        0 if self._rebase_to_us is None else self._rebase_to_us - record.ts_us
                    )
                    self._wall_start = self._clock()
                    self._virtual_start_us = record.ts_us + self._offset_us
                yield ReplayFrame(record.data, record.ts_us + self._offset_us)

    def peek(self) -> ReplayFrame | None:
        """The next frame, without consuming it; None once every file is read."""
        if self._lookahead is None and not self.exhausted:
            self._lookahead = next(self._frames, None)
            self.exhausted = self._lookahead is None
        return self._lookahead

    def take(self) -> ReplayFrame:
        frame = self.peek()
        assert frame is not None
        self._lookahead = None
        return frame

    def seconds_until_due(self, frame: ReplayFrame) -> float:
        """How long the wall clock must still advance before `frame` is due (<= 0: due now)."""
        if self._speed is None:
            return 0.0
        virtual_elapsed = (frame.ts_us - self._virtual_start_us) / 1e6
        return self._wall_start + virtual_elapsed / self._speed - self._clock()


class ReplayCapture:
    """`FlowCapture` that feeds capture files into a frame sink, on a virtual clock.

    `poll(timeout_ms)` feeds every frame that is due within `timeout_ms`
    (at most a few thousand per call), sleeping until the first one is due
    if necessary, and returns how many it fed. Once every file is read it
    behaves like an idle interface: it waits `timeout_ms` and returns 0;
    `finished` says so. Errors from the sink (`NativeEngineError` from a
    bare `NativeFlowAggregator`) propagate; feed through a
    `FallbackFlowEngine` to survive them.
    """

    def __init__(
        self,
        source: Path | str,
        sink: FrameSink,
        speed: str = "max",
        rebase_to: datetime | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._source = source
        self._sink = sink
        self._speed = parse_replay_speed(speed)
        self._rebase_to_us = None if rebase_to is None else to_microseconds(rebase_to)
        self._clock = clock
        self._sleep = sleep
        self._frames: _PacedFrames | None = None
        self._stopped = False
        self._virtual_now_us: int | None = None

    def start(self) -> None:
        """Open the capture file(s). Raises `CaptureError` if there are none or one is unreadable."""
        if self._frames is not None:
            return
        try:
            self._frames = _PacedFrames(self._source, self._speed, self._rebase_to_us, self._clock)
        except OSError as exc:
            raise CaptureError(f"cannot open replay source {self._source}: {exc}") from exc
        self._stopped = False

    def stop(self) -> None:
        """Stop feeding. Idempotent; later polls return 0."""
        self._stopped = True

    def poll(self, timeout_ms: int) -> int:
        """Feed every frame due within `timeout_ms`; 0 on timeout, once stopped, or once finished."""
        frames = self._frames
        if frames is None or self._stopped:
            return 0
        timeout = max(timeout_ms, 0) / 1000.0
        frame = self._peek(frames)
        if frame is None:
            self._sleep(timeout)
            return 0
        wait = frames.seconds_until_due(frame)
        if wait > timeout:
            self._sleep(timeout)
            return 0
        if wait > 0:
            self._sleep(wait)
        fed = 0
        while fed < _MAX_FRAMES_PER_POLL and not self._stopped:
            frame = self._peek(frames)
            if frame is None or frames.seconds_until_due(frame) > 0:
                break
            frames.take()
            self._virtual_now_us = frame.ts_us
            self._sink.feed_us(frame.data, frame.ts_us)
            fed += 1
        return fed

    def _peek(self, frames: _PacedFrames) -> ReplayFrame | None:
        try:
            return frames.peek()
        except OSError as exc:
            raise CaptureError(f"error reading replay source {self._source}: {exc}") from exc

    @property
    def finished(self) -> bool:
        """True once every frame of every file has been fed."""
        return self._frames is not None and self._frames.exhausted

    @property
    def virtual_now_us(self) -> int | None:
        """The capture time of the last frame fed (the replay's clock); None before the first."""
        return self._virtual_now_us

    @property
    def pcap_stats(self) -> list[tuple[Path, PcapStats]]:
        """Per file opened so far, what its reader skipped or found truncated."""
        return [] if self._frames is None else list(self._frames.stats)

    def statistics(self) -> CaptureStatistics:
        """Seen/malformed from the sink; a replay never drops."""
        seen, malformed = self._sink.counters()
        return CaptureStatistics(
            interface=REPLAY_INTERFACE, packets_seen=seen, packets_dropped=0, packets_malformed=malformed
        )


class ReplayPacketCapture:
    """`PacketCapture` over capture files, for the Python path (no native extension).

    Same pacing, rebasing and file order as `ReplayCapture`; `read_packets`
    ends when every file is read or `stop()` is called.
    """

    def __init__(
        self,
        source: Path | str,
        speed: str = "max",
        rebase_to: datetime | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._source = source
        self._speed = parse_replay_speed(speed)
        self._rebase_to_us = None if rebase_to is None else to_microseconds(rebase_to)
        self._clock = clock
        self._sleep = sleep
        self._running = False
        self._seen = 0
        self._malformed = 0

    def start(self) -> None:
        """Check the source exists. Raises `CaptureError` if it has no capture files."""
        capture_files(self._source)
        self._running = True

    def stop(self) -> None:
        """Stop yielding. Idempotent."""
        self._running = False

    def read_packets(self) -> Iterator[CapturedPacket]:
        """Yield every frame, paced, as a `CapturedPacket` stamped with its capture time."""
        if not self._running:
            raise CaptureError("cannot read packets before start() is called")
        frames = _PacedFrames(self._source, self._speed, self._rebase_to_us, self._clock)
        while self._running:
            frame = frames.peek()
            if frame is None:
                return
            wait = frames.seconds_until_due(frame)
            if wait > 0:
                self._sleep(wait)
            frames.take()
            self._seen += 1
            yield CapturedPacket(raw=frame.data, captured_at=from_microseconds(frame.ts_us))

    def record_malformed(self) -> None:
        self._malformed += 1

    def statistics(self) -> CaptureStatistics:
        return CaptureStatistics(
            interface=REPLAY_INTERFACE,
            packets_seen=self._seen,
            packets_dropped=0,
            packets_malformed=self._malformed,
        )


def build_replay_capture(
    config: PirewallConfig, rebase_to: datetime | None = None
) -> tuple[ReplayCapture | ReplayPacketCapture, NativeFlowAggregator | None]:
    """The replay counterpart of `CoreDaemon`'s capture selection.

    Native when the extension is importable (a `ReplayCapture` feeding a
    `NativeFlowAggregator` built exactly as core builds the live one), else
    a `ReplayPacketCapture` for the Python loop. Pass the pair to
    `CoreDaemon(config, capture=..., native_aggregator=...)`. Needs
    `capture.replay_path`.
    """
    source = config.capture.replay_path
    if source is None:
        raise ConfigurationError('capture.backend = "replay" needs capture.replay_path')
    speed = config.capture.replay_speed
    if native_engine_available():
        aggregator = NativeFlowAggregator(
            config.flow,
            config.network.protected_network,
            max_pending_completed=config.capture.native_max_flows_per_drain,
            max_pending_new_flows=config.capture.native_max_new_flows_per_drain,
        )
        return ReplayCapture(source, aggregator, speed=speed, rebase_to=rebase_to), aggregator
    return ReplayPacketCapture(source, speed=speed, rebase_to=rebase_to), None

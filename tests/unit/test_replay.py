"""`capture.backend = "replay"`: pcaps through the live flow path (ADDENDUM_4.md D7)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from pirewall.capture.interfaces import FlowCapture, PacketCapture
from pirewall.capture.pcapio import PcapWriter
from pirewall.capture.pipeline import capture_packets
from pirewall.capture.replay import (
    ReplayCapture,
    ReplayPacketCapture,
    build_replay_capture,
    parse_replay_speed,
)
from pirewall.config.models import FlowConfig
from pirewall.core.exceptions import CaptureError, ConfigurationError
from pirewall.core.models.flow import Flow
from pirewall.flow.aggregator import FlowAggregator
from pirewall.flow.native import NativeFlowAggregator, native_engine_available, to_microseconds
from tests.helpers.config import make_config
from tests.helpers.traffic import T0_US, mixed_stream

CONFIG = FlowConfig(active_timeout_seconds=120, inactive_timeout_seconds=60, max_flows=64)
needs_native = pytest.mark.skipif(not native_engine_available(), reason="pirewall_native not built")


class FakeClock:
    """A wall clock that only moves when something sleeps."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


class RecordingSink:
    """A `FrameSink` that remembers what it was fed."""

    def __init__(self) -> None:
        self.fed: list[tuple[bytes, int]] = []

    def feed_us(self, raw: bytes, ts_us: int) -> None:
        self.fed.append((raw, ts_us))

    def counters(self) -> tuple[int, int]:
        return len(self.fed), 0


def _pcap(path: Path, frames: list[tuple[bytes, int]]) -> Path:
    with PcapWriter(path) as writer:
        for data, ts_us in frames:
            writer.write(data, ts_us)
    return path


def _drain_all(capture: ReplayCapture) -> int:
    total = 0
    while not capture.finished:
        total += capture.poll(10)
    return total


def _comparable(flows: list[Flow]) -> list[dict[str, object]]:
    return [flow.model_dump(exclude={"flow_id"}) for flow in flows]


@pytest.mark.parametrize(("text", "factor"), [("max", None), ("realtime", 1.0), ("10x", 10.0), ("0.5x", 0.5)])
def test_replay_speeds_parse(text: str, factor: float | None) -> None:
    assert parse_replay_speed(text) == factor


@pytest.mark.parametrize("text", ["fast", "0x", "x", "-2x", ""])
def test_bad_replay_speeds_are_refused(text: str) -> None:
    with pytest.raises(ConfigurationError):
        parse_replay_speed(text)


def test_replay_capture_satisfies_flow_capture_and_not_packet_capture(tmp_path: Path) -> None:
    capture = ReplayCapture(_pcap(tmp_path / "a.pcap", []), RecordingSink())
    assert isinstance(capture, FlowCapture)
    assert not isinstance(capture, PacketCapture)
    packet_capture = ReplayPacketCapture(tmp_path / "a.pcap")
    assert isinstance(packet_capture, PacketCapture)
    assert not isinstance(packet_capture, FlowCapture)


def test_max_speed_feeds_every_frame_in_order_without_sleeping(tmp_path: Path) -> None:
    frames = mixed_stream(seed=3, sessions=50)
    clock = FakeClock()
    sink = RecordingSink()
    capture = ReplayCapture(_pcap(tmp_path / "s.pcap", frames), sink, clock=clock, sleep=clock.sleep)
    capture.start()
    assert _drain_all(capture) == len(frames)
    assert sink.fed == frames
    assert capture.virtual_now_us == frames[-1][1]
    assert clock.slept == []
    assert capture.poll(25) == 0  # finished: behaves like an idle interface
    assert clock.slept == [0.025]
    assert capture.statistics().packets_seen == len(frames)


def test_a_directory_replays_as_one_capture_in_name_order(tmp_path: Path) -> None:
    frames = mixed_stream(seed=4, sessions=40)
    half = len(frames) // 2
    _pcap(tmp_path / "02.pcap", frames[half:])
    _pcap(tmp_path / "01.pcap", frames[:half])
    sink = RecordingSink()
    capture = ReplayCapture(tmp_path, sink)
    capture.start()
    _drain_all(capture)
    assert sink.fed == frames
    assert [path.name for path, _ in capture.pcap_stats] == ["01.pcap", "02.pcap"]


def test_realtime_and_multiplied_speeds_pace_on_the_wall_clock(tmp_path: Path) -> None:
    frames = [(b"x" * 60, T0_US), (b"y" * 60, T0_US + 2_000_000), (b"z" * 60, T0_US + 2_500_000)]
    for speed, gaps in (("realtime", [2.0, 0.5]), ("4x", [0.5, 0.125])):
        clock = FakeClock()
        sink = RecordingSink()
        capture = ReplayCapture(
            _pcap(tmp_path / f"{speed}.pcap", frames), sink, speed=speed, clock=clock, sleep=clock.sleep
        )
        capture.start()
        assert capture.poll(100) == 1  # the first frame is due at once; the next is not
        start = clock.now
        while not capture.finished:
            capture.poll(5_000)
        assert sink.fed == frames  # pacing never touches the timestamps
        assert clock.now - start == pytest.approx(sum(gaps))


def test_a_poll_shorter_than_the_next_gap_waits_its_timeout_and_feeds_nothing(tmp_path: Path) -> None:
    frames = [(b"x" * 60, T0_US), (b"y" * 60, T0_US + 10_000_000)]
    clock = FakeClock()
    capture = ReplayCapture(
        _pcap(tmp_path / "gap.pcap", frames),
        RecordingSink(),
        speed="realtime",
        clock=clock,
        sleep=clock.sleep,
    )
    capture.start()
    assert capture.poll(50) == 1
    assert capture.poll(50) == 0
    assert clock.slept == [0.05]


def test_rebasing_shifts_every_timestamp_by_one_constant(tmp_path: Path) -> None:
    frames = mixed_stream(seed=5, sessions=30)
    now = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)
    sink = RecordingSink()
    capture = ReplayCapture(_pcap(tmp_path / "r.pcap", frames), sink, rebase_to=now)
    capture.start()
    _drain_all(capture)
    shift = to_microseconds(now) - frames[0][1]
    assert sink.fed == [(data, ts + shift) for data, ts in frames]


def test_stop_halts_feeding_and_a_missing_source_fails_start(tmp_path: Path) -> None:
    sink = RecordingSink()
    capture = ReplayCapture(_pcap(tmp_path / "s.pcap", mixed_stream(seed=6, sessions=10)), sink)
    capture.start()
    capture.stop()
    assert capture.poll(10) == 0
    assert sink.fed == []
    with pytest.raises(CaptureError):
        ReplayCapture(tmp_path / "nope.pcap", sink).start()
    with pytest.raises(CaptureError):
        ReplayPacketCapture(tmp_path / "nope.pcap").start()


def _python_flows(source: Path) -> list[Flow]:
    capture = ReplayPacketCapture(source)
    capture.start()
    aggregator = FlowAggregator(CONFIG)
    completed: list[Flow] = []
    for packet in capture_packets(capture):
        completed.extend(aggregator.process_packet(packet))
    return completed + aggregator.flush()


def test_the_python_replay_is_deterministic(tmp_path: Path) -> None:
    source = _pcap(tmp_path / "d.pcap", mixed_stream(seed=8))
    first, second = _python_flows(source), _python_flows(source)
    assert len(first) > 50
    assert _comparable(first) == _comparable(second)


def _native_flows(source: Path) -> list[Flow]:
    aggregator = NativeFlowAggregator(CONFIG)
    capture = ReplayCapture(source, aggregator)
    capture.start()
    completed: list[Flow] = []
    while not capture.finished:
        capture.poll(10)
        completed.extend(aggregator.drain().completed)
    return completed + aggregator.flush()


@needs_native
def test_the_native_replay_is_deterministic_and_matches_the_python_replay(tmp_path: Path) -> None:
    source = _pcap(tmp_path / "d.pcap", mixed_stream(seed=8))
    first, second = _native_flows(source), _native_flows(source)
    assert _comparable(first) == _comparable(second)
    assert _comparable(first) == _comparable(_python_flows(source))


def test_build_replay_capture_picks_the_path_core_would(tmp_path: Path) -> None:
    source = _pcap(tmp_path / "b.pcap", mixed_stream(seed=9, sessions=10))
    config = make_config(capture={"interface": "eth0", "backend": "replay", "replay_path": str(source)})
    capture, aggregator = build_replay_capture(config)
    if native_engine_available():
        assert isinstance(capture, ReplayCapture)
        assert isinstance(aggregator, NativeFlowAggregator)
    else:
        assert isinstance(capture, ReplayPacketCapture)
        assert aggregator is None
    with pytest.raises(ConfigurationError):
        build_replay_capture(make_config())

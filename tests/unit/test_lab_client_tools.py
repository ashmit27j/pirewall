"""Phase 18 client-side and Pi-side helpers against fakes: background.py, preflight.py, replay.py."""

import io
import json
import random
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from lab.benign.background import Context, probe, run_profile, segments
from lab.common import LabError
from lab.manifest import Json, read_manifest
from lab.mock.replay import GroundTruth, Timing, replay, summarise
from lab.preflight import Outcome, Preflight, chrony_offset_seconds
from lab.verify_manifest import verify_tree


@dataclass(slots=True)
class FakeNet:
    """Every call succeeds instantly; counts what was asked."""

    calls: list[str] = field(default_factory=list[str])

    def fetch(self, url: str, limit_bytes: int | None, deadline: float) -> int:
        self.calls.append(f"fetch {url}")
        return 1000

    def resolve(self, name: str) -> bool:
        self.calls.append(f"resolve {name}")
        return True

    def ntp(self, server: str) -> bool:
        self.calls.append("ntp")
        return True

    def iperf(self, server: str, seconds: float) -> float | None:
        self.calls.append(f"iperf {server}")
        return 93.5


@dataclass(slots=True)
class FakeTime:
    now: float = 1_800_000_000.0

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(seconds, 0.01)


def _context(net: FakeNet, time: FakeTime, victim: str | None = "10.250.0.2") -> Context:
    def tick() -> float:
        time.now += 0.5  # every look at the clock costs time, so loops always end
        return time.now

    return Context(
        net,
        random.Random(1),
        ["a.example", "b.example"],
        "https://dl.example/big",
        victim,
        clock=time.clock,
        monotonic=tick,
        sleep=time.sleep,
    )


def test_mixed_cycles_the_profiles_one_segment_each() -> None:
    plan = segments("mixed", 1000.0, 300.0)
    assert [name for name, _ in plan] == ["web", "dns-burst", "video", "idle"]
    assert [seconds for _, seconds in plan] == [300.0, 300.0, 300.0, 100.0]


def test_each_segment_writes_one_benign_ground_truth_window() -> None:
    net, time = FakeNet(), FakeTime()
    truth = io.StringIO()
    windows = run_profile(_context(net, time), "mixed", 120.0, 20.0, "02:00:00:00:c0:01", "laptop", truth)
    lines = [json.loads(line) for line in truth.getvalue().splitlines()]
    assert windows == len(lines) == 6
    assert [line["label"] for line in lines] == [
        "benign:web",
        "benign:dns-burst",
        "benign:video",
        "benign:idle",
        "benign:update",
        "benign:iperf",
    ]
    assert all(line["mac"] == "02:00:00:00:c0:01" and line["end"] >= line["start"] for line in lines)
    assert any(call.startswith("iperf") for call in net.calls)


def test_the_probe_writes_samples_the_scorer_reads() -> None:
    net, time = FakeNet(), FakeTime()
    out = io.StringIO()
    written = probe(_context(net, time), "wired", out, seconds=5.0)
    samples = [json.loads(line) for line in out.getvalue().splitlines()]
    assert written == len(samples) > 0
    assert {sample["kind"] for sample in samples} == {"http_ms", "throughput_mbps"}
    assert all(sample["client"] == "wired" for sample in samples)


def test_chrony_offsets_are_signed() -> None:
    assert chrony_offset_seconds("System time     : 0.000120 seconds fast of NTP time\n") == pytest.approx(
        0.00012
    )
    assert chrony_offset_seconds("System time : 0.5 seconds slow of NTP time") == pytest.approx(-0.5)
    assert chrony_offset_seconds("garbage") is None


@dataclass(slots=True)
class EmptyCore:
    live: bool = False

    def rules(self) -> list[dict[str, Json]]:
        return [{"action": "rate_limit", "status": "active"}] if self.live else []

    def events(self) -> list[dict[str, Json]]:
        return []

    def offenders(self) -> list[dict[str, Json]]:
        return []

    def bindings(self) -> int:
        return 0

    def guard_modes(self) -> dict[str, Json]:
        return {}

    def engine(self) -> dict[str, Json]:
        return {}


def test_preflight_reports_every_check(tmp_path: Path) -> None:
    replies = {
        "bash": Outcome(0, "preflight passed"),
        "ip": Outcome(0, "labvictim (id: 0)\n"),
        "chronyc": Outcome(0, "System time : 0.001 seconds fast of NTP time\n"),
        "ssh": Outcome(0, "System time : 0.2 seconds slow of NTP time\n"),
    }
    check = Preflight(
        tmp_path / "c.toml",
        "live",
        ["kali@lab"],
        50.0,
        tmp_path,
        1.0,
        run=lambda argv: replies[argv[0]],
        core=lambda: EmptyCore(live=True),
        free_bytes=lambda path: 5 * 10**9,
    )
    check.pirewall_start()
    check.victim("labvictim")
    check.clocks()
    check.thresholds("config/d1_thresholds.toml", False, "a" * 64)
    check.sets()
    check.disk()
    results = {item.name: item.ok for item in check.checks}
    assert results == {
        "pirewall-start --check": True,
        "lab victim": True,
        "clock local": True,
        "clock kali@lab": False,
        "D1 thresholds": True,
        "adaptive sets empty": False,
        "disk": True,
    }
    assert not check.ok
    assert check.offsets == {"local": pytest.approx(0.001), "kali@lab": pytest.approx(-0.2)}


def test_the_replay_summary_matches_decisions_to_ground_truth() -> None:
    truth = GroundTruth(
        {"02:00:00:00:a0:01": "syn_flood_fixed", "02:00:00:00:a0:02": "masscan_like"},
        {"192.0.2.100": "02:00:00:00:a0:01"},
    )
    events: list[dict[str, Json]] = [
        {"decision": "rate_limit", "mac": None, "source": "192.0.2.100"},
        {"decision": "block", "mac": "02:00:00:00:A0:01", "source": "192.0.2.100"},
        {"decision": "monitor", "mac": "02:00:00:00:b0:01"},
        {"decision": "allow", "mac": "02:00:00:00:b0:02"},
    ]
    summary = summarise(events, truth)
    assert summary["attack_labels_flagged"] == ["syn_flood_fixed"]
    assert summary["attack_labels_missed"] == ["masscan_like"]
    assert summary["benign_devices_flagged"] == ["02:00:00:00:b0:01"]


@dataclass(slots=True)
class FakeLaunched:
    alive: bool = True

    def running(self) -> bool:
        return self.alive

    def stop(self) -> None:
        self.alive = False


@dataclass(slots=True)
class FakeLauncher:
    up: bool = True
    configs: list[Path | None] = field(default_factory=list[Path | None])

    def start(self, pcap: Path, run_dir: Path, config: Path | None) -> FakeLaunched:
        self.configs.append(config)
        run_dir.mkdir(parents=True)
        if self.up:
            (run_dir / "up").touch()
        (run_dir / "core.out").write_text("core log\n", encoding="utf-8")
        return FakeLaunched(alive=self.up)


@dataclass(slots=True)
class DrainingCore(EmptyCore):
    """frames_seen grows for three polls, then stays put."""

    polls: int = 0

    def engine(self) -> dict[str, Json]:
        self.polls += 1
        return {"frames_seen": min(self.polls, 3) * 1000}

    def events(self) -> list[dict[str, Json]]:
        return [
            {"id": "e1", "decision": "block", "mac": "02:00:00:00:a0:01", "timestamp": "2026-01-01T00:00:00"}
        ]


def test_replay_polls_until_drained_and_seals_a_mock_run(tmp_path: Path) -> None:
    pcaps = tmp_path / "pcaps"
    pcaps.mkdir()
    (pcaps / "00.pcap").write_bytes(b"")
    (pcaps / "ground_truth.jsonl").write_text(
        json.dumps({"mac": "02:00:00:00:a0:01", "label": "syn_flood_fixed", "start": 0, "end": 1}) + "\n",
        encoding="utf-8",
    )
    time = FakeTime()
    directory = replay(
        pcaps,
        tmp_path / "runs",
        None,
        FakeLauncher(),
        lambda socket: DrainingCore(),
        Timing(interval=1.0, settle=2.0, timeout=60.0),
        clock=time.clock,
        sleep=time.sleep,
    )
    document = read_manifest(directory)
    assert document["kind"] == "replay" and document["env_tag"] == "mock"
    extra = document["extra"]
    assert isinstance(extra, dict) and extra["drained"] is True and extra["frames_seen"] == 3000
    summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    assert summary["attack_labels_flagged"] == ["syn_flood_fixed"]
    assert (directory / "core.out").is_file()
    assert verify_tree(directory).ok


def test_replay_refuses_without_pcaps_or_when_core_never_comes_up(tmp_path: Path) -> None:
    with pytest.raises(LabError, match="gen_pcaps"):
        replay(tmp_path / "missing", tmp_path / "runs", None, FakeLauncher(), lambda socket: EmptyCore())
    (tmp_path / "p.pcap").write_bytes(b"")
    time = FakeTime()
    with pytest.raises(LabError, match="exited before it was up"):
        replay(
            tmp_path / "p.pcap",
            tmp_path / "runs",
            None,
            FakeLauncher(up=False),
            lambda socket: EmptyCore(),
            clock=time.clock,
            sleep=time.sleep,
        )

"""Replay the mock pcaps through a real pirewall-core and record what it decided (ADDENDUM_4.md D7 `mock`).

    uv run python lab/mock/gen_pcaps.py --seed 1          # once
    uv run python lab/mock/replay.py [--pcap lab/mock/out] [--engine v2] [--config FILE] \\
        [--out lab/runs] [--settle 5] [--timeout 900] [--interval 1]

A thin driver around `scripts/deployment/pirewall-start --data-mode mock
--pcap <dir>`: core replays the capture at `replay_speed = "max"` (the
accelerated clock: every gap keeps its length in capture time, and the
replay runs as fast as core takes frames) against in-memory firewall
fakes, with no root and no nft. This script:

1. starts it in a throwaway run directory and waits for its `up` marker;
2. polls core read-only over its RPC socket (`lab/poll_state.py`) into
   `polls.jsonl` until `engine.frames_seen` has not moved for `--settle`
   seconds (the replay is drained), or `--timeout`. Events are collected
   from every poll rather than read once at the end, because core keeps a
   bounded history (`api.history_size`); more events than that between two
   polls would still be lost, so poll faster (`--interval`) for big replays;
3. writes the final `rules.json` and `offenders.json`, every event
   (`events.jsonl`), a `summary.json` of decisions per device with each
   device's ground-truth label (`ground_truth.jsonl` of the pcap directory,
   copied in), and core's log;
4. stops pirewall-start (SIGINT, as Ctrl-C) and seals the run directory:
   `kind = "replay"`, env tag `mock`, always.

**`--engine`**: `pirewall-start --data-mode mock` builds core's config from
`--config` and does not apply its own `--engine` to it, so this script
writes a copy of the config with `pipeline.engine` set and passes that.

**Not a benign-FP measurement.** At `max` speed core's wall-clock D1
windows each see far more than their span of capture time, so benign
devices can draw decisions that a real-time replay does not produce
(lab/README.md). Use it as a pipeline regression check; use
`lab/benign_fp.py` (capture time) for false positives.

The replay rebases capture timestamps to "now", so decisions are matched to
the ground truth by device: the event's MAC (v2), else its source IP
through the ground truth's attacker IPs (v1 events carry no MAC).
"""

import argparse
import json
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # `python lab/mock/replay.py`

from lab.common import REPO_ROOT, LabError, new_run_dir
from lab.manifest import (
    MANIFEST_NAME,
    Json,
    Manifest,
    ManifestError,
    git_state,
    read_manifest,
    write_manifest,
)
from lab.poll_state import CoreReader, Poller, ReadOnlyCore

TOOL: Final = "lab/mock/replay.py"
DEFAULT_PCAP: Final = REPO_ROOT / "lab" / "mock" / "out"
PIREWALL_START: Final = REPO_ROOT / "scripts" / "deployment" / "pirewall-start"
_ACTING: Final = ("monitor", "rate_limit", "block")


class Launched(Protocol):
    """A running pirewall-start."""

    def running(self) -> bool: ...
    def stop(self) -> None: ...


class Launcher(Protocol):
    """Starts pirewall-start in mock mode. `MockStart` does it; tests pass a fake."""

    def start(self, pcap: Path, run_dir: Path, config: Path | None) -> Launched: ...


@dataclass(slots=True)
class _Process:
    process: subprocess.Popen[bytes]

    def running(self) -> bool:
        return self.process.poll() is None

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


@dataclass(slots=True)
class MockStart:
    """`bash scripts/deployment/pirewall-start --data-mode mock --pcap ... --run-dir ... [--config ...]`."""

    log: Path

    def start(self, pcap: Path, run_dir: Path, config: Path | None) -> Launched:
        """Start it; output goes to `log`."""
        argv = ["bash", str(PIREWALL_START), "--data-mode", "mock", "--pcap", str(pcap)]
        argv += ["--run-dir", str(run_dir)]
        if config is not None:
            argv += ["--config", str(config)]
        with self.log.open("wb") as stream:
            return _Process(subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT, cwd=REPO_ROOT))


def engine_config(source: Path, engine: str, directory: Path) -> Path:
    """A copy of `source` with `pipeline.engine = engine`, written into `directory`. Raises `LabError`."""
    from scripts.deployment.startup import to_toml

    from pirewall.config.loader import load_config
    from pirewall.core.exceptions import ConfigurationError

    try:
        data = load_config(source).model_dump(mode="json")
        data["pipeline"]["engine"] = engine
        path = directory / "replay_config.toml"
        path.write_text(to_toml(data), encoding="utf-8")
        load_config(path)
    except ConfigurationError as exc:
        raise LabError(f"config {source}: {exc}") from exc
    return path


@dataclass(frozen=True, slots=True)
class Timing:
    """How long to wait for what."""

    interval: float = 1.0
    settle: float = 5.0
    timeout: float = 900.0
    startup: float = 120.0


DEFAULT_TIMING: Final = Timing()


@dataclass(slots=True)
class Drained:
    """What the polling saw."""

    frames: int = 0
    drained: bool = False
    events: dict[str, dict[str, Json]] = field(default_factory=dict[str, dict[str, Json]])


def _frames(record: dict[str, Json]) -> int | None:
    engine = record.get("engine")
    value = engine.get("frames_seen") if isinstance(engine, dict) else None
    return value if isinstance(value, int) else None


def wait_until_drained(
    poller: Poller,
    out: Path,
    timing: Timing,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    alive: Callable[[], bool],
) -> Drained:
    """Poll into `out` until frames_seen is stable for `settle` s, collecting every new event."""
    result = Drained()
    started = since = clock()
    last: int | None = None
    with out.open("w", encoding="utf-8", newline="\n") as stream:
        while clock() - started < timing.timeout and alive():
            record = poller.poll()
            stream.write(json.dumps(record, default=str) + "\n")
            events = record.get("events")
            for event in events if isinstance(events, list) else []:
                if isinstance(event, dict):
                    result.events[str(event.get("id"))] = event
            frames = _frames(record)
            now = clock()
            if frames is not None and frames != last:
                last, since = frames, now
            elif frames is not None and frames > 0 and now - since >= timing.settle:
                result.frames, result.drained = frames, True
                return result
            sleep(timing.interval)
    result.frames = last or 0
    return result


@dataclass(frozen=True, slots=True)
class GroundTruth:
    """Labels by MAC, and attacker IP -> MAC (for events without a MAC)."""

    labels: dict[str, str]
    macs_by_ip: dict[str, str]


def read_ground_truth(path: Path) -> GroundTruth:
    """From a `ground_truth.jsonl` (gen_pcaps.py format); empty when there is none."""
    labels: dict[str, str] = {}
    by_ip: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            mac = str(entry["mac"]).lower()
            labels[mac] = str(entry["label"])
            if isinstance(entry.get("ip"), str):
                by_ip[entry["ip"]] = mac
    return GroundTruth(labels, by_ip)


def summarise(events: Sequence[dict[str, Json]], truth: GroundTruth) -> dict[str, Json]:
    """Decisions per device (monitor / rate_limit / block), each with its ground-truth label or `benign`.

    A device is the event's MAC, else the MAC the ground truth gives its
    source IP, else `ip:<source>`.
    """
    per_device: dict[str, dict[str, int]] = {}
    for event in events:
        decision, mac, source = event.get("decision"), event.get("mac"), event.get("source")
        if decision not in _ACTING:
            continue
        if isinstance(mac, str):
            device = mac.lower()
        elif isinstance(source, str):
            device = truth.macs_by_ip.get(source, f"ip:{source}")
        else:
            continue
        counts = per_device.setdefault(device, dict.fromkeys(_ACTING, 0))
        counts[str(decision)] += 1
    by_device: dict[str, Json] = {
        device: {"label": truth.labels.get(device, "benign"), **counts}
        for device, counts in sorted(per_device.items())
    }
    flagged = set(per_device)
    attack = {mac for mac, label in truth.labels.items() if label != "benign"}
    return {
        "by_device": by_device,
        "attack_macs_flagged": len(attack & flagged),
        "attack_macs": len(attack),
        "attack_labels_flagged": list[Json](sorted({truth.labels[mac] for mac in attack & flagged})),
        "attack_labels_missed": list[Json](sorted({truth.labels[mac] for mac in attack - flagged})),
        "benign_devices_flagged": list[Json](sorted(flagged - attack)),
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, default=str) + "\n", encoding="utf-8", newline="\n")


def replay(
    pcap: Path,
    out_root: Path,
    config: Path | None,
    launcher: Launcher,
    reader: Callable[[Path], CoreReader],
    timing: Timing = DEFAULT_TIMING,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    engine: str | None = None,
) -> Path:
    """The whole replay. Returns the sealed run directory. Raises `LabError`."""
    if not pcap.exists():
        raise LabError(f"no pcaps at {pcap}; run lab/mock/gen_pcaps.py --seed 1 first")
    source: dict[str, Json] = {}
    if pcap.is_dir() and (pcap / MANIFEST_NAME).is_file():
        try:
            source = read_manifest(pcap)
        except ManifestError as exc:
            raise LabError(str(exc)) from exc
    directory = new_run_dir(out_root, "mock-replay")
    work = Path(tempfile.mkdtemp(prefix="pirewall-mock-"))
    launched = launcher.start(pcap, work / "run", config)
    seen = Drained()
    try:
        deadline = clock() + timing.startup
        while not (work / "run" / "up").exists():
            if not launched.running():
                raise LabError("pirewall-start exited before it was up")
            if clock() > deadline:
                raise LabError(f"pirewall-start was not up within {timing.startup:g}s")
            sleep(0.5)
        core = reader(work / "run" / "core.sock")
        seen = wait_until_drained(
            Poller(core, clock=time.time), directory / "polls.jsonl", timing, clock, sleep, launched.running
        )
        rules, offenders = core.rules(), core.offenders()
        for event in core.events():
            seen.events.setdefault(str(event.get("id")), event)
    finally:
        launched.stop()
        if (work / "run" / "core.out").is_file():
            shutil.copyfile(work / "run" / "core.out", directory / "core.out")
        shutil.rmtree(work, ignore_errors=True)
    events = sorted(seen.events.values(), key=lambda event: str(event.get("timestamp")))
    _write_json(directory / "rules.json", rules)
    _write_json(directory / "offenders.json", offenders)
    (directory / "events.jsonl").write_text(
        "".join(json.dumps(event, default=str) + "\n" for event in events), encoding="utf-8", newline="\n"
    )
    if pcap.is_dir() and (pcap / "ground_truth.jsonl").is_file():
        shutil.copyfile(pcap / "ground_truth.jsonl", directory / "ground_truth.jsonl")
    summary = summarise(events, read_ground_truth(directory / "ground_truth.jsonl"))
    _write_json(directory / "summary.json", summary)
    sha, dirty = git_state(REPO_ROOT)
    extra: dict[str, Json] = {
        "pcap": str(pcap),
        "source_manifest_env_tag": source.get("env_tag"),
        "source_extra": source.get("extra"),
        "frames_seen": seen.frames,
        "drained": seen.drained,
        "events": len(events),
        "summary": {key: value for key, value in summary.items() if key != "by_device"},
    }
    manifest = Manifest(
        kind="replay",
        env_tag="mock",
        tool=TOOL,
        git_sha=sha,
        git_dirty=dirty,
        pipeline_engine=engine,
        extra=extra,
    )
    write_manifest(directory, manifest)
    return directory


def main(argv: Sequence[str] | None = None) -> int:
    """0 when the replay drained and was sealed, 1 when it timed out (still sealed), 2 on a refusal."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--pcap", type=Path, default=DEFAULT_PCAP)
    parser.add_argument("--engine", choices=("v1", "v2"), default=None, help="default: the config's")
    parser.add_argument("--config", type=Path, default=None, help="default: pirewall-start's choice")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "lab" / "runs")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--settle", type=float, default=5.0)
    parser.add_argument("--timeout", type=float, default=900.0)
    args = parser.parse_args(argv)
    scratch = Path(tempfile.mkdtemp(prefix="pirewall-mock-log-"))
    log = scratch / "pirewall-start.log"
    try:
        config: Path | None = args.config
        if args.engine is not None:
            local = REPO_ROOT / "config" / "local_config.toml"
            source = config or (local if local.is_file() else REPO_ROOT / "config" / "default_config.toml")
            config = engine_config(source, args.engine, scratch)
        directory = replay(
            args.pcap,
            args.out,
            config,
            MockStart(log),
            lambda socket: ReadOnlyCore(str(socket)),
            Timing(args.interval, args.settle, args.timeout),
            engine=args.engine,
        )
    except LabError as exc:
        print(f"replay: {exc}\n(pirewall-start output: {log})", file=sys.stderr)
        return 2
    document = read_manifest(directory)
    extra = document.get("extra")
    drained = isinstance(extra, dict) and extra.get("drained") is True
    print(f"replay {'drained' if drained else 'TIMED OUT'} -> {directory} (env tag mock)")
    summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
    summary.pop("by_device", None)
    print(json.dumps(summary, indent=2))
    return 0 if drained else 1


if __name__ == "__main__":
    raise SystemExit(main())

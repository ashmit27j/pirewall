"""Training rows and live features are the same numbers (ADDENDUM_4.md D6, audit v1 #4).

`scripts/dataset/pcap_to_flows.py` must produce, for a capture, exactly the
feature vectors the live path computes for the same frames: the live path
being `FlowEngine.feed` driven the way `NativePacketCapture` drives it (the
ring hands each frame and its kernel timestamp to `Engine::feed`; core
drains the engine after each poll and sweeps on a timer), then
`extract_features`. Floats are compared exactly, through the CSV and back.
"""

import csv
import json
from ipaddress import IPv4Network
from pathlib import Path

import pytest
from scripts.dataset import pcap_to_flows

from pirewall.capture.pcapio import PcapWriter
from pirewall.config.models import FlowConfig
from pirewall.core.enums import EnvTag
from pirewall.core.models.flow import Flow
from pirewall.features.extractor import extract_features
from pirewall.features.schema import FEATURE_NAMES
from pirewall.flow.connection_start import ConnectionStartTracker
from pirewall.flow.native import (
    NativeFlowAggregator,
    from_microseconds,
    native_engine_available,
    to_microseconds,
)
from tests.helpers.traffic import ATTACKER_MAC, T0_US, mixed_stream

CONFIG = FlowConfig(
    active_timeout_seconds=120, inactive_timeout_seconds=60, max_flows=64, cleanup_interval_seconds=30
)
PROTECTED = IPv4Network("192.168.100.0/24")
needs_native = pytest.mark.skipif(not native_engine_available(), reason="pirewall_native not built")


def _pcap(path: Path, frames: list[tuple[bytes, int]], nanosecond: bool = False) -> Path:
    with PcapWriter(path, nanosecond=nanosecond) as writer:
        for data, ts_us in frames:
            writer.write(data, ts_us, ts_ns_remainder=321 if nanosecond else 0)
    return path


def _live_path(frames: list[tuple[bytes, int]]) -> list[tuple[Flow, bool]]:
    """The engine fed frame by frame as the ring feeds it; drained and swept as core does."""
    aggregator = NativeFlowAggregator(CONFIG, PROTECTED)
    engine = aggregator.engine
    tracker = ConnectionStartTracker(CONFIG.connection_start_max_tracked)
    interval = CONFIG.cleanup_interval_seconds * 1_000_000
    out: list[Flow] = []
    next_sweep: int | None = None
    for index, (raw, ts_us) in enumerate(frames, start=1):
        if next_sweep is None:
            next_sweep = ts_us + interval
        elif ts_us >= next_sweep:
            sweep_at = next_sweep + (ts_us - next_sweep) // interval * interval
            out.extend(aggregator.drain().completed)
            out.extend(aggregator.sweep_timeouts(from_microseconds(sweep_at)))
            next_sweep = sweep_at + interval
        engine.feed(raw, ts_us)
        if index % 1_000 == 0:
            out.extend(aggregator.drain().completed)
    out.extend(aggregator.drain().completed)
    out.extend(aggregator.flush())
    return [(flow, tracker.observe(flow)) for flow in out]


def _rows(out_dir: Path) -> list[dict[str, str]]:
    with (out_dir / "flows.csv").open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _convert(
    captures: list[Path],
    out: Path,
    engine: pcap_to_flows.EngineChoice = "auto",
    ground_truth: Path | None = None,
    strict: bool = False,
) -> dict[str, object]:
    return pcap_to_flows.convert(
        inputs=captures,
        out_dir=out,
        flow_config=CONFIG,
        protected=PROTECTED,
        env_tag=EnvTag.MOCK,
        engine=engine,
        ground_truth=ground_truth,
        strict=strict,
    )


@pytest.fixture(autouse=True)
def _force_csv(monkeypatch: pytest.MonkeyPatch) -> None:  # pyright: ignore[reportUnusedFunction]
    """Compare through the CSV path whether or not pyarrow happens to be installed."""
    real = pcap_to_flows.importlib.util.find_spec
    monkeypatch.setattr(
        pcap_to_flows.importlib.util,
        "find_spec",
        lambda name, *a: None if name == "pyarrow" else real(name, *a),  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )


@needs_native
@pytest.mark.parametrize(("seed", "nanosecond"), [(21, False), (22, True), (23, False)])
def test_pcap_to_flows_rows_equal_live_path_feature_vectors(
    tmp_path: Path, seed: int, nanosecond: bool
) -> None:
    frames = mixed_stream(seed, sessions=1_200)
    capture = _pcap(tmp_path / "capture.pcap", frames, nanosecond=nanosecond)
    manifest = _convert([capture], tmp_path / "out", engine="native")
    rows = _rows(tmp_path / "out")
    live = _live_path(frames)

    assert len(rows) == len(live) > 200
    assert manifest["rows"] == {
        "total": len(rows),
        "connection_starts": sum(s for _, s in live),
        "by_label": None,
    }
    for row, (flow, start) in zip(rows, live, strict=True):
        vector = extract_features(flow)
        assert tuple(float(row[name]) for name in FEATURE_NAMES) == vector.values
        assert row["connection_start"] == str(start)
        assert (row["source_ip"], row["destination_ip"]) == (str(flow.source_ip), str(flow.destination_ip))
        assert row["source_mac"] == str(flow.source_mac)
        assert int(row["first_seen_us"]) == to_microseconds(flow.first_seen)


@needs_native
def test_the_python_engine_produces_the_same_rows(tmp_path: Path) -> None:
    capture = _pcap(tmp_path / "capture.pcap", mixed_stream(31, sessions=800))
    _convert([capture], tmp_path / "native", engine="native")
    _convert([capture], tmp_path / "python", engine="python")
    assert _rows(tmp_path / "native") == _rows(tmp_path / "python")


def test_the_manifest_records_inputs_engine_config_and_counts(tmp_path: Path) -> None:
    frames = mixed_stream(41, sessions=300)
    first = _pcap(tmp_path / "a.pcap", frames[: len(frames) // 2])
    second = _pcap(tmp_path / "b.pcap", frames[len(frames) // 2 :])
    manifest = _convert([tmp_path], tmp_path / "out")
    written = json.loads((tmp_path / "out" / "manifest.json").read_text(encoding="utf-8"))
    assert written == manifest
    assert written["env_tag"] == "mock"
    assert written["feature_names"] == list(FEATURE_NAMES)
    assert [i["path"] for i in written["inputs"]] == [str(first), str(second)]
    assert all(len(i["sha256"]) == 64 for i in written["inputs"])
    assert sum(i["records"] for i in written["inputs"]) == len(frames)
    assert written["frames"]["seen"] == len(frames)
    assert written["output"]["format"] == "csv"
    assert written["engine"]["panics_caught"] == 0
    assert written["engine"]["backends_used"] == (["native"] if native_engine_available() else ["python"])
    assert len(_rows(tmp_path / "out")) == written["rows"]["total"]
    # The config hash moves with any setting that shapes a row, and only then.
    again = _convert([tmp_path], tmp_path / "again")
    other = pcap_to_flows.convert(
        inputs=[tmp_path],
        out_dir=tmp_path / "other",
        env_tag=EnvTag.MOCK,
        protected=PROTECTED,
        flow_config=CONFIG.model_copy(update={"inactive_timeout_seconds": 30}),
    )
    assert again["config_sha256"] == written["config_sha256"] != other["config_sha256"]


def test_ground_truth_labels_flows_by_mac_and_time_window(tmp_path: Path) -> None:
    frames = mixed_stream(51, sessions=400)
    capture = _pcap(tmp_path / "capture.pcap", frames)
    end = frames[-1][1]
    truth = tmp_path / "ground_truth.jsonl"
    truth.write_text(
        json.dumps({"mac": ATTACKER_MAC.upper(), "start": T0_US / 1e6, "end": end / 1e6, "label": "syn_scan"})
        + "\n\n",
        encoding="utf-8",
    )
    manifest = _convert([capture], tmp_path / "loose", ground_truth=truth)
    rows = _rows(tmp_path / "loose")
    attack = [r for r in rows if r["label"] == "syn_scan"]
    assert attack and all(ATTACKER_MAC in (r["source_mac"], r["destination_mac"]) for r in attack)
    assert {r["label"] for r in rows} == {"syn_scan", "benign"}
    assert manifest["rows"] == {
        "total": len(rows),
        "connection_starts": sum(r["connection_start"] == "True" for r in rows),
        "by_label": {"benign": len(rows) - len(attack), "syn_scan": len(attack)},
    }

    _convert([capture], tmp_path / "strict", ground_truth=truth, strict=True)
    assert {r["label"] for r in _rows(tmp_path / "strict")} == {"syn_scan", "unlabelled"}

    before = tmp_path / "before.jsonl"
    before.write_text(json.dumps({"mac": ATTACKER_MAC, "start": 0, "end": 1, "label": "x"}), encoding="utf-8")
    _convert([capture], tmp_path / "none", ground_truth=before)
    assert {r["label"] for r in _rows(tmp_path / "none")} == {"benign"}


@pytest.mark.parametrize(
    "line",
    [
        '{"mac": "02:00:00:00:00:01"}',
        '{"mac": "x", "start": 5, "end": 1, "label": "a"}',
        '{"mac": "x", "start": 0, "end": 1, "label": "benign"}',
        "not json",
    ],
)
def test_bad_ground_truth_is_refused_with_its_line(tmp_path: Path, line: str) -> None:
    truth = tmp_path / "gt.jsonl"
    truth.write_text(line + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"gt.jsonl:1"):
        pcap_to_flows.load_ground_truth(truth)


def test_the_cli_writes_its_outputs_and_reports_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = _pcap(tmp_path / "capture.pcap", mixed_stream(61, sessions=50))
    assert pcap_to_flows.main([str(capture), "--out", str(tmp_path / "out"), "--env-tag", "mock"]) == 0
    assert (tmp_path / "out" / "manifest.json").is_file()
    assert json.loads((tmp_path / "out" / "manifest.json").read_text(encoding="utf-8"))["env_tag"] == "mock"
    assert pcap_to_flows.main([str(tmp_path / "missing.pcap"), "--out", str(tmp_path / "x")]) == 1
    assert "missing.pcap" in capsys.readouterr().err

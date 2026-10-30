"""Splitting pcaps into leak-free D2/D3 datasets (phase 19, critique_ml §4).

The builder is the only place training, validation and test rows are separated,
so these tests pin the properties the model reports depend on: benign is split
temporally with a gap, attacks are held out by run/tool/parameter, every test
file is hashed into an append-only ledger, and provenance tags never mix by
accident.
"""

import csv
import hashlib
import json
from pathlib import Path

import pytest
from scripts.dataset import build_dataset

from pirewall.core.enums import EnvTag
from pirewall.features.schema import (
    LEGACY_SCHEMA_VERSION,
    SCHEMA_VERSION,
    feature_names,
)

SECOND_US = 1_000_000
GAP_HOURS = 1 / 3_600  # one second, enough to exercise the gap without long synthetic runs
METADATA_COLUMNS = (
    "source_pcap",
    "source_mac",
    "destination_mac",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "first_seen_us",
    "last_seen_us",
    "connection_start",
)


def _row(
    *,
    at_us: int,
    label: str | None = "benign",
    source_ip: str = "10.1.0.10",
    source_port: int = 40_000,
    destination_ip: str = "10.1.0.20",
    destination_port: int = 80,
    protocol: str = "tcp",
    source_pcap: str = "capture.pcap",
) -> dict[str, str]:
    row = dict.fromkeys(feature_names(SCHEMA_VERSION), "0.0")
    row.update(
        {
            "source_pcap": source_pcap,
            "source_mac": "02:00:00:00:00:01",
            "destination_mac": "02:00:00:00:00:02",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": str(source_port),
            "destination_port": str(destination_port),
            "protocol": protocol,
            "first_seen_us": str(at_us),
            "last_seen_us": str(at_us + 1_000),
            "connection_start": "False",
        }
    )
    if label is not None:
        row["label"] = label
    return row


def _benign_rows(
    *,
    count: int = 21,
    step: int = 5 * SECOND_US,
    port_base: int = 40_000,
    pcap: str = "capture.pcap",
) -> list[dict[str, str]]:
    return [
        _row(at_us=index * step, source_port=port_base + index, label="benign", source_pcap=pcap)
        for index in range(count)
    ]


def _write_input(
    directory: Path,
    rows: list[dict[str, str]],
    *,
    env_tag: str = EnvTag.MOCK.value,
    schema: str = SCHEMA_VERSION,
    names: tuple[str, ...] | None = None,
    labelled: bool = True,
    ground_truth: Path | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    features = names if names is not None else feature_names(schema)
    columns = [*METADATA_COLUMNS, *features]
    if labelled:
        columns.append("label")
    with (directory / "flows.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows({name: row.get(name, "") for name in columns} for row in rows)
    manifest: dict[str, object] = {
        "feature_schema_version": schema,
        "feature_names": list(features),
        "env_tag": env_tag,
    }
    if ground_truth is not None:
        manifest["ground_truth"] = {"path": str(ground_truth)}
    (directory / "manifest.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    return directory


def _split(out: Path, name: str) -> list[dict[str, str]]:
    with (out / f"{name}.csv").open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _connection(row: dict[str, str]) -> tuple[str, ...]:
    return (
        row["source_ip"],
        row["source_port"],
        row["destination_ip"],
        row["destination_port"],
        row["protocol"],
    )


def test_benign_is_split_temporally_with_a_gap_and_no_crossing_connection(tmp_path: Path) -> None:
    rows = _benign_rows()
    # One connection straddles the 59.4 s train boundary; both its rows must
    # be dropped so the same 5-tuple never appears in train and validation.
    rows.append(_row(at_us=50 * SECOND_US, source_port=50_000))
    rows.append(_row(at_us=60 * SECOND_US, source_port=50_000))
    source = _write_input(tmp_path / "in", rows)

    manifest = build_dataset.build([source], out_dir=tmp_path / "out", benign_gap_hours=GAP_HOURS)

    assert manifest["feature_schema_version"] == SCHEMA_VERSION
    assert manifest["feature_names"] == list(feature_names(SCHEMA_VERSION))
    assert manifest["env_tags"] == ["mock"]
    counts = {
        name: manifest["splits"][name]["rows"]  # type: ignore[index]
        for name in ("benign_train", "benign_validation", "benign_gap", "benign_test")
    }
    assert counts == {
        "benign_train": 12,
        "benign_validation": 3,
        "benign_gap": 1,
        "benign_test": 5,
    }
    policy = manifest["policy"]["benign"]  # type: ignore[index]
    assert policy["gap_hours"] == GAP_HOURS
    assert policy["dropped_crossing_connections"] == 1
    assert policy["blocks"]["train_end_us"] == 59_400_600
    assert policy["blocks"]["validation_end_us"] == 74_250_750
    assert policy["blocks"]["test_start_us"] == 75_250_750

    seen: dict[tuple[str, ...], set[str]] = {}
    for name in ("benign_train", "benign_validation", "benign_test"):
        for row in _split(tmp_path / "out", name):
            seen.setdefault(_connection(row), set()).add(name)
    assert all(len(names) == 1 for names in seen.values())
    dropped = ("10.1.0.10", "50000", "10.1.0.20", "80", "tcp")
    assert dropped not in seen


def test_attack_splits_hold_out_a_tool_a_parameter_variant_and_whole_runs(tmp_path: Path) -> None:
    benign = _write_input(tmp_path / "benign", _benign_rows())
    rows: list[dict[str, str]] = []
    cases = [
        ("masscan_1.pcap", "syn_scan"),
        ("masscan_2.pcap", "syn_scan"),
        ("flood_1.pcap", "syn_flood_random"),
        ("flood_2.pcap", "syn_flood_random"),
        ("flood_3.pcap", "syn_flood"),
        ("flood_4.pcap", "syn_flood"),
        ("flood_5.pcap", "syn_flood"),
        ("flood_6.pcap", "syn_flood"),
        ("flood_7.pcap", "syn_flood"),
    ]
    for index, (pcap, label) in enumerate(cases):
        rows.append(_row(at_us=index * SECOND_US, source_port=50_000 + index, source_pcap=pcap, label=label))
    attacks = _write_input(tmp_path / "attacks", rows)

    manifest = build_dataset.build(
        [benign, attacks], out_dir=tmp_path / "out", benign_gap_hours=GAP_HOURS
    )
    policy = manifest["policy"]["attacks"]  # type: ignore[index]

    assert policy["tool_holdout_runs"] == ["masscan_1", "masscan_2"]
    assert policy["parameter_holdout_runs"] == ["flood_1", "flood_2"]
    assert policy["run_holdout_runs"] == ["flood_7"]
    assert policy["validation_runs"] == ["flood_3"]
    assert policy["training_runs"] == ["flood_4", "flood_5", "flood_6"]
    assert policy["runs"] == len(cases)
    assert policy["held_out_tool"] == "masscan"
    assert policy["parameter_holdout_suffix"] == "random"

    # No run may contribute rows to more than one split.
    owners: dict[str, set[str]] = {}
    for name in (
        "attack_train",
        "attack_validation",
        "attack_test_run_holdout",
        "attack_test_leave_one_tool_out",
        "attack_test_parameter_holdout",
    ):
        for row in _split(tmp_path / "out", name):
            owners.setdefault(row["run_id"], set()).add(name)
    assert all(len(names) == 1 for names in owners.values())
    assert len(owners) == len(cases)


def test_ground_truth_metadata_supplies_run_and_tool_ids(tmp_path: Path) -> None:
    truth = tmp_path / "ground_truth.jsonl"
    truth.write_text(
        json.dumps(
            {
                "pcap": "capture.pcap",
                "label": "syn_scan",
                "run_id": "run-7",
                "tool": "masscan",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    rows = _benign_rows()
    rows.append(_row(at_us=100 * SECOND_US, source_port=51_000, label="syn_scan"))
    for index in range(3):
        rows.append(
            _row(
                at_us=(index + 1) * SECOND_US,
                source_port=52_000 + index,
                source_pcap=f"syn_flood_{index + 1}.pcap",
                label="syn_flood",
            )
        )
    source = _write_input(tmp_path / "in", rows, ground_truth=truth)

    manifest = build_dataset.build([source], out_dir=tmp_path / "out", benign_gap_hours=GAP_HOURS)

    policy = manifest["policy"]["attacks"]  # type: ignore[index]
    assert policy["tool_holdout_runs"] == ["run-7"]
    assert policy["runs"] == 4


def test_a_connection_shared_by_two_attack_runs_is_refused(tmp_path: Path) -> None:
    benign = _write_input(tmp_path / "benign", _benign_rows())
    rows = [
        _row(at_us=index * SECOND_US, source_port=52_000, source_pcap=pcap, label=label)
        for index, (pcap, label) in enumerate(
            [
                ("a.pcap", "syn_flood"),
                ("b.pcap", "syn_flood"),
                ("c.pcap", "syn_flood"),
                ("d.pcap", "syn_flood"),
            ]
        )
    ]
    attacks = _write_input(tmp_path / "attacks", rows)

    with pytest.raises(build_dataset.DatasetError, match="connection spans attack splits"):
        build_dataset.build([benign, attacks], out_dir=tmp_path / "out", benign_gap_hours=GAP_HOURS)


def test_the_per_run_cap_is_seeded_deterministic_and_recorded(tmp_path: Path) -> None:
    rows = _benign_rows(count=20, port_base=40_000, pcap="run.pcap")
    source = _write_input(tmp_path / "in", rows)

    first = build_dataset.build(
        [source],
        out_dir=tmp_path / "first",
        benign_gap_hours=GAP_HOURS,
        max_rows_per_run=10,
    )
    cap = first["policy"]["cap"]  # type: ignore[index]
    assert cap["max_rows_per_run"] == 10
    assert cap["benign_rows_capped_away"] == 10
    assert cap["runs_capped"] == {"benign": 1, "attack": 0}
    assert first["splits"]["benign_train"]["rows"] == 5  # type: ignore[index]
    assert first["splits"]["benign_validation"]["rows"] == 2  # type: ignore[index]
    assert first["splits"]["benign_gap"]["rows"] == 0  # type: ignore[index]
    assert first["splits"]["benign_test"]["rows"] == 3  # type: ignore[index]

    again = build_dataset.build(
        [source],
        out_dir=tmp_path / "again",
        benign_gap_hours=GAP_HOURS,
        max_rows_per_run=10,
    )
    other = build_dataset.build(
        [source],
        out_dir=tmp_path / "other",
        benign_gap_hours=GAP_HOURS,
        max_rows_per_run=10,
        seed=7,
    )
    assert again["dataset_id"] == first["dataset_id"]
    assert other["dataset_id"] != first["dataset_id"]


def test_test_splits_are_hashed_into_an_append_only_ledger_and_rewrites_are_refused(
    tmp_path: Path,
) -> None:
    rows = _benign_rows()
    source = _write_input(tmp_path / "in", rows)
    out = tmp_path / "out"

    first = build_dataset.build([source], out_dir=out, benign_gap_hours=GAP_HOURS)
    test_row = _split(out, "benign_test")
    ledger_path = out / build_dataset.LEDGER_NAME
    entries = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    assert len(entries) == 1
    assert entries[0]["split"] == "benign_test"
    assert entries[0]["action"] == "written"
    assert entries[0]["dataset_id"] == first["dataset_id"]
    assert entries[0]["rows"] == len(test_row) == 5
    assert entries[0]["sha256"] == hashlib.sha256((out / "benign_test.csv").read_bytes()).hexdigest()
    assert first["splits"]["benign_test"]["sha256"] == entries[0]["sha256"]  # type: ignore[index]
    assert first["test_access_ledger"]["entries"] == 1  # type: ignore[index]

    # Rebuilding the same dataset is allowed, but still leaves an audit trail.
    second = build_dataset.build([source], out_dir=out, benign_gap_hours=GAP_HOURS)
    assert second["dataset_id"] == first["dataset_id"]
    assert len(ledger_path.read_text(encoding="utf-8").splitlines()) == 2

    # A different benign test block is a new test set: refuse silently replacing it.
    rows.append(_row(at_us=99 * SECOND_US, source_port=59_999))
    _write_input(tmp_path / "in", rows)
    with pytest.raises(build_dataset.DatasetError, match="already records a different test dataset"):
        build_dataset.build([source], out_dir=out, benign_gap_hours=GAP_HOURS)
    assert len(ledger_path.read_text(encoding="utf-8").splitlines()) == 2

    third = build_dataset.build(
        [source], out_dir=out, benign_gap_hours=GAP_HOURS, allow_test_rewrite=True
    )
    assert third["dataset_id"] != first["dataset_id"]
    entries = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines()]
    assert len(entries) == 3
    assert entries[-1]["action"] == "rewritten"
    assert entries[-1]["allow_test_rewrite"] is True
    assert entries[-1]["dataset_id"] == third["dataset_id"]


def test_env_tags_never_mix_silently(tmp_path: Path) -> None:
    mock = _write_input(
        tmp_path / "mock", _benign_rows(), env_tag=EnvTag.MOCK.value
    )
    live = _write_input(
        tmp_path / "live",
        _benign_rows(port_base=60_000),
        env_tag=EnvTag.PI_LIVE.value,
    )

    with pytest.raises(build_dataset.DatasetError, match="mix env tags"):
        build_dataset.build([mock, live], out_dir=tmp_path / "refused", benign_gap_hours=GAP_HOURS)

    manifest = build_dataset.build(
        [mock, live],
        out_dir=tmp_path / "mixed",
        allow_mixed_benign=["mock", "pi-live"],
        benign_gap_hours=GAP_HOURS,
    )
    assert manifest["env_tags"] == ["mock", "pi-live"]
    assert manifest["mixed_env"] == {"allowed": ["mock", "pi-live"], "used": True}
    assert {item["env_tag"] for item in manifest["inputs"]} == {"mock", "pi-live"}  # type: ignore[index]

    with pytest.raises(build_dataset.DatasetError, match="unknown --allow-mixed-benign"):
        build_dataset.build(
            [mock, live],
            out_dir=tmp_path / "unknown",
            allow_mixed_benign=["mock", "nowhere"],
            benign_gap_hours=GAP_HOURS,
        )


@pytest.mark.parametrize(
    ("schema", "names", "match"),
    [
        (
            LEGACY_SCHEMA_VERSION,
            feature_names(LEGACY_SCHEMA_VERSION),
            "phase-19 training needs",
        ),
        ("1.0.0", feature_names(SCHEMA_VERSION), "unsupported feature schema"),
    ],
)
def test_wrong_or_unknown_schemas_are_refused(
    tmp_path: Path, schema: str, names: tuple[str, ...], match: str
) -> None:
    source = _write_input(tmp_path / "in", _benign_rows(), schema=schema, names=names)
    with pytest.raises(build_dataset.DatasetError, match=match):
        build_dataset.build([source], out_dir=tmp_path / "out", benign_gap_hours=GAP_HOURS)


def test_manifest_feature_names_must_match_the_schema(tmp_path: Path) -> None:
    names = list(feature_names(SCHEMA_VERSION))
    source = _write_input(
        tmp_path / "in", _benign_rows(), names=tuple(reversed(names))
    )
    with pytest.raises(build_dataset.DatasetError, match="manifest feature_names disagree"):
        build_dataset.build([source], out_dir=tmp_path / "out", benign_gap_hours=GAP_HOURS)


def test_unlabelled_captures_need_an_explicit_benign_opt_in(tmp_path: Path) -> None:
    source = _write_input(tmp_path / "in", _benign_rows(), labelled=False)

    with pytest.raises(build_dataset.DatasetError, match="--assume-benign"):
        build_dataset.build([source], out_dir=tmp_path / "refused", benign_gap_hours=GAP_HOURS)

    manifest = build_dataset.build(
        [source], out_dir=tmp_path / "out", benign_gap_hours=GAP_HOURS, assume_benign=True
    )
    assert manifest["policy"]["assume_benign"] is True  # type: ignore[index]
    assert manifest["inputs"][0]["labelled"] is False  # type: ignore[index]
    assert {row["label"] for row in _split(tmp_path / "out", "benign_train")} == {"benign"}


def test_unlabelled_rows_are_counted_and_dropped(tmp_path: Path) -> None:
    rows = _benign_rows()
    rows.append(_row(at_us=500 * SECOND_US, source_port=59_000, label="unlabelled"))
    source = _write_input(tmp_path / "in", rows)

    manifest = build_dataset.build([source], out_dir=tmp_path / "out", benign_gap_hours=GAP_HOURS)

    assert manifest["dropped_rows"] == {"unlabelled": 1}
    assert manifest["splits"]["benign_test"]["rows"] == 5  # type: ignore[index]


def test_bad_inputs_are_refused_with_an_operator_message(tmp_path: Path) -> None:
    with pytest.raises(build_dataset.DatasetError, match="at least one"):
        build_dataset.build([], out_dir=tmp_path / "out")

    source = _write_input(tmp_path / "in", _benign_rows())
    with pytest.raises(build_dataset.DatasetError, match="positive"):
        build_dataset.build([source], out_dir=tmp_path / "out", benign_gap_hours=0)
    with pytest.raises(build_dataset.DatasetError, match=">= 0"):
        build_dataset.build([source], out_dir=tmp_path / "out", max_rows_per_run=-1)
    with pytest.raises(build_dataset.DatasetError, match="capture more benign traffic"):
        build_dataset.build([source], out_dir=tmp_path / "out", benign_gap_hours=1.0)

    empty = _write_input(tmp_path / "empty", [])
    with pytest.raises(build_dataset.DatasetError, match="no usable rows"):
        build_dataset.build([empty], out_dir=tmp_path / "out", benign_gap_hours=GAP_HOURS)


def test_missing_inputs_are_refused(tmp_path: Path) -> None:
    with pytest.raises(build_dataset.DatasetError, match=r"needs flows\.csv and manifest\.json"):
        build_dataset.build([tmp_path / "missing"], out_dir=tmp_path / "out")

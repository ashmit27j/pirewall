"""D1 thresholds: the file, the clamp, and the fitting script (phase 17 deliverable 3).

Fitting runs on synthetic `pcap_to_flows`-shaped directories (env=mock):
it checks determinism and provenance, not any real network's thresholds.
"""

import csv
import json
from pathlib import Path
from typing import Any, Final

import pytest
from scripts.dataset.pcap_to_flows import METADATA_COLUMNS
from scripts.train import fit_d1_thresholds

from pirewall.config.models import D1Config
from pirewall.core.enums import D1Detector
from pirewall.core.exceptions import ConfigurationError
from pirewall.detection_v2.thresholds import (
    DEFAULT_PRIORS,
    Prior,
    ThresholdKey,
    dump_thresholds,
    floors_file,
    load_thresholds,
    percentile,
    threshold_from_benign,
)
from pirewall.features.schema import FEATURE_NAMES

SHIPPED: Final = Path(__file__).resolve().parents[2] / "config" / "d1_thresholds.toml"
T0_US: Final = 1_772_366_400_000_000


def test_the_shipped_file_is_the_floors_and_not_frozen() -> None:
    shipped = load_thresholds(SHIPPED)

    assert shipped.frozen is False
    assert shipped.provenance["source"] == "floors"
    for name, entry in shipped.thresholds.items():
        assert entry.value == entry.floor == DEFAULT_PRIORS[entry.key].floor, name


def test_a_vertical_scan_over_100_ports_a_minute_is_never_benign() -> None:
    assert DEFAULT_PRIORS[ThresholdKey(D1Detector.VERTICAL_SCAN, "device", 60)].ceiling == 100


def test_the_clamp_holds_on_both_sides() -> None:
    prior = Prior(floor=10, ceiling=50)

    assert threshold_from_benign([1, 2, 3], 1.5, prior)[0] == 10
    assert threshold_from_benign([1000.0] * 5, 1.5, prior)[0] == 50
    value, p999 = threshold_from_benign([float(i) for i in range(1, 21)], 2.0, prior)
    assert p999 == pytest.approx(percentile([float(i) for i in range(1, 21)], 0.999))
    assert value == pytest.approx(min(max(p999 * 2.0, 10), 50))


def test_the_file_round_trips_and_a_hand_edit_is_refused(tmp_path: Path) -> None:
    original = floors_file((10, 60), {"note": "test"})
    path = tmp_path / "d1.toml"
    path.write_text(dump_thresholds(original), encoding="utf-8")

    assert load_thresholds(path) == original
    edited = path.read_text(encoding="utf-8").replace("value = 25.0", "value = 26.0", 1)
    path.write_text(edited, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="sha256"):
        load_thresholds(path)


def test_a_missing_file_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="not found"):
        load_thresholds(tmp_path / "missing.toml")


# ----------------------------------------------------------------- fitting


def _flows_dir(
    tmp_path: Path, name: str, *, env_tag: str = "mock", labelled: bool = True, scan: bool = False
) -> Path:
    directory = tmp_path / name
    directory.mkdir()
    columns = [*METADATA_COLUMNS, *(["label"] if labelled else []), *FEATURE_NAMES]
    with (directory / "flows.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for i in range(400):
            mac = f"02:00:00:00:00:{i % 5 + 1:02x}"
            row: dict[str, object] = {
                "source_pcap": "x.pcap",
                "source_mac": mac,
                "destination_mac": "02:00:00:00:00:01",
                "source_ip": f"192.168.1.{i % 5 + 10}",
                "destination_ip": f"93.184.{i % 7}.{i % 3 + 1}",
                "source_port": 40000 + i,
                "destination_port": 443 if i % 4 else 80,
                "protocol": "tcp",
                "first_seen_us": T0_US + i * 1_500_000,
                "last_seen_us": T0_US + i * 1_500_000 + 900_000,
                "connection_start": True,
            }
            if labelled:
                row["label"] = "benign"
            row.update(dict.fromkeys(FEATURE_NAMES, 0.0))
            row.update(
                {
                    "packet_count": 12.0,
                    "backward_packet_count": 5.0,
                    "payload_byte_count": 4000.0 + i,
                    "duration_seconds": 0.9,
                    "destination_port": float(str(row["destination_port"])),
                }
            )
            writer.writerow(row)
        if scan and labelled:
            for port in range(1, 300):  # an attack inside the benign capture, labelled as such
                writer.writerow(
                    {
                        **dict.fromkeys(FEATURE_NAMES, 0.0),
                        "source_pcap": "x.pcap",
                        "source_mac": "02:00:00:00:00:ee",
                        "destination_mac": "02:00:00:00:00:01",
                        "source_ip": "192.168.1.99",
                        "destination_ip": "192.168.1.10",
                        "source_port": 50000,
                        "destination_port": port,
                        "protocol": "tcp",
                        "first_seen_us": T0_US + port,
                        "last_seen_us": T0_US + port,
                        "connection_start": True,
                        "label": "syn_scan",
                        "packet_count": 2.0,
                        "backward_packet_count": 1.0,
                    }
                )
    (directory / "manifest.json").write_text(json.dumps({"env_tag": env_tag, "rows": 400}), encoding="utf-8")
    return directory


def _fit(*directories: Path, **overrides: Any) -> fit_d1_thresholds.D1ThresholdFile:
    arguments: dict[str, Any] = {  # Any: keyword arguments of several types, checked by fit() itself
        "config": D1Config(),
        "margin": 1.5,
        "train_fraction": 0.75,
        "block_start": None,
        "block_end": None,
        "exclude": (),
        "assume_benign": False,
        "freeze": False,
    }
    arguments.update(overrides)
    return fit_d1_thresholds.fit(list(directories), **arguments)


def test_fitting_is_deterministic_and_records_provenance(tmp_path: Path) -> None:
    flows = _flows_dir(tmp_path, "a")

    first, second = _fit(flows), _fit(flows)

    assert dump_thresholds(first) == dump_thresholds(second)
    assert first.provenance["source"] == "fitted"
    assert first.provenance["env_tag"] == "mock"
    manifest_hash = __import__("hashlib").sha256((flows / "manifest.json").read_bytes()).hexdigest()
    assert first.provenance["inputs"] == [f"a:{manifest_hash}"]
    assert int(str(first.provenance["block_end_us"])) > int(str(first.provenance["block_start_us"]))
    vertical = first.thresholds["vertical_scan/device/60"]
    assert vertical.samples > 0 and vertical.benign_p999 is not None and vertical.margin == 1.5
    # Rows cannot measure leases or portal logins: floors, with no samples.
    assert first.thresholds["new_lease_rate/global/60"].samples == 0


def test_attack_rows_never_reach_the_benign_quantiles(tmp_path: Path) -> None:
    clean = _fit(_flows_dir(tmp_path, "clean"))
    poisoned = _fit(_flows_dir(tmp_path, "poisoned", scan=True))

    assert (
        poisoned.thresholds["vertical_scan/device/60"].value
        == clean.thresholds["vertical_scan/device/60"].value
    )


def test_unlabelled_inputs_need_assume_benign(tmp_path: Path) -> None:
    flows = _flows_dir(tmp_path, "u", labelled=False)

    with pytest.raises(fit_d1_thresholds.FitError, match="assume-benign"):
        _fit(flows)
    assert _fit(flows, assume_benign=True).provenance["source"] == "fitted"


def test_mixed_env_tags_are_refused(tmp_path: Path) -> None:
    with pytest.raises(fit_d1_thresholds.FitError, match="env tags"):
        _fit(_flows_dir(tmp_path, "a", env_tag="mock"), _flows_dir(tmp_path, "b", env_tag="sandbox"))


def test_the_cli_writes_a_loadable_frozen_file(tmp_path: Path) -> None:
    out = tmp_path / "out.toml"

    assert fit_d1_thresholds.main([str(_flows_dir(tmp_path, "a")), "--out", str(out), "--freeze"]) == 0
    assert load_thresholds(out).frozen is True
    assert fit_d1_thresholds.main(["--out", str(out)]) == 2  # no inputs and no --floors-only


def test_floors_only_matches_the_shipped_file(tmp_path: Path) -> None:
    out = tmp_path / "floors.toml"

    assert fit_d1_thresholds.main(["--floors-only", "--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == SHIPPED.read_text(encoding="utf-8")

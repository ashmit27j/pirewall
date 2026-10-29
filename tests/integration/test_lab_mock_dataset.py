"""The `mock` data set end to end (phase 18): gen_pcaps -> pcap_to_flows -> benign_fp. env=mock.

* `gen_pcaps.py` is deterministic by seed and writes every attack class into
  `ground_truth.jsonl`;
* `pcap_to_flows` labels attack flows with their class and benign flows
  `benign`;
* the offline G5 evaluator flags the attack MACs and leaves every benign MAC
  at zero enforce actions, and says "no" for a mock data set.

Generated at `--scale 0.05` (the smallest) to keep it quick. Skipped
without scapy (the dev/lab-only `lab` extra).
"""

import csv
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest

pytest.importorskip("scapy.all")

from scripts.dataset.pcap_to_flows import main as pcap_to_flows_main

from lab.benign_fp import main as benign_fp_main
from lab.mock.gen_pcaps import ATTACK_CLASSES, Net, attacker, benign_devices
from lab.mock.gen_pcaps import main as gen_main
from pirewall.config.loader import load_config

_REPO: Final = Path(__file__).resolve().parents[2]
_CONFIG: Final = _REPO / "config" / "default_config.toml"
_NO_FLOWS: Final = frozenset({"arp_poisoning"})  # ARP only: no IPv4 flow to label


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    out = tmp_path_factory.mktemp("mock") / "out"
    assert gen_main(["--seed", "3", "--scale", "0.05", "--out", str(out)]) == 0
    yield out


@pytest.fixture(scope="module")
def flows(generated: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("flows") / "flows"
    code = pcap_to_flows_main(
        [
            str(generated),
            "--out",
            str(out),
            "--config",
            str(_CONFIG),
            "--continuous",
            "--env-tag",
            "mock",
            "--ground-truth",
            str(generated / "ground_truth.jsonl"),
        ]
    )
    assert code == 0
    return out


def test_generation_is_byte_identical_for_a_seed(tmp_path: Path) -> None:
    only = ["--only", "syn_flood_random", "--only", "mac_churn"]
    for name in ("a", "b"):
        assert gen_main(["--seed", "11", "--scale", "0.05", "--out", str(tmp_path / name), *only]) == 0
    files = sorted(path.name for path in (tmp_path / "a").iterdir())
    assert files == sorted(path.name for path in (tmp_path / "b").iterdir())
    for name in files:
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes(), name
    assert gen_main(["--seed", "12", "--scale", "0.05", "--out", str(tmp_path / "c"), *only]) == 0
    assert (tmp_path / "c" / "02_syn_flood_random.pcap").read_bytes() != (
        tmp_path / "a" / "02_syn_flood_random.pcap"
    ).read_bytes()


def test_every_attack_class_is_in_the_ground_truth(generated: Path) -> None:
    windows = [json.loads(line) for line in (generated / "ground_truth.jsonl").read_text().splitlines()]
    assert {window["label"] for window in windows} == set(ATTACK_CLASSES)
    assert all(window["start"] <= window["end"] for window in windows)
    manifest = json.loads((generated / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["env_tag"] == "mock" and manifest["kind"] == "dataset"


def test_an_existing_generation_is_not_overwritten_without_force(generated: Path) -> None:
    assert gen_main(["--seed", "3", "--scale", "0.05", "--out", str(generated)]) == 2


def test_pcap_to_flows_labels_attack_flows_by_class_and_benign_flows_benign(flows: Path) -> None:
    config = load_config(_CONFIG)
    net = Net(
        config.network.pirewall_lan_ip,
        config.network.protected_network,
        list(config.lab.victim_network.hosts())[-1],
        config.portal.listen_port,
    )
    attackers = {attacker(index, net).mac: name for index, name in enumerate(ATTACK_CLASSES)}
    benign = {device.mac for device in benign_devices(net)}
    with (flows / "flows.csv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert rows
    labels_seen: set[str] = set()
    for row in rows:
        macs = {row["source_mac"], row["destination_mac"]}
        owner = next((attackers[mac] for mac in macs if mac in attackers), None)
        if owner is not None:
            assert row["label"] == owner, row
        elif macs & benign:  # neither side an attacker: a benign device's own flow
            assert row["label"] == "benign", row
        labels_seen.add(row["label"])
    assert labels_seen == (set(ATTACK_CLASSES) - _NO_FLOWS) | {"benign"}


def test_the_offline_g5_evaluator_flags_attackers_and_spares_benign_devices(
    generated: Path, flows: Path, tmp_path: Path
) -> None:
    out = tmp_path / "fp"
    code = benign_fp_main(
        [
            str(flows),
            "--out",
            str(out),
            "--config",
            str(_CONFIG),
            "--pcaps",
            str(generated),
            "--ground-truth",
            str(generated / "ground_truth.jsonl"),
            "--min-device-hours",
            "0",
        ]
    )
    assert code == 0
    report = json.loads((out / "fp.json").read_text(encoding="utf-8"))
    assert report["env_tag"] == "mock"
    assert report["verdict"]["forward_guard_may_enforce"] is False
    assert "mock" in report["verdict"]["reason"]
    benign = {f"02:00:00:00:b0:{i:02x}" for i in range(1, 7)}
    assert set(report["devices"]) == benign
    for name, scenario in report["scenarios"].items():
        for mode, result in scenario["modes"].items():
            assert result["g5_zero_enforce"], (name, mode, result["by_mac"])
            assert result["enforce_actions"]["count"] == 0
            assert result["enforce_actions"]["method"] == "rule of three (3/T)"
            for mac, counts in result["by_mac"].items():
                if mac in benign:
                    assert counts["rate_limit"] == counts["block"] == 0, (name, mode, mac)
        lab_trips = {trip["mac"] for trip in scenario["meter_trips"] if trip["lab"]}
        assert "02:00:00:00:a0:01" in lab_trips  # the fixed-source SYN flood trips the SYN meter
        assert not [trip for trip in scenario["meter_trips"] if not trip["lab"]]
    flagged = set(report["scenarios"]["configured"]["modes"]["active"]["by_mac"])
    assert flagged & set(report["attack_window_macs"])
    assert (out / "manifest.json").is_file()

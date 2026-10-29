"""`lab/manifest.py`, `lab/verify_manifest.py`, `lab/seal.py` and `lab/common.py` (phase 18, G7, D7)."""

import json
from pathlib import Path

import pytest

from lab.common import LabError, check_output_location, require_env_tag
from lab.manifest import ENV_TAGS, Manifest, ManifestError, Phase, read_manifest, write_manifest
from lab.seal import read_lab_macs, seal
from lab.verify_manifest import frozen_thresholds_problem, verify_tree
from lab.verify_manifest import main as verify_main
from pirewall.core.enums import EnvTag

_REPO = Path(__file__).resolve().parents[2]


def _sealed(directory: Path, env_tag: str = "mock", phase: Phase | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "a.txt").write_text("alpha\n", encoding="utf-8")
    (directory / "sub").mkdir(exist_ok=True)
    (directory / "sub" / "b.bin").write_bytes(b"\x00\x01")
    write_manifest(directory, Manifest(kind="run", env_tag=env_tag, tool="test", phase=phase))
    return directory


def test_the_env_tags_are_exactly_the_d7_tags() -> None:
    assert set(ENV_TAGS) == {tag.value for tag in EnvTag}


def test_a_manifest_seals_every_file_and_verifies(tmp_path: Path) -> None:
    run = _sealed(tmp_path / "run")
    document = read_manifest(run)
    files = document["files"]
    assert isinstance(files, dict) and set(files) == {"a.txt", "sub/b.bin"}
    report = verify_tree(run)
    assert report.ok and report.verified == [run]


def test_a_changed_byte_is_caught(tmp_path: Path) -> None:
    run = _sealed(tmp_path / "run")
    (run / "sub" / "b.bin").write_bytes(b"\x00\x02")
    report = verify_tree(run)
    assert any("sub/b.bin has changed" in problem for problem in report.problems)


def test_a_missing_file_and_an_added_file_are_caught(tmp_path: Path) -> None:
    run = _sealed(tmp_path / "run")
    (run / "a.txt").unlink()
    (run / "late.txt").write_text("x", encoding="utf-8")
    problems = verify_tree(run).problems
    assert any("a.txt is missing" in problem for problem in problems)
    assert any("late.txt is not in the manifest" in problem for problem in problems)
    assert verify_main([str(run)]) == 1


def test_a_sealed_directory_is_never_resealed(tmp_path: Path) -> None:
    run = _sealed(tmp_path / "run")
    with pytest.raises(ManifestError):
        write_manifest(run, Manifest(kind="run", env_tag="mock", tool="test"))


def test_a_nested_directory_with_another_env_tag_is_refused(tmp_path: Path) -> None:
    run = _sealed(tmp_path / "run", "mock")
    _sealed(run / "score", "sandbox")
    problems = verify_tree(run).problems
    assert any("env tag sandbox inside a mock directory" in problem for problem in problems)


def test_an_eval_run_needs_frozen_thresholds(tmp_path: Path) -> None:
    run = _sealed(tmp_path / "run", "mock", phase="eval")
    assert any("without frozen D1 thresholds" in problem for problem in verify_tree(run).problems)
    shipped = _REPO / "config" / "d1_thresholds.toml"
    problem = frozen_thresholds_problem(shipped)
    assert problem is not None and "frozen = false" in problem


def test_an_unknown_env_tag_is_refused() -> None:
    with pytest.raises(ManifestError):
        Manifest(kind="run", env_tag="pi", tool="test")


def test_pi_tags_are_refused_off_a_pi_and_never_needed_for_mock() -> None:
    with pytest.raises(LabError, match="not a Pi"):
        require_env_tag("pi-live", on_pi=False)
    assert require_env_tag("pi-scripted", on_pi=True) == "pi-scripted"
    assert require_env_tag("mock", on_pi=False) == "mock"
    with pytest.raises(LabError):
        require_env_tag("live", on_pi=True)


def test_outputs_never_land_in_the_tracked_tree(tmp_path: Path) -> None:
    assert check_output_location(_REPO / "lab" / "runs" / "x") == (_REPO / "lab" / "runs" / "x").resolve()
    assert check_output_location(_REPO / "lab" / "mock" / "out") == (_REPO / "lab" / "mock" / "out").resolve()
    assert check_output_location(tmp_path / "anything") == (tmp_path / "anything").resolve()
    for tracked in (_REPO / "lab", _REPO / "docs" / "x", _REPO / "lab" / "campaigns"):
        with pytest.raises(LabError):
            check_output_location(tracked)


def test_a_capture_session_is_sealed_with_its_lab_macs(tmp_path: Path) -> None:
    session = tmp_path / "20261029T000000Z"
    session.mkdir()
    (session / "benign-2026102900.pcap").write_bytes(b"pcap")
    macs = tmp_path / "lab_macs.txt"
    macs.write_text(
        "# lab devices\n02:AA:BB:CC:DD:EE kali joined 2026-10-29\n\n02-11-22-33-44-55 laptop\n",
        encoding="utf-8",
    )
    document = seal(session, "capture", "pi-live", macs, {"interface": "wlan0"}, on_pi=True)
    extra = document["extra"]
    assert isinstance(extra, dict)
    assert extra["lab_macs"] == ["02:aa:bb:cc:dd:ee", "02:11:22:33:44:55"]
    assert verify_tree(session).ok
    with pytest.raises(LabError):
        seal(session, "capture", "pi-live", macs, {}, on_pi=True)  # never re-sealed


def test_a_capture_cannot_be_sealed_pi_live_off_a_pi(tmp_path: Path) -> None:
    (tmp_path / "s").mkdir()
    with pytest.raises(LabError, match="not a Pi"):
        seal(tmp_path / "s", "capture", "pi-live", None, {}, on_pi=False)
    assert not (tmp_path / "s" / "manifest.json").exists()


def test_a_bad_lab_mac_line_is_refused(tmp_path: Path) -> None:
    bad = tmp_path / "lab_macs.txt"
    bad.write_text("kali 02:aa\n", encoding="utf-8")
    with pytest.raises(LabError, match="not a MAC"):
        read_lab_macs(bad)


def test_the_manifest_is_plain_json_with_the_env_tag(tmp_path: Path) -> None:
    run = _sealed(tmp_path / "run", "sandbox")
    raw = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    assert raw["schema"] == "pirewall-lab-manifest" and raw["env_tag"] == "sandbox"

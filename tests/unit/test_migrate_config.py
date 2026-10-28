"""`scripts.deployment.migrate_config`: 1.x and 2.0 local configs upgrade to the v2 schema, losslessly."""

import os
import stat
import sys
import tomllib
from pathlib import Path

import pytest
from scripts.deployment import migrate_config
from scripts.deployment.migrate_config import MigrationError, migrate_text

from pirewall.config.loader import load_config
from pirewall.config.models import GuardsConfig, PirewallConfig, PolicyConfig
from pirewall.core.enums import PipelineEngine
from tests.unit.test_config_loader import DEFAULT_CONFIG, MINIMAL_VALID_TOML

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "config"
SAMPLE_1X = FIXTURES / "local_config_1x.toml"
SAMPLE_2_0 = FIXTURES / "local_config_2_0.toml"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _copy(source: Path, tmp_path: Path) -> Path:
    target = tmp_path / "local_config.toml"
    target.write_text(_read(source), encoding="utf-8")
    return target


# --------------------------------------------------------------------- 1.x


def test_a_1x_config_is_upgraded_to_feature_schema_2_0_and_v2() -> None:
    result = migrate_text(_read(SAMPLE_1X))
    assert result.needed
    raw = tomllib.loads(result.text)
    assert raw["features"]["schema_version"] == "2.0.0"
    assert raw["ml"]["feature_schema_version"] == "2.0.0"
    assert raw["flow"]["active_timeout_seconds"] == 120
    assert raw["threat"]["behavior_weight"] == 80.0
    assert (raw["threat"]["known_attack_weight"], raw["threat"]["anomaly_weight"]) == (60.0, 15.0)
    assert raw["threat"]["behavior_pattern_points"]["scanning"] == 55.0
    for section in migrate_config.V2_SECTION_ORDER:
        assert section in raw, section
    # Left unset so it is derived, and follows the LAN if that moves.
    assert "lease_file" not in raw["antispoof"]
    migrated = PirewallConfig.model_validate(raw)
    assert migrated.antispoof.lease_file == "/var/lib/NetworkManager/dnsmasq-wlan0.leases"


def test_a_1x_migration_keeps_comments_and_untouched_values() -> None:
    original = _read(SAMPLE_1X).replace(
        "scanning_port_threshold = 10", "scanning_port_threshold = 12  # tuned for our NAS"
    )
    migrated = migrate_text(original).text
    assert "scanning_port_threshold = 12  # tuned for our NAS" in migrated
    for line in original.splitlines():
        if line.startswith("#"):
            assert line in migrated.splitlines(), line


def test_a_1x_migration_keeps_a_trailing_comment_on_a_rewritten_key() -> None:
    original = _read(SAMPLE_1X).replace(
        "active_timeout_seconds = 1800", "active_timeout_seconds = 1800   # long-lived SSH"
    )
    assert "active_timeout_seconds = 120   # long-lived SSH" in migrate_text(original).text


def test_custom_1x_weights_are_left_alone() -> None:
    original = _read(SAMPLE_1X).replace("known_attack_weight = 50.0", "known_attack_weight = 55.0")
    raw = tomllib.loads(migrate_text(original).text)
    assert (raw["threat"]["known_attack_weight"], raw["threat"]["anomaly_weight"]) == (55.0, 25.0)


# --------------------------------------------------------------------- 2.0


def test_a_2_0_config_only_gains_the_v2_sections() -> None:
    original = _read(SAMPLE_2_0)
    result = migrate_text(original)
    assert result.needed
    # Purely additive: the original file is a byte-for-byte prefix.
    assert result.text.startswith(original)
    assert [change.split(":")[0] for change in result.changes] == [
        f"[{section}]" for section in migrate_config.V2_SECTION_ORDER
    ]


def test_the_appended_sections_carry_the_model_defaults(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    path.write_text(migrate_text(_read(SAMPLE_2_0)).text, encoding="utf-8")
    config = load_config(path)
    assert config.guards == GuardsConfig()
    assert config.policy == PolicyConfig()
    assert config.pipeline.engine is PipelineEngine.V1


def test_a_section_that_is_already_present_is_not_touched() -> None:
    original = _read(SAMPLE_2_0) + '\n[pipeline]\nengine = "v2"  # trial\n'
    result = migrate_text(original)
    assert result.text.splitlines().count("[pipeline]") == 1
    assert 'engine = "v2"  # trial' in result.text
    assert "[pipeline]: added with v2 defaults" not in result.changes


# --------------------------------------------------------------------- already migrated


@pytest.mark.parametrize("source", [SAMPLE_1X, SAMPLE_2_0], ids=["from-1x", "from-2.0"])
def test_migration_is_idempotent(source: Path) -> None:
    once = migrate_text(_read(source)).text
    twice = migrate_text(once)
    assert not twice.needed
    assert twice.text == once


def test_the_shipped_default_config_is_already_migrated() -> None:
    assert not migrate_text(_read(DEFAULT_CONFIG)).needed


# --------------------------------------------------------------------- refusals


def test_invalid_toml_is_refused() -> None:
    with pytest.raises(MigrationError, match="not valid TOML"):
        migrate_text("[network\n")


def test_a_config_that_would_not_validate_is_refused() -> None:
    with pytest.raises(MigrationError, match="does not validate"):
        migrate_text(MINIMAL_VALID_TOML.replace('admin_pc_ip = "192.0.2.10"', ""))


def test_a_1x_file_missing_a_section_it_must_rewrite_is_refused() -> None:
    broken = _read(SAMPLE_1X).replace("[flow]", "[flow_renamed]")
    with pytest.raises(MigrationError, match=r"\[flow\] is missing"):
        migrate_text(broken)


# --------------------------------------------------------------------- CLI


def test_check_exits_non_zero_when_migration_is_needed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _copy(SAMPLE_1X, tmp_path)
    before = _read(path)
    assert migrate_config.main(["--config", str(path), "--check"]) == migrate_config.EXIT_MIGRATION_NEEDED
    assert _read(path) == before
    assert "migration needed" in capsys.readouterr().out
    assert list(tmp_path.iterdir()) == [path]


def test_check_exits_zero_on_a_migrated_file(tmp_path: Path) -> None:
    path = tmp_path / "local_config.toml"
    path.write_text(migrate_text(_read(SAMPLE_2_0)).text, encoding="utf-8")
    assert migrate_config.main(["--config", str(path), "--check"]) == migrate_config.EXIT_OK


def test_write_backs_up_the_original_then_migrates(tmp_path: Path) -> None:
    path = _copy(SAMPLE_1X, tmp_path)
    original = _read(path)
    assert migrate_config.main(["--config", str(path), "--write"]) == migrate_config.EXIT_OK
    backups = sorted(tmp_path.glob("local_config.toml.*.bak"))
    assert len(backups) == 1
    assert _read(backups[0]) == original
    assert _read(path) == migrate_text(original).text
    assert not (tmp_path / "local_config.toml.new").exists()
    assert migrate_config.main(["--config", str(path), "--check"]) == migrate_config.EXIT_OK


def test_write_on_a_migrated_file_changes_nothing_and_makes_no_backup(tmp_path: Path) -> None:
    path = tmp_path / "local_config.toml"
    path.write_text(migrate_text(_read(SAMPLE_2_0)).text, encoding="utf-8")
    assert migrate_config.main(["--config", str(path), "--write"]) == migrate_config.EXIT_OK
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_write_keeps_the_original_permissions_on_both_files(tmp_path: Path) -> None:
    path = _copy(SAMPLE_2_0, tmp_path)
    os.chmod(path, 0o600)
    assert migrate_config.main(["--config", str(path), "--write"]) == migrate_config.EXIT_OK
    (backup,) = tmp_path.glob("local_config.toml.*.bak")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600


@pytest.mark.parametrize("flag", ["--check", "--write"])
def test_unreadable_or_invalid_input_exits_with_the_error_code(tmp_path: Path, flag: str) -> None:
    missing = tmp_path / "absent.toml"
    assert migrate_config.main(["--config", str(missing), flag]) == migrate_config.EXIT_ERROR
    bad = tmp_path / "bad.toml"
    bad.write_text("not = [toml", encoding="utf-8")
    assert migrate_config.main(["--config", str(bad), flag]) == migrate_config.EXIT_ERROR
    assert _read(bad) == "not = [toml"


def test_exactly_one_mode_is_required() -> None:
    with pytest.raises(SystemExit):
        migrate_config.main([])
    with pytest.raises(SystemExit):
        migrate_config.main(["--check", "--write"])

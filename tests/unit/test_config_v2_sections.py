"""Phase-11 config additions: every v2 section is optional, defaulted, validated, and additive."""

import tomllib
from pathlib import Path
from typing import Any

import pytest

from pirewall.config.loader import load_config
from pirewall.config.models import (
    AntispoofConfig,
    GuardsConfig,
    LabConfig,
    PipelineConfig,
    PirewallConfig,
    PolicyConfig,
)
from pirewall.core.enums import EnvTag, GuardMode, PipelineEngine
from pirewall.core.exceptions import ConfigurationError
from tests.unit.test_config_loader import DEFAULT_CONFIG, MINIMAL_VALID_TOML

V2_SECTIONS = ("pipeline", "guards", "antispoof", "policy", "lab")
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "config"


def _minimal() -> dict[str, Any]:  # Any: raw TOML document under test
    return tomllib.loads(MINIMAL_VALID_TOML)


def test_shipped_default_config_matches_the_model_defaults_for_every_v2_section() -> None:
    # The TOML and the models must not drift: default_config.toml documents the
    # defaults, the models are what a config without the section gets.
    config = load_config(DEFAULT_CONFIG)
    assert config.pipeline == PipelineConfig()
    assert config.guards == GuardsConfig()
    assert config.antispoof == AntispoofConfig()
    assert config.policy == PolicyConfig()
    assert config.lab == LabConfig()
    assert config.capture.replay_speed == "max"


def test_shipped_default_config_declares_every_v2_section_explicitly() -> None:
    raw = tomllib.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
    for section in V2_SECTIONS:
        assert section in raw, section


def test_a_config_without_any_v2_section_still_loads_with_defaults(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(MINIMAL_VALID_TOML, encoding="utf-8")
    config = load_config(path)
    assert config.pipeline.engine is PipelineEngine.V1
    assert config.guards.raw_mode is GuardMode.ENFORCE
    assert config.guards.input_mode is GuardMode.ENFORCE
    assert config.guards.forward_mode is GuardMode.OBSERVE
    assert config.capture.backend == "auto"
    assert config.lab.env_tag is EnvTag.SANDBOX


@pytest.mark.parametrize("fixture", ["local_config_1x.toml", "local_config_2_0.toml"])
def test_pre_v2_local_configs_still_load_unmigrated(fixture: str) -> None:
    config = load_config(FIXTURES / fixture)
    assert config.pipeline.engine is PipelineEngine.V1


def test_the_default_env_tag_never_claims_a_pi_result() -> None:
    assert not LabConfig().env_tag.value.startswith("pi-")


def _validate(**sections: dict[str, Any]) -> PirewallConfig:  # Any: raw TOML tables
    document = _minimal()
    for name, table in sections.items():
        document[name] = {**document.get(name, {}), **table}
    return PirewallConfig.model_validate(document)


@pytest.mark.parametrize(
    "sections",
    [
        {"guards": {"no_such_key": 1}},
        {"pipeline": {"engine": "v3"}},
        {"guards": {"raw_mode": "drop"}},
        {"guards": {"syn": {"rate": 0, "burst": 400}}},
        {"guards": {"syn": {"rate": 200}}},
        {"policy": {"sustained_polls": 1}},
        {"policy": {"max_ttl_seconds": 7200}},
        {"policy": {"block_ttl_seconds": 1800, "max_ttl_seconds": 900}},
        {"lab": {"env_tag": "pi"}},
        {"lab": {"victim_network": "10.250.0.0/24"}},
        {"antispoof": {"static": [{"ip": "192.0.2.20", "mac": "ff:ff:ff:ff:ff:ff", "reason": "x"}]}},
        {"antispoof": {"static": [{"ip": "192.0.2.20", "mac": "02:00:00:00:00:20"}]}},
        {
            "antispoof": {
                "static": [
                    {"ip": "192.0.2.20", "mac": "02:00:00:00:00:20", "reason": "a"},
                    {"ip": "192.0.2.21", "mac": "02-00-00-00-00-20", "reason": "same MAC, other case"},
                ]
            }
        },
        {"capture": {"backend": "replay"}},
        {"capture": {"backend": "replay", "replay_path": "x.pcap", "replay_speed": "fast"}},
        {"capture": {"replay_speed": "x10"}},
    ],
)
def test_invalid_v2_settings_are_refused(sections: dict[str, dict[str, Any]]) -> None:
    with pytest.raises(ValueError):  # pydantic.ValidationError is a ValueError
        _validate(**sections)


@pytest.mark.parametrize("speed", ["max", "realtime", "10x", "2.5x"])
def test_replay_backend_is_accepted_with_a_source(speed: str) -> None:
    config = _validate(capture={"backend": "replay", "replay_path": "lab/mock/out", "replay_speed": speed})
    assert config.capture.backend == "replay"
    assert config.capture.replay_path == "lab/mock/out"


def test_static_bindings_are_normalised_and_loaded() -> None:
    config = _validate(
        antispoof={"static": [{"ip": "192.0.2.20", "mac": "02-AA-00-00-00-20", "reason": "NAS"}]}
    )
    (entry,) = config.antispoof.static
    assert entry.mac == "02:aa:00:00:00:20"


def test_a_full_v2_section_round_trips_through_the_loader(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        MINIMAL_VALID_TOML
        + """
[pipeline]
engine = "v2"

[guards]
forward_mode = "enforce"
syn = { rate = 150, burst = 300 }

[policy]
block_ttl_seconds = 600

[lab]
env_tag = "pi-scripted"
""",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.pipeline.engine is PipelineEngine.V2
    assert config.guards.forward_mode is GuardMode.ENFORCE
    assert (config.guards.syn.rate, config.guards.syn.burst) == (150, 300)
    assert config.guards.icmp == GuardsConfig().icmp
    assert config.policy.block_ttl_seconds == 600
    assert config.lab.env_tag is EnvTag.PI_SCRIPTED


def test_an_unknown_top_level_section_is_still_refused(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(MINIMAL_VALID_TOML + "\n[sensor]\nenabled = true\n", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(path)

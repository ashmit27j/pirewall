"""Config loader: valid TOML loads, missing/malformed input raises `ConfigurationError`."""

from pathlib import Path

import pytest

from pirewall.config.loader import load_config
from pirewall.core.enums import EnforcementMode, FailureMode
from pirewall.core.exceptions import ConfigurationError

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "config" / "default_config.toml"

MINIMAL_VALID_TOML = """
[network]
wan_interface = "eth0"
lan_interface = "eth1"
protected_network = "192.0.2.0/24"
upstream_gateway = "192.0.2.1"
pirewall_lan_ip = "192.0.2.2"

[capture]
interface = "eth1"

[flow]

[features]

[detection]

[ml]
lightgbm_model_path = "pirewall/ml/artifacts/lightgbm_model.txt"
isolation_forest_model_path = "pirewall/ml/artifacts/isolation_forest_model.joblib"

[threat]

[firewall]

[api]
tls_cert_path = "deploy/certificates/test.crt"
tls_key_path = "deploy/certificates/test.key"

[authentication]
admin_username = "admin"
admin_password_hash = "hash"

[admin]
admin_pc_ip = "192.0.2.10"

[logging]

[integration]

[security]

[failure]
"""


def test_shipped_default_config_loads() -> None:
    config = load_config(DEFAULT_CONFIG)
    assert config.firewall.enforcement_mode is EnforcementMode.SHADOW
    assert config.failure.mode is FailureMode.FAIL_OPEN


def test_minimal_valid_toml_loads(tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(MINIMAL_VALID_TOML, encoding="utf-8")
    config = load_config(config_file)
    assert config.network.wan_interface == "eth0"
    assert config.admin.admin_pc_ip.compressed == "192.0.2.10"


def test_missing_file_raises_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        load_config(tmp_path / "does_not_exist.toml")


def test_malformed_toml_raises_configuration_error(tmp_path: Path) -> None:
    config_file = tmp_path / "bad.toml"
    config_file.write_text("this is not [ valid toml", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_missing_required_admin_pc_ip_raises_configuration_error(tmp_path: Path) -> None:
    broken = MINIMAL_VALID_TOML.replace('admin_pc_ip = "192.0.2.10"', "")
    config_file = tmp_path / "config.toml"
    config_file.write_text(broken, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="admin_pc_ip"):
        load_config(config_file)


def test_missing_required_section_raises_configuration_error(tmp_path: Path) -> None:
    broken = MINIMAL_VALID_TOML.replace("[admin]\nadmin_pc_ip = \"192.0.2.10\"", "")
    config_file = tmp_path / "config.toml"
    config_file.write_text(broken, encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(config_file)


def test_missing_tls_cert_path_raises_configuration_error(tmp_path: Path) -> None:
    """spec §28/§29 TLS: a deployment with no certificate configured must fail loudly, not start."""
    broken = MINIMAL_VALID_TOML.replace('tls_cert_path = "deploy/certificates/test.crt"\n', "")
    config_file = tmp_path / "config.toml"
    config_file.write_text(broken, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="tls_cert_path"):
        load_config(config_file)


def test_missing_tls_key_path_raises_configuration_error(tmp_path: Path) -> None:
    broken = MINIMAL_VALID_TOML.replace('tls_key_path = "deploy/certificates/test.key"\n', "")
    config_file = tmp_path / "config.toml"
    config_file.write_text(broken, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="tls_key_path"):
        load_config(config_file)


def test_empty_tls_cert_path_raises_configuration_error(tmp_path: Path) -> None:
    """An empty string is present-but-useless — must be rejected the same as missing entirely."""
    broken = MINIMAL_VALID_TOML.replace(
        'tls_cert_path = "deploy/certificates/test.crt"', 'tls_cert_path = ""'
    )
    config_file = tmp_path / "config.toml"
    config_file.write_text(broken, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="tls_cert_path"):
        load_config(config_file)

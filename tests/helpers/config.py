"""Factory for a complete, valid `PirewallConfig` in tests, with per-section overrides."""

from typing import Any

from pirewall.config.models import PirewallConfig

_BASE: dict[str, dict[str, object]] = {
    "network": {
        "wan_interface": "eth0",
        "lan_interface": "eth1",
        "protected_network": "192.168.1.0/24",
        "upstream_gateway": "192.168.1.1",
    },
    "capture": {"interface": "eth1"},
    "flow": {},
    "features": {},
    "detection": {},
    "ml": {
        "lightgbm_model_path": "pirewall/ml/artifacts/lightgbm_model.txt",
        "isolation_forest_model_path": "pirewall/ml/artifacts/isolation_forest_model.joblib",
    },
    "threat": {},
    "firewall": {},
    "api": {"tls_cert_path": "deploy/certificates/test.crt", "tls_key_path": "deploy/certificates/test.key"},
    "authentication": {"admin_username": "admin", "admin_password_hash": "hash"},
    "admin": {"admin_pc_ip": "192.168.1.50"},
    "logging": {},
    "integration": {},
    "security": {},
    "failure": {},
}


def make_config(**section_overrides: dict[str, Any]) -> PirewallConfig:
    """Build a complete, valid `PirewallConfig`. Pass e.g. `firewall={"enforcement_mode": "active"}`."""
    merged: dict[str, dict[str, object]] = {
        section: dict(fields) for section, fields in _BASE.items()
    }
    for section, overrides in section_overrides.items():
        merged[section] = {**merged.get(section, {}), **overrides}
    return PirewallConfig.model_validate(merged)

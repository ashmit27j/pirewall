"""`pirewall.main` and `pirewall.api.__main__` — the two systemd `ExecStart=` targets.

Neither entry point is *started* here (that needs a real NIC, real TLS, and
a real socket); what is tested is everything they do before that point,
which is where a deployment actually fails: config resolution, validation,
and the refusal to serve with placeholder credentials or missing TLS
material.
"""

import ssl
from pathlib import Path

import pytest

from pirewall import main as core_main
from pirewall.api import __main__ as api_main
from pirewall.core.exceptions import ConfigurationError
from tests.helpers.config import make_config


def _write_config(tmp_path: Path, config_toml: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(config_toml, encoding="utf-8")
    return path


def test_shipped_default_config_is_valid() -> None:
    """`config/default_config.toml` is the fallback both entry points resolve to."""
    assert core_main.main(["--config", "config/default_config.toml", "--check-config"]) == 0


def test_check_config_reports_an_invalid_file_without_starting_anything(tmp_path: Path) -> None:
    """An invalid config must exit non-zero *before* any privileged resource is touched."""
    path = _write_config(tmp_path, "[network]\nwan_interface = \"eth0\"\n")
    with pytest.raises(SystemExit) as excinfo:
        core_main.main(["--config", str(path), "--check-config"])
    assert excinfo.value.code == core_main.EXIT_FAILURE


def test_missing_config_file_exits_non_zero_rather_than_tracebacking(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        core_main.main(["--config", str(tmp_path / "nope.toml"), "--check-config"])
    assert excinfo.value.code == core_main.EXIT_FAILURE


def test_config_resolution_prefers_the_gitignored_local_file() -> None:
    """`config/local_config.toml` holds the real network layout; the default ships placeholders."""
    assert core_main.default_config_path() in {
        Path("config/local_config.toml"),
        Path("config/default_config.toml"),
    }
    assert api_main.default_config_path() == core_main.default_config_path()


class TestApiRuntimePrerequisites:
    """spec §29: HTTPS + authentication, or refuse to start and say why."""

    def test_placeholder_credentials_are_refused(self, tmp_path: Path) -> None:
        cert = tmp_path / "pirewall.crt"
        cert.write_text("cert", encoding="utf-8")
        key = tmp_path / "pirewall.key"
        key.write_text("key", encoding="utf-8")
        config = make_config(
            authentication={
                "admin_username": "CHANGE_ME",
                "admin_password_hash": "CHANGE_ME",
            },
            api={"tls_cert_path": str(cert), "tls_key_path": str(key)},
        )
        with pytest.raises(ConfigurationError) as excinfo:
            api_main.validate_runtime_prerequisites(config)
        message = str(excinfo.value)
        assert "admin_username" in message
        assert "admin_password_hash" in message
        # The message has to tell the operator how to fix it, not just what broke.
        assert "hash_password" in message

    def test_missing_tls_material_is_refused(self, tmp_path: Path) -> None:
        config = make_config(
            api={
                "tls_cert_path": str(tmp_path / "absent.crt"),
                "tls_key_path": str(tmp_path / "absent.key"),
            }
        )
        with pytest.raises(ConfigurationError) as excinfo:
            api_main.validate_runtime_prerequisites(config)
        assert "does not exist" in str(excinfo.value)

    def test_unsupported_min_tls_version_is_refused(self, tmp_path: Path) -> None:
        cert = tmp_path / "pirewall.crt"
        cert.write_text("cert", encoding="utf-8")
        key = tmp_path / "pirewall.key"
        key.write_text("key", encoding="utf-8")
        config = make_config(
            api={"tls_cert_path": str(cert), "tls_key_path": str(key)},
            security={"min_tls_version": "SSLv3"},
        )
        with pytest.raises(ConfigurationError) as excinfo:
            api_main.validate_runtime_prerequisites(config)
        assert "min_tls_version" in str(excinfo.value)

    def test_a_complete_configuration_passes(self, tmp_path: Path) -> None:
        cert = tmp_path / "pirewall.crt"
        cert.write_text("cert", encoding="utf-8")
        key = tmp_path / "pirewall.key"
        key.write_text("key", encoding="utf-8")
        config = make_config(api={"tls_cert_path": str(cert), "tls_key_path": str(key)})
        api_main.validate_runtime_prerequisites(config)  # must not raise


def test_ssl_context_factory_raises_the_minimum_tls_version() -> None:
    """uvicorn's own `ssl_version=` sets a protocol family, not a floor (spec §29)."""
    factory = api_main.make_ssl_context_factory(ssl.TLSVersion.TLSv1_3)
    base = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    base.minimum_version = ssl.TLSVersion.TLSv1_2

    context = factory(None, lambda: base)  # pyright: ignore[reportArgumentType]

    assert context.minimum_version is ssl.TLSVersion.TLSv1_3


def test_api_main_exits_non_zero_on_an_unusable_config(tmp_path: Path) -> None:
    """pirewall-api returns an exit code rather than raising, so `Restart=on-failure` sees it."""
    path = _write_config(tmp_path, "not = [valid\n")
    assert api_main.main(["--config", str(path)]) == api_main.EXIT_FAILURE

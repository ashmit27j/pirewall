"""Loads and validates `PirewallConfig` from a TOML file."""

import tomllib
from pathlib import Path

from pydantic import ValidationError

from pirewall.config.models import PirewallConfig
from pirewall.core.exceptions import ConfigurationError


def load_config(path: Path | str) -> PirewallConfig:
    """Read the TOML file at `path` and validate it into a `PirewallConfig`.

    Raises `ConfigurationError` (never a raw `tomllib`/`pydantic` exception)
    if the file is missing, malformed, or fails validation — including a
    missing required security-relevant field such as `admin.admin_pc_ip`.
    """
    config_path = Path(path)
    try:
        raw_bytes = config_path.read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"could not read config file at {config_path}: {exc}") from exc

    try:
        raw_data = tomllib.loads(raw_bytes.decode("utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigurationError(f"malformed TOML in {config_path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigurationError(f"config file {config_path} is not valid UTF-8: {exc}") from exc

    try:
        return PirewallConfig.model_validate(raw_data)
    except ValidationError as exc:
        raise ConfigurationError(f"invalid configuration in {config_path}:\n{exc}") from exc

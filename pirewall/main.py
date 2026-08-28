"""`pirewall-core` entry point — `python -m pirewall.main` (spec §42, §43).

The privileged half of the ADDENDUM.md A4 process split: this is the only
process that opens an `AF_PACKET` socket or talks to nftables. It is
deliberately thin. Everything it does is:

1. Parse arguments (just a config path).
2. Load and validate `PirewallConfig` — a `ConfigurationError` here exits
   non-zero *before* any privileged resource is touched, so an invalid
   config can never leave a half-started firewall behind.
3. Configure logging (`pirewall.core.logging`).
4. Build a `pirewall.runtime.core.CoreDaemon` and run it.

All the actual wiring lives in `pirewall.runtime.core`; keeping it out of
here is what makes the whole daemon testable without a `__main__` guard,
without root, and without a real NIC.

Config-file resolution: `--config` if given, otherwise
`config/local_config.toml` if it exists, otherwise
`config/default_config.toml`. The local file is gitignored and holds the
real network layout; the default file ships placeholders and is the
fallback so a fresh checkout still starts and fails with a clear message
about `CHANGE_ME` values rather than a missing-file traceback.

Exit codes: `0` clean shutdown, `1` fatal startup failure (bad config,
unbindable RPC socket). A non-zero exit is what makes
`Restart=on-failure` + `StartLimitBurst=` in
`deploy/systemd/pirewall-core.service` detect a crash-loop (ADDENDUM.md A6).
"""

import argparse
import logging
import sys
from pathlib import Path

from pirewall.config.loader import load_config
from pirewall.config.models import PirewallConfig
from pirewall.core.exceptions import ConfigurationError, PirewallError
from pirewall.core.logging import configure_logging
from pirewall.runtime.core import CoreDaemon

_COMPONENT = "core"
_DEFAULT_CONFIG_PATHS = (Path("config/local_config.toml"), Path("config/default_config.toml"))

EXIT_OK = 0
EXIT_FAILURE = 1


def default_config_path() -> Path:
    """First existing entry in `_DEFAULT_CONFIG_PATHS`, or the last one as a reportable target."""
    for candidate in _DEFAULT_CONFIG_PATHS:
        if candidate.is_file():
            return candidate
    return _DEFAULT_CONFIG_PATHS[-1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pirewall-core",
        description="pirewall packet capture, detection, and firewall enforcement daemon.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="path to a pirewall TOML config file (default: config/local_config.toml, "
        "falling back to config/default_config.toml)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate the configuration and exit without starting capture or binding sockets",
    )
    return parser


def load(config_path: Path) -> PirewallConfig:
    """Load and validate the config, or exit non-zero with an actionable message."""
    try:
        return load_config(config_path)
    except ConfigurationError as exc:
        print(f"pirewall-core: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_FAILURE) from exc


def main(argv: list[str] | None = None) -> int:
    """Run pirewall-core. Returns the process exit code."""
    args = build_parser().parse_args(argv)
    config_path = args.config if args.config is not None else default_config_path()
    config = load(config_path)

    if args.check_config:
        print(f"pirewall-core: configuration at {config_path} is valid")
        return EXIT_OK

    log_path = configure_logging(config.logging, _COMPONENT)
    logger = logging.getLogger(__name__)
    logger.info("pirewall-core starting with config %s (log: %s)", config_path, log_path or "stderr")

    daemon = CoreDaemon(config)
    daemon.install_signal_handlers()
    try:
        daemon.start()
    except PirewallError as exc:
        logger.critical("pirewall-core failed to start: %s", exc)
        daemon.stop()
        return EXIT_FAILURE
    return daemon.run()


if __name__ == "__main__":
    raise SystemExit(main())

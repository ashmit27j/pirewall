"""`pirewall.core.logging.configure_logging` (spec §38).

The behaviour worth pinning down is the failure path: a firewall that
refuses to start because it could not open its log file would be strictly
worse than one that starts and logs to stderr, and `/var/log/pirewall` (the
shipped default) does not exist on any development machine.
"""

import logging
from pathlib import Path

from pirewall.config.models import LoggingConfig
from pirewall.core.logging import configure_logging, resolve_level


def _restore_root_logger() -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()


def test_opens_a_rotating_file_named_for_the_component(tmp_path: Path) -> None:
    try:
        path = configure_logging(LoggingConfig(log_dir=str(tmp_path)), "core")
        assert path == tmp_path / "core.log"
        logging.getLogger("test").info("hello")
        assert path is not None
        assert "hello" in path.read_text(encoding="utf-8")
    finally:
        _restore_root_logger()


def test_core_and_api_never_share_a_log_file(tmp_path: Path) -> None:
    """The two processes run as different users writing into the same directory."""
    try:
        core = configure_logging(LoggingConfig(log_dir=str(tmp_path)), "core")
        api = configure_logging(LoggingConfig(log_dir=str(tmp_path)), "api")
        assert core != api
    finally:
        _restore_root_logger()


def test_unwritable_log_dir_degrades_to_stderr_instead_of_raising(tmp_path: Path) -> None:
    """A log directory that cannot be created must not stop pirewall from starting."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")
    try:
        path = configure_logging(LoggingConfig(log_dir=str(blocker / "logs")), "core")
        assert path is None
        assert any(
            isinstance(handler, logging.StreamHandler) for handler in logging.getLogger().handlers
        )
    finally:
        _restore_root_logger()


def test_calling_twice_replaces_handlers_rather_than_doubling_them(tmp_path: Path) -> None:
    try:
        configure_logging(LoggingConfig(log_dir=str(tmp_path)), "core")
        first = len(logging.getLogger().handlers)
        configure_logging(LoggingConfig(log_dir=str(tmp_path)), "core")
        assert len(logging.getLogger().handlers) == first
    finally:
        _restore_root_logger()


def test_unknown_level_name_falls_back_to_info_rather_than_failing() -> None:
    """The level is cosmetic; refusing to start over a typo would be disproportionate."""
    assert resolve_level("DEBUG") == logging.DEBUG
    assert resolve_level("  warning ") == logging.WARNING
    assert resolve_level("NOT_A_LEVEL") == logging.INFO

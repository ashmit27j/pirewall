"""Centralized logging setup for both pirewall processes (spec §38).

Both `pirewall-core` (`pirewall.main`) and `pirewall-api`
(`pirewall.api.__main__`) call `configure_logging` exactly once, at startup,
before any subsystem is constructed. Every module elsewhere in the codebase
keeps using a plain module-level `logging.getLogger(__name__)` — this module
only configures the *root* logger's handlers, so nothing else has to know
logging exists.

Two design points worth stating explicitly:

* **Failing to open the log file is not fatal.** `logging.log_dir` defaults
  to `/var/log/pirewall`, which does not exist on a development machine and
  is not writable by an unprivileged user. A firewall that refuses to start
  because it could not open its log file is strictly worse than one that
  starts and logs to stderr (journald captures stderr under systemd), so a
  failure here is reported on stderr and downgraded to stderr-only logging.
  `configure_logging` returns the path it actually opened, or `None`, so the
  caller can say which happened in its own startup log line.
* **Rotation is bounded by config**, `logging.max_bytes` /
  `logging.backup_count` — a long-running capture process must never be able
  to fill the Pi's SD card with its own logs.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from pirewall.config.models import LoggingConfig

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


def resolve_level(level_name: str) -> int:
    """Map a `logging.level` config string to a stdlib level, defaulting to INFO.

    An unrecognized name is not a fatal configuration error: the value is
    cosmetic, and refusing to start over it would be disproportionate. INFO
    is the documented default in `config/default_config.toml`.
    """
    resolved = logging.getLevelNamesMapping().get(level_name.strip().upper())
    return resolved if resolved is not None else logging.INFO


def configure_logging(config: LoggingConfig, component: str) -> Path | None:
    """Install stderr + rotating-file handlers on the root logger for `component`.

    `component` names the log file (`<log_dir>/<component>.log`) and is what
    distinguishes pirewall-core's log from pirewall-api's — the two run as
    different users writing into the same directory, so they must never
    share a file.

    Returns the log file path that was successfully opened, or `None` if
    only stderr logging is active. Idempotent in the sense that it always
    replaces the root logger's handlers rather than appending to them, so
    calling it twice cannot double every log line.
    """
    root = logging.getLogger()
    root.setLevel(resolve_level(config.level))
    for existing in list(root.handlers):
        root.removeHandler(existing)
        existing.close()

    formatter = logging.Formatter(fmt=_LOG_FORMAT, datefmt=_DATE_FORMAT)

    stream_handler = logging.StreamHandler(stream=sys.stderr)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    log_path = Path(config.log_dir) / f"{component}.log"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=config.max_bytes,
            backupCount=config.backup_count,
            encoding="utf-8",
        )
    except OSError as exc:
        # Deliberately not raising: see the module docstring. print() rather
        # than a logger call because the root logger is mid-configuration.
        print(
            f"pirewall: could not open log file {log_path} ({exc}); logging to stderr only",
            file=sys.stderr,
        )
        return None

    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    return log_path

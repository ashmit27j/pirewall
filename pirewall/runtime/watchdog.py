"""`sd_notify` support for `Type=notify` + `WatchdogSec=` (ADDENDUM.md A6).

`deploy/systemd/pirewall-core.service` declares `Type=notify` and
`WatchdogSec=30s`. Both are promises this module has to keep:

* `Type=notify` means systemd holds the unit in `activating` until the
  process sends `READY=1`. Without that, `systemctl start pirewall-core`
  hangs until the start timeout and then kills the process — so a daemon
  that never calls `notify_ready()` cannot be started at all.
* `WatchdogSec=` means systemd kills and restarts the process if it does
  not receive `WATCHDOG=1` within the window. A6 wants exactly that: a
  wedged capture/detection loop must be *detected*, not silently tolerated.

Implemented against the `sd_notify` protocol directly (a datagram to the
`AF_UNIX` socket named by `$NOTIFY_SOCKET`) rather than via
`python-systemd`, which is a compiled dependency not on `CLAUDE.md`'s
allowed list and unnecessary for a protocol this small.

**Outside systemd `$NOTIFY_SOCKET` is unset**, so every method is a no-op
and `enabled` is `False`. That is what lets `python -m pirewall.main` run
identically from a shell for testing.
"""

import logging
import os
import socket

_logger = logging.getLogger(__name__)

_NOTIFY_SOCKET_ENV = "NOTIFY_SOCKET"
# systemd's abstract-namespace sockets are spelled with a leading '@',
# which maps to a leading NUL byte in the sockaddr (see sd_notify(3)).
_ABSTRACT_PREFIX = "@"


class SystemdNotifier:
    """Sends `sd_notify` datagrams to systemd, or does nothing when not run by systemd."""

    def __init__(self, notify_socket: str | None = None) -> None:
        self._address = self._resolve_address(
            notify_socket if notify_socket is not None else os.environ.get(_NOTIFY_SOCKET_ENV)
        )

    @staticmethod
    def _resolve_address(raw: str | None) -> str | None:
        if not raw:
            return None
        if raw.startswith(_ABSTRACT_PREFIX):
            return "\0" + raw[1:]
        return raw

    @property
    def enabled(self) -> bool:
        """`True` only when systemd actually asked to be notified."""
        return self._address is not None

    def notify_ready(self, status: str) -> None:
        """Tell systemd startup finished. Until this lands the unit stays in `activating`."""
        self._send(f"READY=1\nSTATUS={status}")

    def notify_watchdog(self) -> None:
        """One watchdog heartbeat. Must arrive more often than `WatchdogSec=`."""
        self._send("WATCHDOG=1")

    def notify_stopping(self, status: str) -> None:
        """Tell systemd a clean shutdown is in progress, so it isn't mistaken for a crash."""
        self._send(f"STOPPING=1\nSTATUS={status}")

    def notify_status(self, status: str) -> None:
        """Update the one-line status `systemctl status` shows."""
        self._send(f"STATUS={status}")

    def _send(self, message: str) -> None:
        address = self._address
        if address is None:
            return
        try:
            # Python sockets are close-on-exec by default (PEP 446), so no
            # SOCK_CLOEXEC here — it is a Linux-only constant and pirewall is
            # developed on macOS.
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                sock.connect(address)
                sock.sendall(message.encode("utf-8"))
        except OSError as exc:
            # Never fatal: failing to notify systemd is a supervision
            # problem, not a reason to stop filtering traffic (A6
            # fail-open). systemd's own watchdog will restart us if the
            # heartbeats really have stopped arriving.
            _logger.warning("sd_notify failed (%s): %s", message.splitlines()[0], exc)

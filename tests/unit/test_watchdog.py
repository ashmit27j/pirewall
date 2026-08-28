"""`pirewall.runtime.watchdog.SystemdNotifier` (ADDENDUM.md A6).

`deploy/systemd/pirewall-core.service` declares `Type=notify`, which means
systemd holds the unit in `activating` until `READY=1` arrives — a daemon
that never sends it cannot be started at all. These tests send against a
real `AF_UNIX` datagram socket rather than a mock, so the wire format is
actually exercised.
"""

import socket
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from pirewall.runtime.watchdog import SystemdNotifier

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="platform has no AF_UNIX support"
)


@pytest.fixture
def notify_socket() -> Iterator[tuple[socket.socket, str]]:
    """A real datagram socket standing in for systemd's `$NOTIFY_SOCKET`.

    Short temp dir: `AF_UNIX` paths are capped at ~104 bytes on macOS.
    """
    with tempfile.TemporaryDirectory(prefix="pw") as directory:
        path = str(Path(directory) / "n.sock")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(path)
        sock.settimeout(5.0)
        try:
            yield sock, path
        finally:
            sock.close()


def test_disabled_when_not_run_under_systemd(monkeypatch: pytest.MonkeyPatch) -> None:
    """No `$NOTIFY_SOCKET` means `python -m pirewall.main` from a shell works unchanged."""
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    notifier = SystemdNotifier()
    assert notifier.enabled is False
    # Every method must be a silent no-op, not a crash.
    notifier.notify_ready("up")
    notifier.notify_watchdog()
    notifier.notify_status("fine")
    notifier.notify_stopping("bye")


def test_ready_and_watchdog_datagrams_reach_systemd(
    notify_socket: tuple[socket.socket, str],
) -> None:
    sock, path = notify_socket
    notifier = SystemdNotifier(path)
    assert notifier.enabled is True

    notifier.notify_ready("mode=shadow")
    assert sock.recv(4096).decode("utf-8") == "READY=1\nSTATUS=mode=shadow"

    notifier.notify_watchdog()
    assert sock.recv(4096).decode("utf-8") == "WATCHDOG=1"

    notifier.notify_stopping("shutting down")
    assert sock.recv(4096).decode("utf-8") == "STOPPING=1\nSTATUS=shutting down"


def test_abstract_socket_names_are_translated_to_a_leading_nul() -> None:
    """systemd spells abstract-namespace sockets '@name'; the sockaddr needs a NUL (sd_notify(3))."""
    notifier = SystemdNotifier("@pirewall-test")
    assert notifier.enabled is True
    # The address is private, but the translation is the whole contract, so
    # assert on it rather than on an unobservable side effect.
    assert notifier._address == "\0pirewall-test"  # pyright: ignore[reportPrivateUsage]


def test_a_send_failure_is_survivable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Failing to notify systemd is a supervision problem, not a reason to stop filtering (A6)."""
    notifier = SystemdNotifier("/nonexistent/directory/notify.sock")
    assert notifier.enabled is True
    notifier.notify_watchdog()  # must not raise

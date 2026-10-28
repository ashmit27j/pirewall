"""Lease sync: the dnsmasq lease file -> `LeaseBindingTable` -> the kernel binding sets (ADDENDUM_4.md D3).

One core thread (`pirewall-lease-sync`), replacing the separate
`pirewall-leases` unit the template header still names (critique_round2.md
item 8: a second privileged writer would break D1's single-writer rule, and
nothing needs it, because binding elements already outlive core).

Each pass re-reads the whole lease file (`antispoof.lease_file`), parses it
strictly (`pirewall.core.bindings.parse_leases`), hands the full lease set to
the binding table, and writes whatever changed through
`FirewallManager.sync_bindings`, one nft batch with removals first. A pass
runs every `antispoof.poll_seconds`, and sooner when inotify reports the
file changed (where inotify is available: Linux, through libc; otherwise the
poll alone). The poll is needed anyway: a lease that expires changes the
binding set without the file changing.

**Failure handling, and why it is asymmetric.**

* **At startup (`seed`)** the kernel's binding sets must be made to match
  the lease file before the raw guard's spoof drop can be trusted. If the
  file cannot be read or the kernel refuses the batch, the raw guard is
  set to observe and a SYSTEM_WARNING says so (D2: raw is enforce *if
  seeded*). It is not switched back to enforce on its own: ENFORCE is an
  admin decision (V2_CONTRACTS §9 re-authenticates it).
* **While running (`poll`)** an unreadable file keeps the last known
  bindings rather than dropping them. Treating it as empty would unbind
  every device at once, sending the whole LAN into the tightly metered
  unbound class. Leases still age out on their expiry, and the kernel
  elements on their own timeouts. A refused kernel write is retried as a
  full replacement on the next pass, so the kernel cannot stay out of step
  with the table.

This thread never takes core's RPC lock (V2_CONTRACTS §9). The table has
its own lock and the manager serializes its own set-backend calls.

Nothing from the lease file's hostname or client-id fields ever reaches a
log line or an event: only counts.
"""

import contextlib
import ctypes
import logging
import os
import select
import struct
import sys
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from pirewall.config.models import PirewallConfig
from pirewall.core.bindings import (
    MAX_LEASE_FILE_BYTES,
    IgnoredLease,
    LeaseBindingTable,
    LeaseParse,
    parse_leases,
)
from pirewall.core.enums import EventSeverity, GuardMode, GuardName, SecurityEventType
from pirewall.core.exceptions import FirewallError
from pirewall.core.models.event import SecurityEvent
from pirewall.firewall.manager import FirewallManager

_logger = logging.getLogger(__name__)
_SUBSYSTEM = "runtime.lease_sync"
SEED_FAILURE_ACTOR: Final = "pirewall-core (binding seed failed)"
"""The `actor` recorded on the raw guard's automatic downgrade to observe."""

# inotify(7): the events that mean "the file's contents may have changed".
_IN_MODIFY = 0x00000002
_IN_CLOSE_WRITE = 0x00000008
_IN_MOVED_FROM = 0x00000040
_IN_MOVED_TO = 0x00000080
_IN_CREATE = 0x00000100
_IN_DELETE = 0x00000200
_WATCH_MASK = _IN_MODIFY | _IN_CLOSE_WRITE | _IN_MOVED_FROM | _IN_MOVED_TO | _IN_CREATE | _IN_DELETE
_IN_NONBLOCK = 0o4000
_IN_CLOEXEC = 0o2000000
_EVENT_HEADER = struct.Struct("iIII")  # wd, mask, cookie, name length
_READ_CHUNK = 64 * 1024


class LeaseFileWatcher:
    """Waits for the lease file to change: inotify on its directory where available, else just a timeout.

    The directory is watched, not the file, because the file may be
    replaced by rename, and a watch on the old inode would go quiet.
    """

    def __init__(self, path: Path) -> None:
        self._name = os.fsencode(path.name)
        self._fd: int | None = _open_inotify(path.parent)

    @property
    def uses_inotify(self) -> bool:
        """Whether change notifications are live (otherwise `wait` is a plain timeout)."""
        return self._fd is not None

    def wait(self, timeout_seconds: float, stop: threading.Event) -> bool:
        """Block up to `timeout_seconds`. True if the lease file changed, False on timeout or stop."""
        fd = self._fd
        if fd is None:
            stop.wait(timeout_seconds)
            return False
        try:
            ready, _, _ = select.select([fd], [], [], timeout_seconds)
            if not ready:
                return False
            data = os.read(fd, _READ_CHUNK)
        except (BlockingIOError, InterruptedError):
            return False
        except OSError as exc:
            _logger.warning("inotify on the lease directory failed (%s); polling only", exc)
            self.close()
            return False
        return self._name in _event_names(data)

    def close(self) -> None:
        """Release the inotify descriptor. Idempotent."""
        fd, self._fd = self._fd, None
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)


def _open_inotify(directory: Path) -> int | None:
    if sys.platform != "linux":
        return None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        add_watch = libc.inotify_add_watch
    except (OSError, AttributeError):
        return None
    init.argtypes = [ctypes.c_int]
    init.restype = ctypes.c_int
    add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    add_watch.restype = ctypes.c_int
    fd = int(init(_IN_NONBLOCK | _IN_CLOEXEC))
    if fd < 0:
        return None
    if int(add_watch(fd, os.fsencode(directory), _WATCH_MASK)) < 0:
        os.close(fd)
        return None
    return fd


def _event_names(data: bytes) -> set[bytes]:
    names: set[bytes] = set()
    offset = 0
    while offset + _EVENT_HEADER.size <= len(data):
        _, _, _, length = _EVENT_HEADER.unpack_from(data, offset)
        start = offset + _EVENT_HEADER.size
        names.add(data[start : start + length].rstrip(b"\0"))
        offset = start + length
    return names


class LeaseSync:
    """Keeps `LeaseBindingTable` and the kernel binding sets in step with the lease file."""

    def __init__(
        self,
        config: PirewallConfig,
        table: LeaseBindingTable,
        manager: FirewallManager,
        on_event: Callable[[SecurityEvent], None],
        now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._path = Path(config.antispoof.lease_file)
        self._poll_seconds = config.antispoof.poll_seconds
        self._protected = config.network.protected_network
        self._table = table
        self._manager = manager
        self._on_event = on_event
        self._now_fn = now_fn
        self._needs_full_resync = False
        self._read_failing = False
        self._last_ignored: Mapping[IgnoredLease, int] = {}
        self.passes = 0
        self.failures = 0

    def seed(self) -> bool:
        """Startup: bind the kernel sets to the lease file and static config. False if that failed.

        On failure the raw guard goes to observe (module docstring). Static
        bindings are still written, best effort, so a device declared in
        `[[antispoof.static]]` resolves either way.
        """
        now = self._now_fn()
        parsed, read_error = self._read()
        if parsed is not None:
            self._table.apply_leases(parsed.bindings, now)
        try:
            self._manager.replace_bindings(self._table.snapshot(), now)
        except FirewallError as exc:
            self._seed_failed(f"writing the binding sets failed: {exc}", now)
            return False
        if parsed is None:
            self._seed_failed(f"the lease file could not be read: {read_error}", now)
            return False
        bound = len(self._table.snapshot())
        _logger.info("binding seed: %d binding(s) from %s and static config", bound, self._path)
        return True

    def poll(self) -> int:
        """One pass: re-read, re-apply, write what changed. Returns the ops written (0 if nothing changed)."""
        now = self._now_fn()
        self.passes += 1
        parsed, read_error = self._read()
        if parsed is None:
            if not self._read_failing:
                self._read_failing = True
                self._emit(
                    EventSeverity.ERROR,
                    f"the lease file {self._path} could not be read ({read_error}); keeping the "
                    "last known bindings until it can",
                    now,
                )
            # Age out what has expired, from what we already hold.
            leases = [binding for binding in self._table.snapshot() if binding.expires_at is not None]
        else:
            if self._read_failing:
                self._read_failing = False
                self._emit(EventSeverity.INFO, f"the lease file {self._path} is readable again", now)
            leases = list(parsed.bindings)
        change = self._table.apply_leases(leases, now)
        try:
            if self._needs_full_resync:
                written = self._manager.replace_bindings(self._table.snapshot(), now)
                self._needs_full_resync = False
                return written
            return self._manager.sync_bindings(change, now)
        except FirewallError as exc:
            self.failures += 1
            self._needs_full_resync = True
            self._emit(EventSeverity.ERROR, f"binding sync failed, retrying as a full resync: {exc}", now)
            return 0

    def run(self, stop: threading.Event) -> None:
        """The thread body: `poll` on every lease-file change and every `antispoof.poll_seconds`."""
        watcher = LeaseFileWatcher(self._path)
        _logger.info(
            "lease sync watching %s (%s, poll every %.1fs)",
            self._path,
            "inotify" if watcher.uses_inotify else "polling only",
            self._poll_seconds,
        )
        try:
            while not stop.is_set():
                watcher.wait(self._poll_seconds, stop)
                if stop.is_set():
                    break
                try:
                    self.poll()
                except Exception:  # never let one bad pass end lease sync for the process lifetime
                    self.failures += 1
                    _logger.exception("lease sync pass failed")
        finally:
            watcher.close()

    def _read(self) -> tuple[LeaseParse | None, str]:
        try:
            with self._path.open("rb") as handle:
                raw = handle.read(MAX_LEASE_FILE_BYTES + 1)
        except OSError as exc:
            return None, exc.strerror or type(exc).__name__
        if len(raw) > MAX_LEASE_FILE_BYTES:
            return None, f"larger than {MAX_LEASE_FILE_BYTES} bytes"
        # Undecodable bytes can only be in fields that are never read.
        parsed = parse_leases(raw.decode("utf-8", errors="replace"), self._protected)
        if parsed.ignored and parsed.ignored != self._last_ignored:
            counts = ", ".join(f"{reason.value}={count}" for reason, count in sorted(parsed.ignored.items()))
            _logger.info("lease file: ignored %d line(s) (%s)", parsed.ignored_total, counts)
        self._last_ignored = parsed.ignored
        return parsed, ""

    def _seed_failed(self, why: str, now: datetime) -> None:
        self.failures += 1
        downgraded = ""
        hint = ""
        if self._manager.uses_set_backend:
            hint = (
                ". Fix the cause, then put the raw guard back in enforce mode (set_guard_mode, "
                "or reload the static template with pirewall-start)"
            )
            try:
                self._on_event(
                    self._manager.set_guard_mode(GuardName.RAW, GuardMode.OBSERVE, SEED_FAILURE_ACTOR, now)
                )
                downgraded = "; the raw guard is now in observe mode (anti-spoof records but does not drop)"
            except FirewallError as exc:
                downgraded = f"; setting the raw guard to observe ALSO failed: {exc}"
        self._emit(
            EventSeverity.CRITICAL if "ALSO failed" in downgraded else EventSeverity.WARNING,
            f"binding seed failed, {why}{downgraded}{hint}.",
            now,
        )

    def _emit(self, severity: EventSeverity, reason: str, now: datetime) -> None:
        self._on_event(
            SecurityEvent(
                timestamp=now,
                severity=severity,
                event_type=SecurityEventType.SYSTEM_WARNING,
                subsystem=_SUBSYSTEM,
                reason=reason,
            )
        )

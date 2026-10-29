"""`V2Snapshots`: the read-only v2 views core serves without its RPC lock (docs/V2_CONTRACTS.md §9).

`get_guard_modes`, `list_offenders`, `list_bindings` and `get_engine_stats`
must never wait behind core's single RPC lock (critique_round2.md 17): a
dashboard refresh must not queue behind a portal login's scrypt, and the
kill switch's own status view must answer while the pipeline is busy. So
the threads that own each source publish an immutable value here, and the
dispatcher reads the latest one:

* the one-second v2 watch thread in `pirewall.runtime.core` publishes the
  guard modes (read back from the kernel's verdict chains) and the engine
  counters;
* the offender poller (phase 17) publishes `@offenders`; until it exists
  the list is empty, and `offenders_polled` says so;
* bindings are not copied at all: `BindingTable.snapshot()` already returns
  an immutable tuple, so the holder keeps a reference to that method.

Every value stored is immutable (frozen Pydantic models, tuples), and each
publish swaps one reference under a small lock of this class's own, which
is never held while doing I/O.
"""

import threading
from collections.abc import Callable

from pirewall.core.models.identity import Binding
from pirewall.ipc.protocol_v2 import EngineStats, GuardModes, OffenderEntry

BindingsSource = Callable[[], tuple[Binding, ...]]


class V2Snapshots:
    """Latest published v2 read views. Thread-safe; every getter returns an immutable value."""

    def __init__(self, bindings: BindingsSource | None = None) -> None:
        """`bindings` is `BindingTable.snapshot`; without one, `bindings()` is empty."""
        self._lock = threading.Lock()
        self._bindings = bindings
        self._guard_modes: GuardModes | None = None
        self._guard_modes_error: str | None = "guard modes have not been read yet"
        self._offenders: tuple[OffenderEntry, ...] = ()
        self._offenders_polled = False
        self._engine_stats: EngineStats | None = None

    # ------------------------------------------------------------- publish

    def publish_guard_modes(self, modes: GuardModes | None, error: str | None = None) -> None:
        """Record the latest guard modes, or why they could not be read (`modes` None)."""
        with self._lock:
            self._guard_modes = modes
            self._guard_modes_error = None if modes is not None else (error or "guard modes unavailable")

    def publish_offenders(self, offenders: tuple[OffenderEntry, ...]) -> None:
        """Record the latest `@offenders` poll (phase 17's K poller)."""
        with self._lock:
            self._offenders = offenders
            self._offenders_polled = True

    def publish_engine_stats(self, stats: EngineStats) -> None:
        """Record the latest capture/flow engine counters."""
        with self._lock:
            self._engine_stats = stats

    # ---------------------------------------------------------------- read

    @property
    def guard_modes(self) -> GuardModes | None:
        """The last guard modes read from the kernel, or None if the last read failed."""
        with self._lock:
            return self._guard_modes

    @property
    def guard_modes_error(self) -> str | None:
        """Why `guard_modes` is None; None when it holds a value."""
        with self._lock:
            return self._guard_modes_error

    @property
    def offenders(self) -> tuple[OffenderEntry, ...]:
        """The last `@offenders` poll. Empty until a poller has published one."""
        with self._lock:
            return self._offenders

    @property
    def offenders_polled(self) -> bool:
        """Whether any poller has published offenders yet (an empty list can mean either)."""
        with self._lock:
            return self._offenders_polled

    @property
    def engine_stats(self) -> EngineStats | None:
        """The last published engine counters, or None before the first."""
        with self._lock:
            return self._engine_stats

    def bindings(self) -> tuple[Binding, ...]:
        """The binding table's current immutable snapshot."""
        return () if self._bindings is None else self._bindings()

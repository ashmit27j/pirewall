"""v2 RPC operations: names, result models and signatures only (docs/V2_CONTRACTS.md "RPC").

Frozen by phase 11 so the API (phase 16) and core (phases 13/14/16) agree
before either is written. Deliberately **not** added to `RpcOperation` yet:
an enum member with no dispatcher handler would be a live operation that
fails at runtime. Phase 16, which owns `pirewall/ipc/dispatcher.py`, adds
these names to `RpcOperation` and handlers to `CoreRpcDispatcher`.

All six are admin operations on `core.sock` only. None may ever be added to
`PortalRpcDispatcher` (ADDENDUM_3.md C1): `set_guard_mode` and `panic` are
as dangerous as the kill switch.

Read operations (`get_guard_modes`, `list_offenders`, `list_bindings`,
`get_engine_stats`) are served from snapshots that the poller and lease-sync
threads publish, never under core's single RPC lock (critique_round2.md 17).
"""

from typing import Final, Literal, Protocol

from pydantic import AwareDatetime, Field

from pirewall.core.enums import GuardMode, GuardName
from pirewall.core.models.common import PirewallModel, UnicastMacAddress
from pirewall.core.models.identity import Binding
from pirewall.core.nft_names import OffenderCode

OP_GET_GUARD_MODES: Final = "get_guard_modes"
OP_SET_GUARD_MODE: Final = "set_guard_mode"
OP_PANIC: Final = "panic"
OP_LIST_OFFENDERS: Final = "list_offenders"
OP_LIST_BINDINGS: Final = "list_bindings"
OP_GET_ENGINE_STATS: Final = "get_engine_stats"

V2_OPERATIONS: Final = (
    OP_GET_GUARD_MODES,
    OP_SET_GUARD_MODE,
    OP_PANIC,
    OP_LIST_OFFENDERS,
    OP_LIST_BINDINGS,
    OP_GET_ENGINE_STATS,
)


class GuardModes(PirewallModel):
    """The current mode of every static guard, as read back from the kernel verdict chains."""

    raw: GuardMode
    input: GuardMode
    forward: GuardMode
    read_at: AwareDatetime


class OffenderEntry(PirewallModel):
    """One live `@offenders` element, as last polled (tier K evidence, not yet a decision)."""

    mac: UnicastMacAddress
    code: OffenderCode
    guard: GuardName
    guard_mode: GuardMode
    sustained_polls: int = Field(ge=1)
    first_seen: AwareDatetime
    last_seen: AwareDatetime


class EngineStats(PirewallModel):
    """Capture/flow engine health, re-sourcing the v1 Netdata capture gauges (ADDENDUM_4.md D9)."""

    backend: Literal["native", "python", "replay"]
    has_packet_ring: bool
    frames_seen: int = Field(ge=0)
    kernel_drops: int = Field(ge=0)
    flows_shed: int = Field(ge=0)
    new_flow_signals_shed: int = Field(ge=0)
    panics_caught: int = Field(ge=0)
    read_at: AwareDatetime


class PanicResult(PirewallModel):
    """What `panic` removed, and the exact command that restores the tables (ADDENDUM_4.md D5)."""

    deleted_tables: tuple[str, ...]
    restore_command: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    performed_at: AwareDatetime


class CoreRpcV2(Protocol):
    """Signatures of the six v2 operations as `RpcClient` will expose them to `pirewall-api`.

    `actor` is the authenticated admin username, recorded in the audit
    entry. `set_guard_mode(..., ENFORCE)` requires password re-entry at the
    API layer before the call is made; core still audits every flip.
    """

    def get_guard_modes(self) -> GuardModes:
        """Read every guard's mode back from its `guard_verdict_*` chain."""
        ...

    def set_guard_mode(self, guard: GuardName, mode: GuardMode, actor: str) -> GuardModes:
        """Replace one `guard_verdict_*` chain's contents in one atomic batch; return all modes after."""
        ...

    def panic(self, actor: str) -> PanicResult:
        """Delete the v2 pirewall tables (`nft_names.PANIC_TABLES`) and nothing else."""
        ...

    def list_offenders(self) -> tuple[OffenderEntry, ...]:
        """The latest poller snapshot of `@offenders`."""
        ...

    def list_bindings(self) -> tuple[Binding, ...]:
        """The latest `BindingTable.snapshot()`."""
        ...

    def get_engine_stats(self) -> EngineStats:
        """The latest capture/flow engine counters."""
        ...

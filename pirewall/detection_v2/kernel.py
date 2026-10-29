"""Tier K: the kernel offender poller (ADDENDUM_4.md D4, PLAN_FINAL §4.5; phase 17).

Once a second core calls `KernelPoller.poll`, which reads, through a
`KernelReader`:

* `@offenders` (`pirewall_static`): each (MAC, code) element is a device
  some static guard's meter caught. It becomes a `KernelGuardEvidence`
  carrying the guard's mode **at this poll** and how many consecutive polls
  the element has been present (`sustained_polls`);
* the per-guard verdict counters (meter hits; in ENFORCE every hit is a
  drop), reported as per-poll deltas for the Netdata gauges;
* the fill level of the sets that can fill up, with one WARNING when one
  crosses `d1.set_fill_warning_ratio` (re-armed once it drains below it);
* whether the static table is there at all. Its disappearance is reported
  CRITICAL by the same 1 s loop in core (`_v2_watch_loop`), which owns
  table-loss reporting for both engines; the poller only skips the reads.

Meter-set membership is never evidence (RESULTS.md finding 3): only
`@offenders` produces `KernelGuardEvidence`.

**Evidence identity.** An offender *episode* is one unbroken run of polls
in which the element is present. Its id names the episode, the guard mode
and whether it has reached `policy.sustained_polls`, so re-polling the same
episode yields the same id (no escalation from repetition, D4), while
crossing the sustained bar, or the guard changing mode, yields a new one.

The reader is a Protocol so this module never imports the firewall package
(the dependency would point backwards, `pirewall.core.nft_names`); core
adapts `FirewallManager`'s read-only views to it.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final, Protocol

from pirewall.core import nft_names
from pirewall.core.enums import EventSeverity, GuardMode, GuardName
from pirewall.core.models.evidence_v2 import KernelGuardEvidence
from pirewall.core.nft_names import OFFENDER_GUARD, OffenderCode
from pirewall.detection_v2.d1 import unicast_mac

__all__ = [
    "WATCHED_SETS",
    "KernelAlert",
    "KernelPollResult",
    "KernelPoller",
    "KernelReader",
]

WATCHED_SETS: Final[tuple[tuple[str, str], ...]] = (
    *((nft_names.ADAPTIVE_TABLE, name) for name in sorted(nft_names.ADAPTIVE_ENFORCEMENT_SETS)),
    *((nft_names.STATIC_TABLE, name) for name in sorted(nft_names.STATIC_METER_SETS)),
    (nft_names.STATIC_TABLE, nft_names.SET_OFFENDERS),
    (nft_names.STATIC_TABLE, nft_names.SET_MACBIND),
)
"""(table, set) pairs whose fill level is watched: everything a flood or MAC churn can fill."""


class KernelReader(Protocol):
    """Read-only kernel views the poller needs. Every method may raise `FirewallError`."""

    def offenders(self) -> Sequence[tuple[str, int]]:
        """`@offenders` now, as (MAC, offender code) pairs."""
        ...

    def counters(self, names: Iterable[str]) -> Mapping[str, int]:
        """Packet counts of these `pirewall_static` named counters."""
        ...

    def guard_modes(self) -> Mapping[GuardName, GuardMode]:
        """Every guard's verdict-chain mode now (a guard missing from it reads as observe)."""
        ...

    def static_table_present(self) -> bool:
        """Whether `inet pirewall_static` is loaded."""
        ...

    def set_fill(self, table: str, set_name: str) -> tuple[int, int | None]:
        """(elements, declared size or None) for one set."""
        ...


@dataclass(frozen=True, slots=True)
class KernelAlert:
    """A SYSTEM_WARNING-class observation for core to emit."""

    severity: EventSeverity
    reason: str


@dataclass(frozen=True, slots=True)
class KernelPollResult:
    """One poll: evidence for the policy engine, gauges for Netdata, alerts for the event log."""

    evidence: tuple[KernelGuardEvidence, ...] = ()
    # evidence id -> when its offender episode began (the RPC's `first_seen`).
    started_at: Mapping[str, datetime] = field(default_factory=dict[str, datetime])
    guard_hits: Mapping[GuardName, int] = field(default_factory=dict[GuardName, int])
    offender_count: int = 0
    max_set_fill_ratio: float = 0.0
    alerts: tuple[KernelAlert, ...] = ()
    table_present: bool = True
    error: str | None = None


@dataclass(slots=True)
class _Episode:
    started_at: datetime
    polls: int


class KernelPoller:
    """Turns successive kernel reads into `KernelGuardEvidence` with `sustained_polls` tracked."""

    def __init__(self, reader: KernelReader, *, sustained_polls: int, set_fill_warning_ratio: float) -> None:
        """`sustained_polls` is `policy.sustained_polls`: where an episode's id changes stage."""
        self._reader = reader
        self._sustained_polls = sustained_polls
        self._warning_ratio = set_fill_warning_ratio
        self._episodes: dict[tuple[OffenderCode, str], _Episode] = {}
        self._last_counters: dict[GuardName, int] = {}
        self._warned: set[tuple[str, str]] = set()

    def poll(self, now: datetime) -> KernelPollResult:
        """Read the kernel once. Never raises: a failed read is reported in `error`."""
        try:
            if not self._reader.static_table_present():
                self._episodes.clear()
                return KernelPollResult(table_present=False)
            offenders = self._reader.offenders()
            modes = self._reader.guard_modes()
            counters = self._reader.counters(nft_names.GUARD_VERDICT_COUNTERS.values())
            fills: dict[tuple[str, str], tuple[int, int | None]] = {
                location: self._reader.set_fill(*location) for location in WATCHED_SETS
            }
        except Exception as exc:  # FirewallError, or a backend bug: the poller must keep running
            return KernelPollResult(error=f"kernel poll failed: {exc}")
        evidence = self._track(offenders, modes, now)
        return KernelPollResult(
            evidence=evidence,
            started_at={item.id: self._episodes[(item.code, str(item.mac))].started_at for item in evidence},
            guard_hits=self._deltas(counters),
            offender_count=len(offenders),
            max_set_fill_ratio=max((count / size for count, size in fills.values() if size), default=0.0),
            alerts=self._fill_alerts(fills),
        )

    def _track(
        self,
        offenders: Sequence[tuple[str, int]],
        modes: Mapping[GuardName, GuardMode],
        now: datetime,
    ) -> tuple[KernelGuardEvidence, ...]:
        present: set[tuple[OffenderCode, str]] = set()
        for raw_mac, raw_code in offenders:
            mac = unicast_mac(raw_mac)
            try:
                code = OffenderCode(raw_code)
            except ValueError:
                continue
            if mac is not None:
                present.add((code, mac))
        for key in list(self._episodes):
            if key not in present:
                del self._episodes[key]  # the element expired: the episode is over
        found: list[KernelGuardEvidence] = []
        for code, mac in sorted(present):
            episode = self._episodes.get((code, mac))
            if episode is None:
                episode = self._episodes[(code, mac)] = _Episode(now, 0)
            episode.polls += 1
            guard = OFFENDER_GUARD[code]
            mode = modes.get(guard) or GuardMode.OBSERVE  # unreadable: assume the weaker mode
            # Only an enforce-mode episode changes stage: an observe-mode one stays one piece of evidence.
            if mode is GuardMode.OBSERVE:
                stage = "observe"
            else:
                stage = "sustained" if episode.polls >= self._sustained_polls else "new"
            found.append(
                KernelGuardEvidence(
                    id=f"k:{code.value}:{mac}:{episode.started_at.isoformat()}:{mode.value}:{stage}",
                    code=code,
                    mac=mac,
                    guard=guard,
                    guard_mode=mode,
                    sustained_polls=episode.polls,
                    observed_at=now,
                )
            )
        return tuple(found)

    def _deltas(self, counters: Mapping[str, int]) -> dict[GuardName, int]:
        deltas: dict[GuardName, int] = {}
        for guard, name in nft_names.GUARD_VERDICT_COUNTERS.items():
            if name not in counters:
                continue
            value = counters[name]
            previous = self._last_counters.get(guard)
            # A reload resets the counter: count from zero again rather than go negative.
            deltas[guard] = value if previous is None or value < previous else value - previous
            self._last_counters[guard] = value
        return deltas

    def _fill_alerts(
        self, fills: Mapping[tuple[str, str], tuple[int, int | None]]
    ) -> tuple[KernelAlert, ...]:
        alerts: list[KernelAlert] = []
        for location, (count, size) in fills.items():
            ratio = count / size if size else 0.0
            if ratio > self._warning_ratio and location not in self._warned:
                self._warned.add(location)
                table, name = location
                alerts.append(
                    KernelAlert(
                        EventSeverity.WARNING,
                        f"set {table} @{name} is {ratio:.0%} full ({count}/{size}); a full set refuses "
                        "adds (enforcement) or fails open (meters)",
                    )
                )
            elif ratio <= self._warning_ratio:
                self._warned.discard(location)
        return tuple(alerts)

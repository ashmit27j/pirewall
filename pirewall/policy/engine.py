"""The v2 policy engine: one device's evidence bundle -> `PolicyDecision`s (ADDENDUM_4.md D4).

Evidence in, decisions out; nothing here touches the firewall. Each
decision then goes through the validator chain and `FirewallManager`, the
single deploy path, exactly like a v1 candidate.

**No scores.** The action comes from `policy/table.toml` and the
*kinds* of evidence present, never from a score: `AnomalyEvidence.anomaly_score`,
`ClassifierEvidence.attack_probability` and D1 values are only read as the
evidence's own yes/no (`is_anomaly`, `is_attack`, "a D1 detector fired")
and copied into the reasons. `tests/unit/test_policy_matrix.py` mutates
scores and checks the actions do not move.

**One decision pass per bundle**, for one device (`RuleTarget`):

1. Allowlisted or infrastructure targets get nothing (the validator
   refuses them too; this is defence in depth).
2. Only *new* evidence can produce a decision, and only new evidence is
   classified. An id this device has already been decided on never acts
   again, so repeating the same evidence cannot lengthen, renew or
   upgrade an action (D4).
3. The bundle is classified (`EvidenceClass`), each matching row's cell for
   the enforcement mode is read, and the strongest action wins.
4. An escalating row (D1 + sustained enforce-mode K, or D1 again with new
   evidence) multiplies the BLOCK TTL per earlier enforcing D1 decision,
   capped at `policy.max_ttl_seconds`.

In ASSISTED, a row saying `["rate_limit", "block_approval"]` yields the
held BLOCK first and the RATE_LIMIT second. Order matters: the validator's
escalation stage refuses a BLOCK whose evidence an *active* RATE_LIMIT
already carries, and a pending BLOCK is not active, so submitting it first
lets both through; approving it later upgrades the RATE_LIMIT atomically.

**SHADOW** reads the ACTIVE column, so the shadow log shows what ACTIVE
would have done; `FirewallManager` records it SHADOWED and writes nothing.

Not thread-safe: one engine belongs to the detection thread.
"""

from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

from pirewall.config.models import PolicyConfig
from pirewall.core.enums import EnforcementMode, FirewallAction, GuardMode
from pirewall.core.models.evidence import AnomalyEvidence
from pirewall.core.models.evidence_v2 import (
    ClassifierEvidence,
    D1Evidence,
    KernelGuardEvidence,
    evidence_id,
)
from pirewall.core.models.identity import RuleTarget
from pirewall.core.models.policy import PolicyDecision
from pirewall.policy.table import EvidenceClass, PolicyTable, TableAction

__all__ = ["EvidenceBundle", "PolicyEngine", "classify"]

type Evidence = KernelGuardEvidence | D1Evidence | AnomalyEvidence | ClassifierEvidence

_STRENGTH: Final = {
    TableAction.MONITOR: 1,
    TableAction.RATE_LIMIT: 2,
    TableAction.BLOCK: 3,
}


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    """Everything known about one device right now."""

    target: RuleTarget
    evidence: tuple[Evidence, ...]


@dataclass(slots=True)
class _History:
    used: OrderedDict[str, None] = field(default_factory=OrderedDict[str, None])
    d1_strikes: int = 0


def classify(
    bundle: Sequence[Evidence],
    table: PolicyTable,
    sustained_polls: int,
    prior_d1_strikes: int,
    new_ids: frozenset[str],
) -> frozenset[EvidenceClass]:
    """Which table rows `bundle` matches. Pure; the matrix tests call it directly."""
    classes: set[EvidenceClass] = set()
    kernel = [item for item in bundle if isinstance(item, KernelGuardEvidence)]
    d1 = [item for item in bundle if isinstance(item, D1Evidence)]
    ml = [
        item
        for item in bundle
        if (isinstance(item, AnomalyEvidence) and item.is_anomaly)
        or (isinstance(item, ClassifierEvidence) and item.is_attack)
    ]
    sustained = False
    for item in kernel:
        if item.guard_mode is GuardMode.OBSERVE:
            classes.add(EvidenceClass.K_OBSERVE)
        elif item.sustained_polls >= sustained_polls:
            classes.add(EvidenceClass.K_ENFORCE_SUSTAINED)
            sustained = True
        else:
            classes.add(EvidenceClass.K_ENFORCE_PENDING)
    detectors = {item.detector for item in d1}
    if detectors & table.high:
        classes.add(EvidenceClass.D1_HIGH)
    if detectors & table.standard:
        classes.add(EvidenceClass.D1_STANDARD)
    acting_d1 = bool(detectors & (table.high | table.standard))
    new_d1 = any(item.id in new_ids for item in d1 if item.detector in table.high | table.standard)
    if acting_d1 and new_d1 and (sustained or prior_d1_strikes > 0):
        classes.add(EvidenceClass.D1_ESCALATED)
    if ml:
        classes.add(EvidenceClass.ML_WITH_D1 if acting_d1 else EvidenceClass.ML_ONLY)
    return frozenset(classes)


class PolicyEngine:
    """Applies the table to evidence bundles, remembering per device what it has already acted on."""

    def __init__(
        self,
        table: PolicyTable,
        config: PolicyConfig,
        *,
        is_protected: Callable[[RuleTarget], bool] = lambda _target: False,
    ) -> None:
        """`is_protected(target)`: True for allowlisted or infrastructure targets (never acted on)."""
        self._table = table
        self._config = config
        self._is_protected = is_protected
        self._history: OrderedDict[str, _History] = OrderedDict()

    @property
    def table(self) -> PolicyTable:
        """The table in force."""
        return self._table

    def tracked_devices(self) -> int:
        """Devices with escalation memory."""
        return len(self._history)

    def decide(
        self, bundle: EvidenceBundle, mode: EnforcementMode, now: datetime
    ) -> tuple[PolicyDecision, ...]:
        """The decisions for `bundle` under `mode`, in submission order. Empty when nothing new."""
        if not bundle.evidence or self._is_protected(bundle.target):
            return ()
        history = self._history_for(bundle.target)
        ids = tuple(dict.fromkeys(evidence_id(item) for item in bundle.evidence))
        new_ids = frozenset(item for item in ids if item not in history.used)
        if not new_ids:
            return ()
        # Only evidence new to this device classifies it (step 2 of the module docstring).
        fresh = tuple(item for item in bundle.evidence if evidence_id(item) in new_ids)
        classes = classify(fresh, self._table, self._config.sustained_polls, history.d1_strikes, new_ids)
        self._remember(history, ids)
        if not classes:
            return ()
        actions: set[TableAction] = set()
        escalate = False
        for evidence_class in classes:
            row = self._table.rows[evidence_class]
            actions.update(row.cell(mode))
            escalate = escalate or (row.escalate and evidence_class is EvidenceClass.D1_ESCALATED)
        return self._decisions(bundle, actions, escalate, history, ids, now)

    def record_enforced(self, decision: PolicyDecision, had_d1: bool) -> None:
        """Count one D1-backed RATE_LIMIT/BLOCK the validator accepted (the escalation strike count).

        Called by the runtime after `FirewallManager.submit_candidate`, so a
        decision the validator refused (a duplicate while the first block is
        still active, say) does not lengthen the next TTL.
        """
        if had_d1 and decision.action in (FirewallAction.RATE_LIMIT, FirewallAction.BLOCK):
            self._history_for(decision.target).d1_strikes += 1

    def _decisions(
        self,
        bundle: EvidenceBundle,
        actions: set[TableAction],
        escalate: bool,
        history: _History,
        ids: tuple[str, ...],
        now: datetime,
    ) -> tuple[PolicyDecision, ...]:
        reasons = tuple(_reason(item) for item in bundle.evidence)
        direct = max(
            (action for action in actions if action in _STRENGTH), key=_STRENGTH.__getitem__, default=None
        )
        out: list[PolicyDecision] = []
        if TableAction.BLOCK_APPROVAL in actions and direct is not TableAction.BLOCK:
            out.append(
                PolicyDecision(
                    target=bundle.target,
                    action=FirewallAction.BLOCK,
                    ttl_seconds=self._block_ttl(escalate, history),
                    reasons=("BLOCK held for approval (ASSISTED)", *reasons),
                    evidence_ids=ids,
                    requires_approval=True,
                    decided_at=now,
                )
            )
        if direct is TableAction.BLOCK:
            out.append(
                PolicyDecision(
                    target=bundle.target,
                    action=FirewallAction.BLOCK,
                    ttl_seconds=self._block_ttl(escalate, history),
                    reasons=reasons,
                    evidence_ids=ids,
                    decided_at=now,
                )
            )
        elif direct is TableAction.RATE_LIMIT:
            out.append(
                PolicyDecision(
                    target=bundle.target,
                    action=FirewallAction.RATE_LIMIT,
                    ttl_seconds=min(self._config.rate_limit_ttl_seconds, self._config.max_ttl_seconds),
                    reasons=reasons,
                    evidence_ids=ids,
                    decided_at=now,
                )
            )
        elif direct is TableAction.MONITOR and not out:
            out.append(
                PolicyDecision(
                    target=bundle.target,
                    action=FirewallAction.MONITOR,
                    reasons=reasons,
                    evidence_ids=ids,
                    decided_at=now,
                )
            )
        return tuple(out)

    def _block_ttl(self, escalate: bool, history: _History) -> int:
        ttl = self._config.block_ttl_seconds
        if escalate:
            ttl *= self._config.escalation_ttl_multiplier ** max(history.d1_strikes, 1)
        return min(ttl, self._config.max_ttl_seconds)

    def _history_for(self, target: RuleTarget) -> _History:
        key = str(target.mac) if target.mac is not None else str(target.ip)
        history = self._history.get(key)
        if history is None:
            history = self._history[key] = _History()
            if len(self._history) > self._config.max_tracked_devices:
                self._history.popitem(last=False)
        else:
            self._history.move_to_end(key)
        return history

    def _remember(self, history: _History, ids: Sequence[str]) -> None:
        for item in ids:
            history.used[item] = None
            history.used.move_to_end(item)
        while len(history.used) > self._config.max_evidence_ids_per_device:
            history.used.popitem(last=False)


def _reason(item: Evidence) -> str:
    if isinstance(item, KernelGuardEvidence):
        return (
            f"kernel {item.guard.value} guard ({item.guard_mode.value}): offender code "
            f"{item.code.name} for {item.sustained_polls} poll(s)"
        )
    if isinstance(item, D1Evidence):
        return f"D1 {item.detector.value} over {item.window_seconds}s: {item.value:g} > {item.threshold:g}"
    if isinstance(item, ClassifierEvidence):
        family = f" ({item.family})" if item.family else ""
        return f"classifier{family}: p={item.attack_probability:.2f} (corroboration only)"
    return f"anomaly score {item.anomaly_score:.3f} (corroboration only)"

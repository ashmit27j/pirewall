"""The single authorized orchestrator for the rule lifecycle (spec §22, §25).

`FirewallManager` is the *only* module allowed to call into
`pirewall.firewall.backend` (CLAUDE.md) — enforced by
`tests/security/test_backend_isolation.py`, which asserts no other
non-test module in the codebase imports from that package. Every other
subsystem (Phase 7's API included) talks to the firewall exclusively
through this class's public methods.

Drives the addendum-updated lifecycle from `docs/ADDENDUM.md`:

```text
CANDIDATE -> VALIDATING -> REJECTED
                        -> SHADOWED                    (A1, terminal)
                        -> PENDING_APPROVAL -> APPROVED -> DEPLOYED -> ACTIVE
                                             -> REJECTED
                        -> APPROVED -> DEPLOYED -> ACTIVE
ACTIVE -> EXPIRED | DISABLED | REMOVED (incl. kill-switch, A8)
```
"""

import contextlib
from dataclasses import dataclass
from datetime import datetime

from pirewall.config.models import PirewallConfig
from pirewall.core.enums import (
    EnforcementMode,
    EventSeverity,
    FirewallAction,
    RuleStatus,
    SecurityEventType,
)
from pirewall.core.exceptions import FirewallError
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.rule import CandidateRule, FirewallRule
from pirewall.firewall.interface import FirewallBackend
from pirewall.firewall.rate_limiter import RuleCreationRateLimiter
from pirewall.firewall.validator import validate_candidate_rule

_SUBSYSTEM = "firewall.manager"


@dataclass(frozen=True, slots=True)
class RuleTransition:
    """One lifecycle transition, for the audit trail (spec §25 "record lifecycle changes")."""

    rule_id: str
    from_status: RuleStatus | None
    to_status: RuleStatus
    at: datetime
    reason: str


@dataclass(slots=True)
class SubmissionResult:
    """What happened when a candidate was submitted: the resulting rule (if any) plus its event."""

    rule: FirewallRule | None
    event: SecurityEvent


class FirewallManager:
    """Owns rule state, enforcement mode, and the only reference to a `FirewallBackend`."""

    def __init__(self, config: PirewallConfig, backend: FirewallBackend) -> None:
        self._config = config
        self.__backend = backend
        self._rules: dict[str, FirewallRule] = {}
        self._known_decision_ids: set[str] = set()
        self._transitions: list[RuleTransition] = []
        self._rate_limiter = RuleCreationRateLimiter(
            config.firewall.max_adaptive_rules_per_window, config.firewall.rate_window_seconds
        )
        self._enforcement_mode = config.firewall.enforcement_mode
        self._allowlist: list[AllowlistEntry] = list(config.firewall.allowlist)

    @property
    def enforcement_mode(self) -> EnforcementMode:
        return self._enforcement_mode

    @property
    def transitions(self) -> tuple[RuleTransition, ...]:
        return tuple(self._transitions)

    @property
    def allowlist(self) -> tuple[AllowlistEntry, ...]:
        return tuple(self._allowlist)

    def get_rule(self, rule_id: str) -> FirewallRule | None:
        return self._rules.get(rule_id)

    def active_rules(self) -> list[FirewallRule]:
        return [rule for rule in self._rules.values() if rule.status is RuleStatus.ACTIVE]

    def all_rules(self) -> list[FirewallRule]:
        """Every rule this manager knows about, in any status (spec §30 control panel "rule status")."""
        return list(self._rules.values())

    def disable_rule(self, rule_id: str, now: datetime) -> FirewallRule | None:
        """Stop enforcing `rule_id` but keep its record (spec §28 `/rules/{id}/disable`).

        Distinct from `remove_rule`: `DISABLED` and `REMOVED` are separate
        terminal states (spec §25) — disabling is the reversible-in-spirit
        "turn this off" action an operator reaches for first.
        """
        return self._retire_rule(rule_id, RuleStatus.DISABLED, now, "disabled by administrator")

    def remove_rule(self, rule_id: str, now: datetime) -> FirewallRule | None:
        """Permanently remove `rule_id` (spec §28 `/rules/{id}/remove`)."""
        return self._retire_rule(rule_id, RuleStatus.REMOVED, now, "removed by administrator")

    def _retire_rule(
        self, rule_id: str, to_status: RuleStatus, now: datetime, reason: str
    ) -> FirewallRule | None:
        rule = self._rules.get(rule_id)
        if rule is None or rule.status is not RuleStatus.ACTIVE:
            return None
        with contextlib.suppress(FirewallError):
            self.__backend.remove_rule(rule_id)
        updated = rule.model_copy(update={"status": to_status})
        self._rules[rule_id] = updated
        self._record(rule_id, RuleStatus.ACTIVE, to_status, now, reason)
        return updated

    def add_allowlist_entry(self, entry: AllowlistEntry) -> None:
        """Add a static allowlist entry (ADDENDUM.md A2)."""
        self._allowlist.append(entry)

    def remove_allowlist_entry(self, entry_id: str) -> bool:
        """Remove an allowlist entry by id. Returns `False` if `entry_id` wasn't found."""
        for index, entry in enumerate(self._allowlist):
            if entry.id == entry_id:
                del self._allowlist[index]
                return True
        return False

    def register_decision(self, decision: FirewallDecision) -> None:
        """Record that `decision` came from the real decision engine (spec §24 authorization stage)."""
        self._known_decision_ids.add(decision.id)

    def submit_candidate(self, candidate: CandidateRule, now: datetime) -> SubmissionResult:
        """Run the full validation chain against `candidate` and drive the lifecycle for it."""
        outcome = validate_candidate_rule(
            candidate,
            config=self._config,
            known_decision_ids=tuple(self._known_decision_ids),
            active_rules=self.active_rules(),
            allowlist=self._allowlist,
            rate_limiter=self._rate_limiter,
            now=now,
        )
        if not outcome.approved or outcome.priority is None:
            rejection = outcome.rejection
            reason = f"{rejection.stage}:{rejection.reason.value}" if rejection else "unknown"
            event = SecurityEvent(
                timestamp=now,
                severity=EventSeverity.INFO,
                event_type=SecurityEventType.RULE_REJECTED,
                subsystem=_SUBSYSTEM,
                rule_id=candidate.id,
                threat_score=candidate.threat_score,
                decision=candidate.action,
                reason=reason,
            )
            return SubmissionResult(rule=None, event=event)

        self._rate_limiter.record(now)
        rule = FirewallRule(
            id=candidate.id,
            action=candidate.action,
            direction=candidate.direction,
            source=candidate.source,
            destination=candidate.destination,
            protocol=candidate.protocol,
            source_port=candidate.source_port,
            destination_port=candidate.destination_port,
            priority=outcome.priority,
            created_at=candidate.created_at,
            expires_at=candidate.expires_at,
            reason=candidate.reason,
            threat_score=candidate.threat_score,
            evidence=candidate.evidence,
            status=RuleStatus.VALIDATING,
            metadata=candidate.metadata,
        )
        self._record(rule.id, None, RuleStatus.VALIDATING, now, "passed full validation chain")

        if self._enforcement_mode is EnforcementMode.SHADOW:
            return self._shadow(rule, now)

        if self._enforcement_mode is EnforcementMode.ASSISTED and self._needs_review(candidate):
            return self._hold_for_approval(rule, now)

        return self._deploy(rule, now)

    def approve_pending(self, rule_id: str, now: datetime) -> SubmissionResult | None:
        """Approve a `PENDING_APPROVAL` rule (ADDENDUM.md A7), deploying through the normal path.

        Returns `None` if `rule_id` isn't currently pending approval.
        """
        rule = self._rules.get(rule_id)
        if rule is None or rule.status is not RuleStatus.PENDING_APPROVAL:
            return None
        approved = rule.model_copy(update={"status": RuleStatus.APPROVED})
        self._record(
            rule_id, RuleStatus.PENDING_APPROVAL, RuleStatus.APPROVED, now, "approved by administrator"
        )
        return self._deploy(approved, now)

    def reject_pending(self, rule_id: str, now: datetime) -> FirewallRule | None:
        """Reject a `PENDING_APPROVAL` rule. Returns `None` if it isn't currently pending."""
        rule = self._rules.get(rule_id)
        if rule is None or rule.status is not RuleStatus.PENDING_APPROVAL:
            return None
        rejected = rule.model_copy(update={"status": RuleStatus.REJECTED})
        self._rules[rule_id] = rejected
        self._record(
            rule_id, RuleStatus.PENDING_APPROVAL, RuleStatus.REJECTED, now, "rejected by administrator"
        )
        return rejected

    def revert_to_base(self, now: datetime) -> SecurityEvent:
        """Emergency kill-switch (ADDENDUM.md A8): SHADOW mode + remove every active adaptive rule.

        Leaves the static base ruleset and the allowlist untouched. Drives
        each rule through the normal ACTIVE -> REMOVED transition, not a
        special-cased shortcut.
        """
        self._enforcement_mode = EnforcementMode.SHADOW
        removed = 0
        for rule in list(self._rules.values()):
            if rule.status is not RuleStatus.ACTIVE:
                continue
            # fail-open (ADDENDUM.md A6): still mark removed in our own authoritative state
            with contextlib.suppress(FirewallError):
                self.__backend.remove_rule(rule.id)
            self._rules[rule.id] = rule.model_copy(update={"status": RuleStatus.REMOVED})
            self._record(rule.id, RuleStatus.ACTIVE, RuleStatus.REMOVED, now, "kill-switch")
            removed += 1
        return SecurityEvent(
            timestamp=now,
            severity=EventSeverity.WARNING,
            event_type=SecurityEventType.SYSTEM_WARNING,
            subsystem=_SUBSYSTEM,
            reason=f"kill-switch activated: {removed} active rule(s) reverted, mode set to SHADOW",
        )

    def _needs_review(self, candidate: CandidateRule) -> bool:
        if candidate.action is not FirewallAction.BLOCK:
            return False
        threat_score = candidate.threat_score if candidate.threat_score is not None else 0.0
        return threat_score >= self._config.firewall.assisted_review_threshold

    def _shadow(self, rule: FirewallRule, now: datetime) -> SubmissionResult:
        shadowed = rule.model_copy(update={"status": RuleStatus.SHADOWED})
        self._rules[rule.id] = shadowed
        self._record(rule.id, RuleStatus.VALIDATING, RuleStatus.SHADOWED, now, "shadow mode")
        event = SecurityEvent(
            timestamp=now,
            severity=EventSeverity.INFO,
            event_type=SecurityEventType.RULE_CREATED,
            subsystem=_SUBSYSTEM,
            rule_id=rule.id,
            threat_score=rule.threat_score,
            decision=rule.action,
            reason=f"[shadow mode] would have {rule.action.value}ed this traffic",
        )
        return SubmissionResult(rule=shadowed, event=event)

    def _hold_for_approval(self, rule: FirewallRule, now: datetime) -> SubmissionResult:
        pending = rule.model_copy(update={"status": RuleStatus.PENDING_APPROVAL})
        self._rules[rule.id] = pending
        self._record(rule.id, RuleStatus.VALIDATING, RuleStatus.PENDING_APPROVAL, now, "assisted mode review")
        event = SecurityEvent(
            timestamp=now,
            severity=EventSeverity.WARNING,
            event_type=SecurityEventType.RULE_CREATED,
            subsystem=_SUBSYSTEM,
            rule_id=rule.id,
            threat_score=rule.threat_score,
            decision=rule.action,
            reason="pending human approval (assisted mode, high-confidence BLOCK)",
        )
        return SubmissionResult(rule=pending, event=event)

    def _deploy(self, rule: FirewallRule, now: datetime) -> SubmissionResult:
        previous_status = rule.status
        try:
            self.__backend.apply_rule(rule)
        except FirewallError as exc:
            failed = rule.model_copy(update={"status": RuleStatus.REJECTED})
            self._rules[rule.id] = failed
            self._record(rule.id, previous_status, RuleStatus.REJECTED, now, f"deploy failed: {exc}")
            event = SecurityEvent(
                timestamp=now,
                severity=EventSeverity.ERROR,
                event_type=SecurityEventType.FIREWALL_ERROR,
                subsystem=_SUBSYSTEM,
                rule_id=rule.id,
                reason=str(exc),
            )
            return SubmissionResult(rule=failed, event=event)

        active = rule.model_copy(update={"status": RuleStatus.ACTIVE, "deployed_at": now})
        self._rules[rule.id] = active
        self._record(rule.id, previous_status, RuleStatus.DEPLOYED, now, "deployed to backend")
        self._record(rule.id, RuleStatus.DEPLOYED, RuleStatus.ACTIVE, now, "active")
        is_block = rule.action is FirewallAction.BLOCK
        event_type = SecurityEventType.FIREWALL_BLOCK if is_block else SecurityEventType.RULE_DEPLOYED
        event = SecurityEvent(
            timestamp=now,
            severity=EventSeverity.WARNING if is_block else EventSeverity.INFO,
            event_type=event_type,
            subsystem=_SUBSYSTEM,
            rule_id=rule.id,
            threat_score=rule.threat_score,
            decision=rule.action,
            reason=rule.reason,
        )
        return SubmissionResult(rule=active, event=event)

    def _record(
        self, rule_id: str, from_status: RuleStatus | None, to_status: RuleStatus, at: datetime, reason: str
    ) -> None:
        self._transitions.append(RuleTransition(rule_id, from_status, to_status, at, reason))

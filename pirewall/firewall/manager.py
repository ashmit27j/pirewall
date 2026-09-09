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
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

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

    def backend_health(self) -> bool:
        """Whether the firewall backend is reachable and operating normally (spec §33).

        Exists so the running daemon can report firewall health without
        holding a reference to the backend itself — this manager is the only
        code path allowed to touch `pirewall.firewall.backend` (CLAUDE.md),
        and that has to stay true for a read-only health probe too.
        Swallows a backend failure into `False`: "is it healthy" must always
        have an answer.
        """
        try:
            return self.__backend.health_check()
        except FirewallError:
            return False

    def adaptive_rules_in_window(self, now: datetime) -> int:
        """How many adaptive rules have been created in the current A3 rate window.

        Delegates to the rate limiter this manager owns; nothing outside
        gets a reference to the limiter itself (the manager is the single
        authorized owner of rule-creation state, spec §22).
        """
        return self._rate_limiter.count_in_window(now)

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

    def expire_rules(self, now: datetime) -> list[FirewallRule]:
        """Retire every ACTIVE rule whose `expires_at` has passed (spec §25).

        `CandidateRule.expires_at` is mandatory — the validation chain's
        expiration stage rejects a candidate without one — but until this
        existed nothing ever acted on it: an ACTIVE rule stayed deployed in
        the backend indefinitely, and `RuleStatus.EXPIRED` was a state the
        lifecycle documented but could never reach. `pirewall.runtime.core`
        calls this on a timer; that timer is what makes a rule TTL mean
        anything.

        Returns the rules that were expired, so the caller can emit one
        `RULE_EXPIRED` `SecurityEvent` each — the same division of labour as
        `disable_rule`/`remove_rule`.
        """
        expired: list[FirewallRule] = []
        for rule in list(self._rules.values()):
            if rule.status is not RuleStatus.ACTIVE or rule.expires_at is None:
                continue
            if rule.expires_at > now:
                continue
            retired = self._retire_rule(rule.id, RuleStatus.EXPIRED, now, "rule TTL elapsed")
            if retired is not None:
                expired.append(retired)
        return expired

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

    def authorize_portal_client(self, client_ip: IPv4Address, timeout_seconds: int) -> None:
        """Authorize a logged-in captive-portal client for forwarding (ADDENDUM_3.md C2).

        Routed through this manager for the same reason every rule is: it
        holds the only reference to the backend (CLAUDE.md, "exactly one
        authorized code path may deploy to the firewall backend"). The
        portal process cannot reach the backend, and neither can the
        dispatcher that serves it — both go through here.

        This is deliberately *not* a `FirewallRule`. It creates no rule, has
        no `RuleStatus`, runs no validation chain, and does not consume the
        A3 rate cap: it authorizes an address the admin's own user store
        already vouched for, which is the opposite of an ML-driven
        restriction. The safety properties the validation chain exists to
        guarantee (§24) are about restrictive rules being too broad; an
        additive portal grant scoped to one /32 cannot lock anyone out.
        """
        if client_ip not in self._config.network.protected_network:
            # A portal grant only ever means "this LAN client logged in".
            # Refusing anything off the protected network keeps a confused
            # or hostile caller from authorizing a WAN address.
            raise FirewallError(
                f"refusing to authorize {client_ip}: not inside the protected network "
                f"{self._config.network.protected_network}"
            )
        self.__backend.authorize_portal_client(client_ip, timeout_seconds)

    def deauthorize_portal_client(self, client_ip: IPv4Address) -> None:
        """Revoke a portal client's forwarding authorization. Idempotent."""
        self.__backend.deauthorize_portal_client(client_ip)

    def authorized_portal_clients(self) -> frozenset[IPv4Address]:
        """Addresses the kernel currently has authorized. Empty set if the backend is unreachable.

        Swallows `FirewallError` for the same reason `backend_health` does:
        the control panel asking "who is online" must always get an answer,
        and fail-open (ADDENDUM.md A6) means a down backend is reported, not
        raised into the caller.
        """
        try:
            return self.__backend.list_portal_clients()
        except FirewallError:
            return frozenset()

    def blocking_rules_matching(self, client_ip: IPv4Address) -> list[FirewallRule]:
        """Active BLOCK rules targeting `client_ip` — the ones that actually disconnect it."""
        return blocking_rules_targeting(
            self.active_rules(), client_ip, self._config.network.protected_network
        )

    def restrictive_rules_matching(self, client_ip: IPv4Address) -> list[FirewallRule]:
        """Active BLOCK/RATE_LIMIT rules that actually target `client_ip`.

        This is how a blocked LAN client gets told *why* their network died
        (ADDENDUM_3.md C4). Scanning on demand rather than pushing an event
        at the portal keeps the two sides uncoupled and cannot miss a
        transition; it is an O(active rules) walk, bounded by
        `firewall.max_active_rules`.
        """
        return rules_targeting(
            self.active_rules(), client_ip, self._config.network.protected_network
        )

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


def blocking_rules_targeting(
    rules: Iterable[FirewallRule], client_ip: IPv4Address, protected_network: IPv4Network
) -> list[FirewallRule]:
    """Only the rules that actually cut `client_ip` off — BLOCK, never RATE_LIMIT.

    The captive portal uses this to decide whether to revoke a session and
    tell someone their device is suspended. A RATE_LIMIT throttles a flow; it
    does not disconnect anybody, and treating it as a disconnection took a
    user off the network entirely over a rule that was meant to slow one
    connection down. `rules_targeting` still reports both, for the control
    panel and anything that wants the full picture.
    """
    return [
        rule
        for rule in rules_targeting(rules, client_ip, protected_network)
        if rule.action is FirewallAction.BLOCK
    ]


def rules_targeting(
    rules: Iterable[FirewallRule], client_ip: IPv4Address, protected_network: IPv4Network
) -> list[FirewallRule]:
    """Which of `rules` restrict `client_ip` specifically (ADDENDUM_3.md C4).

    A module-level function, not a method, because it is pure: it is the
    predicate behind the portal's "am I blocked?" answer, and being able to
    test it against an arbitrary rule list — including shapes the validation
    chain currently prevents — is worth more than keeping it private.

    "Targets" means a side of the rule *names LAN addresses* and covers this
    client, not merely that some side's network contains it. A plain
    containment check reads a rule like
    `source=<some other client>/32 destination=0.0.0.0/0` as blocking
    everybody, because every address is inside `0.0.0.0/0` — so one
    misbehaving device would show the malicious-activity notice to every
    client on the network. Spec §24's safety validation refuses `0.0.0.0/0`
    today, so the adaptive pipeline cannot currently produce that shape; this
    is deliberately defensive about it anyway, because the cost of being
    wrong is telling innocent users they are infected.

    An exactly-equal network still counts: a rule against the whole
    protected LAN does target every client on it.
    """
    restrictive = {FirewallAction.BLOCK, FirewallAction.RATE_LIMIT}

    def targets(network: IPv4Network) -> bool:
        return client_ip in network and network.subnet_of(protected_network)

    return [
        rule
        for rule in rules
        if rule.action in restrictive and (targets(rule.source) or targets(rule.destination))
    ]

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

**v2 set path (ADDENDUM_4.md D1, D4, D5; phase 13).** When constructed with
a `set_backend`, the same lifecycle drives *set elements* instead of
per-rule chains: a validated rule becomes one element in `block_mac`,
`block4`, `ratelimit_mac` or `ratelimit4` (`pirewall.firewall.sets`), with a
kernel timeout, after `validate_set_candidate` (the v2 chain, per device).
An upgrade (RATE_LIMIT -> BLOCK on the same device) is one atomic delete +
add. The kill switch flushes the enforcement sets and sets every static
guard to observe; a clean fail-open shutdown (`fail_open_shutdown`) flushes
the sets only; `panic` deletes the v2 tables. `reconcile` rebuilds rule
state from live set contents at startup and never recreates a table. Without
a `set_backend` everything behaves exactly as before (v1), which is what
`pirewall-core` does until phase 16 wires `NftablesSetBackend` in.
"""

import contextlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network

from pirewall.config.models import PirewallConfig
from pirewall.core import nft_names
from pirewall.core.enums import (
    EnforcementMode,
    EventSeverity,
    FirewallAction,
    GuardMode,
    GuardName,
    Protocol,
    RuleDirection,
    RuleStatus,
    SecurityEventType,
)
from pirewall.core.exceptions import FirewallError
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.identity import RuleTarget
from pirewall.core.models.rule import CandidateRule, FirewallRule
from pirewall.firewall.allowlist_store import AllowlistStore
from pirewall.firewall.guards import ALL_OBSERVE
from pirewall.firewall.interface import FirewallBackend
from pirewall.firewall.rate_limiter import RuleCreationRateLimiter
from pirewall.firewall.sets import (
    ElementKey,
    SetBackend,
    SetFill,
    SetOp,
    SetOpKind,
    TransportMetrics,
    device_target,
    element_key,
    element_timeout_seconds,
    enforcement_set_for,
)
from pirewall.firewall.validator import ActiveTarget, validate_candidate_rule, validate_set_candidate
from pirewall.ipc.protocol_v2 import GuardModes, PanicResult

_SUBSYSTEM = "firewall.manager"

# Rule metadata keys recording where a v2 rule's element lives.
_META_SET = "v2_set"
_META_KEY = "v2_key"
_RECONCILED_PREFIX = "reconciled"
_WHOLE_INTERNET = IPv4Network("0.0.0.0/0")
_RESTORE_COMMAND = "sudo pirewall-start"
_ACTION_FOR_SET: Mapping[str, FirewallAction] = {
    nft_names.SET_BLOCK_MAC: FirewallAction.BLOCK,
    nft_names.SET_BLOCK4: FirewallAction.BLOCK,
    nft_names.SET_RATELIMIT_MAC: FirewallAction.RATE_LIMIT,
    nft_names.SET_RATELIMIT4: FirewallAction.RATE_LIMIT,
}
_IP_KEYED_SETS = frozenset({nft_names.SET_BLOCK4, nft_names.SET_RATELIMIT4})


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


@dataclass(slots=True)
class ReconcileReport:
    """What `FirewallManager.reconcile` found in the kernel at startup (v2 set path).

    * `adopted`: rule ids created for live elements this process had no record of.
    * `retired`: ACTIVE rules whose element was no longer in the kernel.
    * `unattributed`: MAC-keyed elements no binding maps to an IP. They are
      left in place to expire on their own (<= 1 h); core never deletes
      enforcement it cannot explain, and never invents a target for it.
    * `missing_tables`: v2 tables that are not loaded. Core never recreates
      them (D1, D5); reloading is `pirewall-start`'s job.
    """

    adopted: list[str] = field(default_factory=list[str])
    retired: list[str] = field(default_factory=list[str])
    unattributed: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])
    missing_tables: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])


class FirewallManager:
    """Owns rule state, enforcement mode, and the only reference to a `FirewallBackend`."""

    def __init__(
        self,
        config: PirewallConfig,
        backend: FirewallBackend,
        allowlist_store: AllowlistStore | None = None,
        *,
        set_backend: SetBackend | None = None,
        mac_resolver: Callable[[IPv4Address], str | None] | None = None,
    ) -> None:
        """`set_backend` switches adaptive enforcement to the v2 set path (module docstring).

        `backend` is still required: the captive portal's `authed` set
        (ADDENDUM_3.md C2) stays on it until phase 14. `mac_resolver` maps a
        target IP to its bound MAC; phase 14 passes the binding table's
        lookup. Without one every v2 target is IP-only (`block4`/`ratelimit4`).
        """
        self._config = config
        self.__backend = backend
        # Same discipline as `__backend`: the only reference to the kernel's
        # adaptive sets lives here (CLAUDE.md single deploy path).
        self.__sets = set_backend
        self._mac_resolver = mac_resolver
        self._targets: dict[str, RuleTarget] = {}
        self._rules: dict[str, FirewallRule] = {}
        self._known_decision_ids: set[str] = set()
        self._transitions: list[RuleTransition] = []
        self._rate_limiter = RuleCreationRateLimiter(
            config.firewall.max_adaptive_rules_per_window, config.firewall.rate_window_seconds
        )
        self._enforcement_mode = config.firewall.enforcement_mode
        # `config.firewall.allowlist` is the static, deployment-declared
        # seed; `allowlist_store` (KNOWN_ISSUES.md #10) holds whatever was
        # added at runtime and survives a restart. `None` means "no
        # persistence" — every existing caller (tests, and any deployment
        # that hasn't set `allowlist_store_path`) keeps working exactly as
        # before, just without the durability fix.
        self._allowlist_store = allowlist_store
        self._allowlist: list[AllowlistEntry] = list(config.firewall.allowlist)
        if allowlist_store is not None:
            self._allowlist.extend(allowlist_store.list_entries())

    @property
    def enforcement_mode(self) -> EnforcementMode:
        return self._enforcement_mode

    @property
    def uses_set_backend(self) -> bool:
        """True when adaptive enforcement runs on the v2 set path."""
        return self.__sets is not None

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
            healthy = self.__backend.health_check()
            if self.__sets is not None:
                healthy = healthy and self.__sets.health_check()
            return healthy
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
            if self.__sets is not None:
                self._delete_element(rule)
            else:
                self.__backend.remove_rule(rule_id)
        updated = rule.model_copy(update={"status": to_status})
        self._rules[rule_id] = updated
        self._record(rule_id, RuleStatus.ACTIVE, to_status, now, reason)
        return updated

    def add_allowlist_entry(self, entry: AllowlistEntry) -> None:
        """Add an allowlist entry (ADDENDUM.md A2), persisted so it survives a restart.

        See KNOWN_ISSUES.md #10.
        """
        self._allowlist.append(entry)
        if self._allowlist_store is not None:
            self._allowlist_store.add(entry)

    def remove_allowlist_entry(self, entry_id: str) -> bool:
        """Remove an allowlist entry by id. Returns `False` if `entry_id` wasn't found.

        Also removes it from the persistent store if it was there — a
        no-op for an entry that came from `config.firewall.allowlist`
        instead, which reappears on the next restart regardless (it is the
        static seed, not something this call owns).
        """
        for index, entry in enumerate(self._allowlist):
            if entry.id == entry_id:
                del self._allowlist[index]
                if self._allowlist_store is not None:
                    self._allowlist_store.remove(entry_id)
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
        return rules_targeting(self.active_rules(), client_ip, self._config.network.protected_network)

    def register_decision(self, decision: FirewallDecision) -> None:
        """Record that `decision` came from the real decision engine (spec §24 authorization stage)."""
        self._known_decision_ids.add(decision.id)

    def submit_candidate(self, candidate: CandidateRule, now: datetime) -> SubmissionResult:
        """Run the full validation chain against `candidate` and drive the lifecycle for it."""
        if self.__sets is not None:
            return self._submit_to_sets(candidate, now)
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
        if self.__sets is not None:
            return self._deploy_to_sets(approved, now, upgrade_of=self._rate_limit_to_upgrade(approved))
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
        if self.__sets is not None:
            return self._kill_switch_sets(now)
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

    # ================================================================ v2 set path

    def _submit_to_sets(self, candidate: CandidateRule, now: datetime) -> SubmissionResult:
        target = self._target_for(candidate)
        outcome = validate_set_candidate(
            candidate,
            target=target,
            config=self._config,
            known_decision_ids=tuple(self._known_decision_ids),
            active=self._active_targets(),
            allowlist=self._allowlist,
            rate_limiter=self._rate_limiter,
            now=now,
        )
        if not outcome.approved or target is None:
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

        # A3 counts element insertions; one approved candidate is one element.
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
            # Display only: escalation replaces priority on the set path (D4).
            priority=_display_priority(candidate.threat_score),
            created_at=candidate.created_at,
            expires_at=candidate.expires_at,
            reason=candidate.reason,
            threat_score=candidate.threat_score,
            evidence=candidate.evidence,
            status=RuleStatus.VALIDATING,
            metadata=candidate.metadata,
        )
        self._targets[rule.id] = target
        self._record(rule.id, None, RuleStatus.VALIDATING, now, "passed the v2 validation chain")

        if self._enforcement_mode is EnforcementMode.SHADOW:
            return self._shadow(rule, now)
        if self._enforcement_mode is EnforcementMode.ASSISTED and self._needs_review(candidate):
            return self._hold_for_approval(rule, now)
        return self._deploy_to_sets(rule, now, upgrade_of=outcome.upgrade_of)

    def _target_for(self, rule: CandidateRule | FirewallRule) -> RuleTarget | None:
        mac: str | None = None
        if self._mac_resolver is not None and rule.source.prefixlen == 32:
            mac = self._mac_resolver(rule.source.network_address)
        return device_target(rule, self._config.network.protected_network, mac)

    def _active_targets(self) -> list[ActiveTarget]:
        return [
            ActiveTarget(rule, target)
            for rule in self.active_rules()
            if (target := self._targets.get(rule.id)) is not None
        ]

    def _rate_limit_to_upgrade(self, rule: FirewallRule) -> str | None:
        """For a BLOCK approved later (A7): the ACTIVE RATE_LIMIT on the same device, if any."""
        target = self._targets.get(rule.id)
        if rule.action is not FirewallAction.BLOCK or target is None:
            return None
        for entry in self._active_targets():
            if entry.rule.action is FirewallAction.RATE_LIMIT and (
                entry.target.ip == target.ip or (target.mac is not None and entry.target.mac == target.mac)
            ):
                return entry.rule.id
        return None

    def _deploy_to_sets(self, rule: FirewallRule, now: datetime, upgrade_of: str | None) -> SubmissionResult:
        sets = self.__sets
        assert sets is not None
        previous_status = rule.status
        target = self._targets[rule.id]
        set_name = enforcement_set_for(rule.action, target)
        ops: list[SetOp] = []
        metadata = dict(rule.metadata)
        superseded = self._rules.get(upgrade_of) if upgrade_of is not None else None
        if superseded is not None and superseded.status is RuleStatus.ACTIVE:
            ops.extend(_delete_ops(superseded))
        if set_name is not None:
            key = element_key(set_name, target)
            assert rule.expires_at is not None  # the expiration stage guarantees it
            timeout = element_timeout_seconds(rule.expires_at, now, self._config.policy.max_ttl_seconds)
            ops.append(SetOp(SetOpKind.ADD, set_name, key, timeout))
            metadata.update({_META_SET: set_name, _META_KEY: key})
        try:
            sets.apply(ops)
        except FirewallError as exc:
            failed = rule.model_copy(update={"status": RuleStatus.REJECTED})
            self._rules[rule.id] = failed
            self._record(rule.id, previous_status, RuleStatus.REJECTED, now, f"deploy failed: {exc}")
            # CRITICAL, not ERROR: a refused add (most often a full set) means
            # evidence-backed enforcement did not happen (PLAN_FINAL §4.2).
            event = SecurityEvent(
                timestamp=now,
                severity=EventSeverity.CRITICAL,
                event_type=SecurityEventType.FIREWALL_ERROR,
                subsystem=_SUBSYSTEM,
                rule_id=rule.id,
                reason=str(exc),
            )
            return SubmissionResult(rule=failed, event=event)

        if superseded is not None and superseded.status is RuleStatus.ACTIVE:
            self._rules[superseded.id] = superseded.model_copy(update={"status": RuleStatus.REMOVED})
            self._record(
                superseded.id,
                RuleStatus.ACTIVE,
                RuleStatus.REMOVED,
                now,
                f"upgraded to BLOCK by rule {rule.id}",
            )
        active = rule.model_copy(
            update={"status": RuleStatus.ACTIVE, "deployed_at": now, "metadata": metadata}
        )
        self._rules[rule.id] = active
        self._record(rule.id, previous_status, RuleStatus.DEPLOYED, now, f"element added to {set_name}")
        self._record(rule.id, RuleStatus.DEPLOYED, RuleStatus.ACTIVE, now, "active")
        is_block = rule.action is FirewallAction.BLOCK
        event = SecurityEvent(
            timestamp=now,
            severity=EventSeverity.WARNING if is_block else EventSeverity.INFO,
            event_type=SecurityEventType.FIREWALL_BLOCK if is_block else SecurityEventType.RULE_DEPLOYED,
            subsystem=_SUBSYSTEM,
            rule_id=rule.id,
            threat_score=rule.threat_score,
            decision=rule.action,
            reason=rule.reason if superseded is None else f"{rule.reason} (upgraded from RATE_LIMIT)",
        )
        return SubmissionResult(rule=active, event=event)

    def _delete_element(self, rule: FirewallRule) -> None:
        sets = self.__sets
        assert sets is not None
        ops = _delete_ops(rule)
        if ops:
            sets.apply(ops)

    def _kill_switch_sets(self, now: datetime) -> SecurityEvent:
        """A8 extended (D5): SHADOW, flush every enforcement set, every guard to observe, audit."""
        sets = self.__sets
        assert sets is not None
        self._enforcement_mode = EnforcementMode.SHADOW
        problems: list[str] = []
        try:
            sets.flush_sets(nft_names.ADAPTIVE_ENFORCEMENT_SETS)
        except FirewallError as exc:
            problems.append(f"flushing the adaptive sets failed: {exc}")
        try:
            sets.set_guard_modes(ALL_OBSERVE)
        except FirewallError as exc:
            problems.append(f"setting the guards to observe failed: {exc}")
        removed = self._retire_all_active(now, "kill-switch")
        reason = (
            f"kill-switch activated: {removed} active rule(s) reverted, adaptive sets flushed, "
            "every static guard set to observe, mode set to SHADOW"
        )
        return SecurityEvent(
            timestamp=now,
            severity=EventSeverity.CRITICAL if problems else EventSeverity.WARNING,
            event_type=SecurityEventType.SYSTEM_WARNING,
            subsystem=_SUBSYSTEM,
            reason=reason if not problems else f"{reason}; " + "; ".join(problems),
        )

    def fail_open_shutdown(self, now: datetime) -> SecurityEvent:
        """A clean fail-open shutdown (A6 narrowed by D5): flush the adaptive sets, and nothing else.

        The static guards keep their modes, so a crash loop no longer turns
        pirewall off: the kernel guards keep protecting while core is down
        (audit item 17). Bindings expire by their own timeouts. Without a set
        backend this is the v1 behaviour, `revert_to_base`.
        """
        sets = self.__sets
        if sets is None:
            return self.revert_to_base(now)
        problem = ""
        try:
            sets.flush_sets(nft_names.ADAPTIVE_ENFORCEMENT_SETS)
        except FirewallError as exc:
            problem = f"; flushing the adaptive sets failed: {exc}"
        removed = self._retire_all_active(now, "fail-open shutdown")
        return SecurityEvent(
            timestamp=now,
            severity=EventSeverity.ERROR if problem else EventSeverity.INFO,
            event_type=SecurityEventType.SYSTEM_WARNING,
            subsystem=_SUBSYSTEM,
            reason=f"fail-open shutdown: {removed} adaptive rule(s) removed; static guards left as they were"
            + problem,
        )

    def panic(self, actor: str, now: datetime) -> tuple[PanicResult, SecurityEvent]:
        """Delete the v2 tables (`nft_names.PANIC_TABLES`) and nothing else (D5).

        Also drives every active rule to REMOVED and sets SHADOW, so core's
        state matches the kernel. The restore path is re-running
        `pirewall-start`. Raises `FirewallError` without a set backend or if
        the kernel refuses; the RPC wiring is phase 16's.
        """
        sets = self.__sets
        if sets is None:
            raise FirewallError("panic needs the v2 set backend")
        deleted = sets.panic()
        self._enforcement_mode = EnforcementMode.SHADOW
        removed = self._retire_all_active(now, f"panic by {actor}")
        result = PanicResult(
            deleted_tables=tuple(f"{family} {table}" for family, table in deleted),
            restore_command=_RESTORE_COMMAND,
            actor=actor,
            performed_at=now,
        )
        event = SecurityEvent(
            timestamp=now,
            severity=EventSeverity.CRITICAL,
            event_type=SecurityEventType.SYSTEM_WARNING,
            subsystem=_SUBSYSTEM,
            reason=(
                f"panic by {actor}: deleted {', '.join(result.deleted_tables)}; {removed} rule(s) removed; "
                f"mode SHADOW. Restore with: {_RESTORE_COMMAND}"
            ),
        )
        return result, event

    def set_guard_mode(self, guard: GuardName, mode: GuardMode, actor: str, now: datetime) -> SecurityEvent:
        """Flip one static guard (D1's single permitted static write) in one atomic batch, and audit it.

        Re-authentication for ENFORCE is the API's job (V2_CONTRACTS §9);
        every flip is audited here whatever the caller.
        """
        sets = self.__sets
        if sets is None:
            raise FirewallError("guard modes need the v2 set backend")
        sets.set_guard_mode(guard, mode)
        return SecurityEvent(
            timestamp=now,
            severity=EventSeverity.WARNING,
            event_type=SecurityEventType.SYSTEM_WARNING,
            subsystem=_SUBSYSTEM,
            reason=f"guard {guard.value} set to {mode.value} by {actor}",
        )

    def guard_modes(self, now: datetime) -> GuardModes:
        """Every guard's mode as the kernel's verdict chains encode it now."""
        sets = self.__sets
        if sets is None:
            raise FirewallError("guard modes need the v2 set backend")
        modes: dict[GuardName, GuardMode] = {}
        for guard in GuardName:
            mode = sets.guard_mode(guard)
            if mode is None:
                raise FirewallError(
                    f"guard verdict chain for {guard.value} is missing (is pirewall_static loaded?)"
                )
            modes[guard] = mode
        return GuardModes(
            raw=modes[GuardName.RAW],
            input=modes[GuardName.INPUT],
            forward=modes[GuardName.FORWARD],
            read_at=now,
        )

    def missing_tables(self) -> list[tuple[str, str]]:
        """v2 tables that are not loaded. Core reports this (CRITICAL); it never recreates them."""
        sets = self.__sets
        if sets is None:
            return []
        return [location for location in nft_names.PANIC_TABLES if not sets.table_exists(*location)]

    def set_fill(self, set_name: str) -> SetFill:
        """How full one adaptive set is (critique_redteam V2: alert before a set fills)."""
        sets = self.__sets
        if sets is None:
            raise FirewallError("set fill needs the v2 set backend")
        return sets.set_fill(set_name)

    def set_backend_metrics(self) -> TransportMetrics | None:
        """The set backend's transport and counters, or None on the v1 path."""
        return None if self.__sets is None else self.__sets.metrics()

    def reconcile(self, now: datetime) -> ReconcileReport:
        """Rebuild rule state from the kernel's live set contents at startup. Never recreates a table.

        * A live element matching a known ACTIVE rule: kept.
        * A known ACTIVE rule whose element is gone: REMOVED.
        * An IP-keyed element nothing here knows about (left by a previous
          run): adopted as an ACTIVE rule against that device, expiring when
          the element does.
        * A MAC-keyed one no resolver maps to an IP: reported, left in place.
        """
        report = ReconcileReport()
        sets = self.__sets
        if sets is None:
            return report
        report.missing_tables = self.missing_tables()
        if (nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE) in report.missing_tables:
            return report
        live: dict[tuple[str, ElementKey], int | None] = {}
        for set_name in sorted(nft_names.ADAPTIVE_ENFORCEMENT_SETS):
            for element in sets.list_set(set_name):
                live[(set_name, element.key)] = element.expires_in_seconds
        known: set[tuple[str, ElementKey]] = set()
        for rule in self.active_rules():
            location = _element_of(rule)
            if location is None:
                continue
            if location in live:
                known.add(location)
                continue
            self._rules[rule.id] = rule.model_copy(update={"status": RuleStatus.REMOVED})
            self._record(
                rule.id, RuleStatus.ACTIVE, RuleStatus.REMOVED, now, "element not in the kernel at reconcile"
            )
            report.retired.append(rule.id)
        for (set_name, key), expires_in in sorted(
            live.items(), key=lambda item: (item[0][0], str(item[0][1]))
        ):
            if (set_name, key) in known:
                continue
            if set_name not in _IP_KEYED_SETS or not isinstance(key, str):
                report.unattributed.append((set_name, str(key)))
                continue
            report.adopted.append(self._adopt(set_name, key, expires_in, now))
        return report

    def _adopt(self, set_name: str, key: str, expires_in: int | None, now: datetime) -> str:
        rule_id = f"{_RECONCILED_PREFIX}:{set_name}:{key}"
        ttl = expires_in if expires_in is not None else self._config.policy.max_ttl_seconds
        rule = FirewallRule(
            id=rule_id,
            action=_ACTION_FOR_SET[set_name],
            direction=RuleDirection.INBOUND,
            source=IPv4Network(f"{key}/32"),
            destination=_WHOLE_INTERNET,
            protocol=Protocol.ANY,
            priority=0,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            deployed_at=now,
            reason=f"reconciled from the kernel at startup ({set_name} element left by a previous run)",
            status=RuleStatus.ACTIVE,
            metadata={_META_SET: set_name, _META_KEY: key},
        )
        self._rules[rule_id] = rule
        self._targets[rule_id] = RuleTarget(ip=IPv4Address(key))
        self._record(rule_id, None, RuleStatus.ACTIVE, now, "reconciled from live set contents")
        return rule_id

    def _retire_all_active(self, now: datetime, reason: str) -> int:
        removed = 0
        for rule in list(self._rules.values()):
            if rule.status is not RuleStatus.ACTIVE:
                continue
            self._rules[rule.id] = rule.model_copy(update={"status": RuleStatus.REMOVED})
            self._record(rule.id, RuleStatus.ACTIVE, RuleStatus.REMOVED, now, reason)
            removed += 1
        return removed

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


def _display_priority(threat_score: float | None) -> int:
    """v1's priority formula, kept on v2 rules for display only (higher score -> lower number)."""
    score = threat_score if threat_score is not None else 0.0
    return round(100.0 - min(max(score, 0.0), 100.0))


def _element_of(rule: FirewallRule) -> tuple[str, ElementKey] | None:
    """Where a v2 rule's element lives (from its metadata), or None for a rule with no element."""
    set_name = rule.metadata.get(_META_SET)
    key = rule.metadata.get(_META_KEY)
    if set_name is None or key is None:
        return None
    return (set_name, key)


def _delete_ops(rule: FirewallRule) -> list[SetOp]:
    location = _element_of(rule)
    if location is None:
        return []
    return [SetOp(SetOpKind.DELETE, location[0], location[1])]

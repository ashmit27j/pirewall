"""`FirewallManager(local_addresses=...)` pins the safety stage's host view (KNOWN_ISSUES.md #19).

Without it, any test that drives `submit_candidate` is judged against the
addresses the machine running the suite happens to hold. Each test here
makes the kernel's view say the opposite of the pinned one, so a pass
proves the pinned view is the one consulted, on both enforcement paths.
"""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

import pytest

from pirewall.core.enums import RuleRejectionReason, ThreatLevel
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.rule import CandidateRule
from pirewall.firewall import validator
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.firewall.local_addresses import LocalAddresses
from pirewall.firewall.manager import FirewallManager, SubmissionResult
from tests.helpers.config import make_config
from tests.helpers.rules import make_candidate

NOW = datetime(2026, 1, 1, tzinfo=UTC)
DEVICE = "192.168.1.20"
EMPTY = LocalAddresses(host=frozenset(), broadcast=frozenset())
DEVICE_IS_LOCAL = LocalAddresses(host=frozenset({IPv4Address(DEVICE)}), broadcast=frozenset())


def _register(manager: FirewallManager, candidate: CandidateRule) -> None:
    manager.register_decision(
        FirewallDecision.model_validate(
            {
                "id": candidate.decision_id,
                "threat_assessment_id": "a",
                "action": candidate.action,
                "threat_score": candidate.threat_score,
                "threat_level": ThreatLevel.CRITICAL,
                "reason": "test",
                "decided_at": NOW,
            }
        )
    )


def _submit(*, set_path: bool, pinned: LocalAddresses) -> SubmissionResult:
    config = make_config(firewall={"enforcement_mode": "active"})
    manager = FirewallManager(
        config,
        FakeFirewallBackend(),
        set_backend=FakeSetBackend(lambda: NOW) if set_path else None,
        local_addresses=pinned,
    )
    candidate = make_candidate(
        source=f"{DEVICE}/32",
        destination="203.0.113.9/32",
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=300),
        evidence=("evidence-1",),
    )
    _register(manager, candidate)
    return manager.submit_candidate(candidate, NOW)


@pytest.mark.parametrize("set_path", [False, True], ids=["v1-rules", "v2-sets"])
def test_a_pinned_host_address_is_refused_even_when_the_kernel_disagrees(
    monkeypatch: pytest.MonkeyPatch, set_path: bool
) -> None:
    monkeypatch.setattr(validator, "cached_local_addresses", lambda: EMPTY)

    result = _submit(set_path=set_path, pinned=DEVICE_IS_LOCAL)

    assert result.rule is None
    assert RuleRejectionReason.UNSAFE.value in (result.event.reason or "")


@pytest.mark.parametrize("set_path", [False, True], ids=["v1-rules", "v2-sets"])
def test_a_pinned_empty_view_ignores_the_hosts_real_addresses(
    monkeypatch: pytest.MonkeyPatch, set_path: bool
) -> None:
    # The machine "holds" the device's address; the pinned view says it
    # holds nothing, and the pinned view must win (the #19 failure mode).
    monkeypatch.setattr(validator, "cached_local_addresses", lambda: DEVICE_IS_LOCAL)

    result = _submit(set_path=set_path, pinned=EMPTY)

    assert result.rule is not None, result.event.reason

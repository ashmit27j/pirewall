"""The v2 policy table, exhaustively (ADDENDUM_4.md D4, PLAN_FINAL §4.6; phase 17).

The cross-product {K none/observe/enforce-pending/enforce-sustained} x
{D1 none/single/repeat-new/repeat-same} x {D2 none/anomaly} x
{D3 none/attack} x {SHADOW/ASSISTED/ACTIVE} is checked against an
independent statement of the table (`_expected`), and the D4 invariants are
asserted separately: ML-only and anomaly-only <= MONITOR, observe-mode K
<= MONITOR, allowlisted => nothing, escalation only on new evidence, and
scores never move an action.
"""

import itertools
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from typing import Final, Literal

import pytest

from pirewall.config.models import PolicyConfig
from pirewall.core.enums import D1Detector, EnforcementMode, FirewallAction, GuardMode, GuardName
from pirewall.core.exceptions import ConfigurationError
from pirewall.core.models.evidence import AnomalyEvidence
from pirewall.core.models.evidence_v2 import ClassifierEvidence, D1Evidence, KernelGuardEvidence
from pirewall.core.models.identity import RuleTarget
from pirewall.core.models.policy import PolicyDecision
from pirewall.core.nft_names import OffenderCode
from pirewall.policy.engine import Evidence, EvidenceBundle, PolicyEngine
from pirewall.policy.table import PolicyTable, load_policy_table

NOW: Final = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
MAC: Final = "02:00:00:00:00:66"
TARGET: Final = RuleTarget(ip=IPv4Address("192.168.1.66"), mac=MAC)
TABLE_PATH: Final = Path(__file__).resolve().parents[2] / "pirewall" / "policy" / "table.toml"
CONFIG: Final = PolicyConfig()

K = Literal["none", "observe", "enforce_pending", "enforce_sustained"]
D1 = Literal["none", "single", "repeat_new", "repeat_same"]
MODES: Final = (EnforcementMode.SHADOW, EnforcementMode.ASSISTED, EnforcementMode.ACTIVE)
_ORDER: Final = {None: 0, FirewallAction.MONITOR: 1, FirewallAction.RATE_LIMIT: 2, FirewallAction.BLOCK: 3}


@pytest.fixture(scope="module")
def table() -> PolicyTable:
    return load_policy_table(TABLE_PATH)


def _kernel(state: K) -> list[KernelGuardEvidence]:
    if state == "none":
        return []
    mode = GuardMode.OBSERVE if state == "observe" else GuardMode.ENFORCE
    polls = CONFIG.sustained_polls if state == "enforce_sustained" else 1
    return [
        KernelGuardEvidence(
            id=f"k:{state}",
            code=OffenderCode.NEWCONN,
            mac=MAC,
            guard=GuardName.FORWARD,
            guard_mode=mode,
            sustained_polls=polls,
            observed_at=NOW,
        )
    ]


def _d1(
    evidence_id: str, detector: D1Detector = D1Detector.VERTICAL_SCAN, value: float = 120.0
) -> D1Evidence:
    return D1Evidence(
        id=evidence_id,
        detector=detector,
        window_seconds=60,
        value=value,
        threshold=25.0,
        mac=MAC,
        observed_at=NOW,
    )


def _anomaly(score: float = -0.3) -> AnomalyEvidence:
    return AnomalyEvidence(
        flow_id="f-anomaly",
        anomaly_score=score,
        threshold=0.0,
        is_anomaly=True,
        model_version="if-1",
        feature_schema_version="3.0.0",
        generated_at=NOW,
    )


def _classifier(probability: float = 0.97) -> ClassifierEvidence:
    return ClassifierEvidence(
        flow_id="f-classifier",
        mac=MAC,
        attack_probability=probability,
        operating_threshold=0.8,
        is_attack=probability >= 0.8,
        model_version="lgbm-1",
        feature_schema_version="3.0.0",
        generated_at=NOW,
    )


def _strongest(decisions: tuple[PolicyDecision, ...], *, include_pending: bool) -> FirewallAction | None:
    actions = [item.action for item in decisions if include_pending or not item.requires_approval]
    return max(actions, key=_ORDER.__getitem__, default=None)


def _run(
    table: PolicyTable, k: K, d1: D1, d2: bool, d3: bool, mode: EnforcementMode
) -> tuple[PolicyDecision, ...]:
    """The decisions of the *last* evaluation for one matrix cell."""
    engine = PolicyEngine(table, CONFIG)
    ml: list[Evidence] = [*([_anomaly()] if d2 else []), *([_classifier()] if d3 else [])]
    if d1 in ("repeat_new", "repeat_same"):
        first = engine.decide(EvidenceBundle(TARGET, (_d1("d1:first"),)), mode, NOW)
        for decision in first:
            engine.record_enforced(decision, had_d1=True)
    d1_items = {
        "none": [],
        "single": [_d1("d1:first")],
        "repeat_new": [_d1("d1:second")],
        "repeat_same": [_d1("d1:first")],
    }[d1]
    bundle = EvidenceBundle(TARGET, (*_kernel(k), *d1_items, *ml))
    return engine.decide(bundle, mode, NOW + timedelta(seconds=61))


def _expected(k: K, d1: D1, d2: bool, d3: bool, mode: EnforcementMode) -> tuple[FirewallAction | None, bool]:
    """(strongest direct action, BLOCK held for approval?) per PLAN_FINAL §4.6, written out independently.

    SHADOW computes the ACTIVE column (the manager records it SHADOWED).
    """
    column = EnforcementMode.ACTIVE if mode is EnforcementMode.SHADOW else mode
    assisted = column is EnforcementMode.ASSISTED
    ml = d2 or d3
    # Only evidence new to the device classifies it: a repeated D1 id counts for nothing.
    new_d1 = d1 in ("single", "repeat_new")
    d1_present = new_d1
    sustained = k == "enforce_sustained"
    escalated = new_d1 and (sustained or d1 == "repeat_new")
    actions: list[FirewallAction] = []
    approval = False
    if k in ("observe", "enforce_pending"):
        actions.append(FirewallAction.MONITOR)
    if sustained:
        actions.append(FirewallAction.RATE_LIMIT)
    if d1_present:  # vertical scan: high certainty
        if assisted:
            actions.append(FirewallAction.RATE_LIMIT)
            approval = True
        else:
            actions.append(FirewallAction.BLOCK)
    if escalated:
        if assisted:
            approval = True
        else:
            actions.append(FirewallAction.BLOCK)
    if ml:
        actions.append(FirewallAction.RATE_LIMIT if d1_present else FirewallAction.MONITOR)
    strongest = max(actions, key=_ORDER.__getitem__, default=None)
    if approval and strongest is FirewallAction.BLOCK:
        approval = False
    return strongest, approval


_CELLS: Final = list(
    itertools.product(
        ("none", "observe", "enforce_pending", "enforce_sustained"),
        ("none", "single", "repeat_new", "repeat_same"),
        (False, True),
        (False, True),
        MODES,
    )
)


@pytest.mark.parametrize(("k", "d1", "d2", "d3", "mode"), _CELLS)
def test_policy_matrix(table: PolicyTable, k: K, d1: D1, d2: bool, d3: bool, mode: EnforcementMode) -> None:
    decisions = _run(table, k, d1, d2, d3, mode)
    expected_action, expected_approval = _expected(k, d1, d2, d3, mode)

    assert _strongest(decisions, include_pending=False) is expected_action
    assert any(item.requires_approval for item in decisions) is expected_approval
    for item in decisions:
        assert item.target == TARGET
        if item.action in (FirewallAction.RATE_LIMIT, FirewallAction.BLOCK):
            assert item.ttl_seconds is not None and item.ttl_seconds <= CONFIG.max_ttl_seconds


def test_the_matrix_is_complete() -> None:
    assert len(_CELLS) == 4 * 4 * 2 * 2 * 3


# ------------------------------------------------------------------ invariants


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(("d2", "d3"), [(True, False), (False, True), (True, True)])
def test_ml_only_and_anomaly_only_never_exceed_monitor(
    table: PolicyTable, mode: EnforcementMode, d2: bool, d3: bool
) -> None:
    for k in ("none", "observe", "enforce_pending"):
        decisions = _run(table, k, "none", d2, d3, mode)
        assert _strongest(decisions, include_pending=True) in (None, FirewallAction.MONITOR)


@pytest.mark.parametrize("mode", MODES)
def test_an_observe_mode_offender_is_at_most_monitor_however_long_it_persists(
    table: PolicyTable, mode: EnforcementMode
) -> None:
    engine = PolicyEngine(table, CONFIG)
    for polls in range(1, 30):
        evidence = KernelGuardEvidence(
            id=f"k:observe:{polls}",
            code=OffenderCode.SYN_PPS,
            mac=MAC,
            guard=GuardName.RAW,
            guard_mode=GuardMode.OBSERVE,
            sustained_polls=polls,
            observed_at=NOW,
        )
        decisions = engine.decide(EvidenceBundle(TARGET, (evidence,)), mode, NOW)
        assert _strongest(decisions, include_pending=True) in (None, FirewallAction.MONITOR)


@pytest.mark.parametrize("mode", MODES)
def test_an_allowlisted_target_gets_nothing(table: PolicyTable, mode: EnforcementMode) -> None:
    engine = PolicyEngine(table, CONFIG, is_protected=lambda target: target == TARGET)
    bundle = EvidenceBundle(TARGET, (*_kernel("enforce_sustained"), _d1("d1:a"), _classifier()))

    assert engine.decide(bundle, mode, NOW) == ()


def test_repeating_the_same_evidence_never_escalates(table: PolicyTable) -> None:
    engine = PolicyEngine(table, CONFIG)
    bundle = EvidenceBundle(TARGET, (_d1("d1:same"),))
    first = engine.decide(bundle, EnforcementMode.ACTIVE, NOW)
    for decision in first:
        engine.record_enforced(decision, had_d1=True)

    for step in range(1, 10):
        assert engine.decide(bundle, EnforcementMode.ACTIVE, NOW + timedelta(seconds=step)) == ()


def test_new_independent_evidence_doubles_the_block_ttl_up_to_the_cap(table: PolicyTable) -> None:
    engine = PolicyEngine(table, CONFIG)
    ttls: list[int] = []
    for strike in range(8):
        (decision,) = engine.decide(
            EvidenceBundle(TARGET, (_d1(f"d1:{strike}"),)),
            EnforcementMode.ACTIVE,
            NOW + timedelta(minutes=strike),
        )
        assert decision.action is FirewallAction.BLOCK
        assert decision.ttl_seconds is not None
        ttls.append(decision.ttl_seconds)
        engine.record_enforced(decision, had_d1=True)

    base = CONFIG.block_ttl_seconds
    assert ttls[:4] == [base, base * 2, base * 4, base * 8]
    assert max(ttls) == CONFIG.max_ttl_seconds


def test_a_refused_decision_does_not_count_as_a_strike(table: PolicyTable) -> None:
    engine = PolicyEngine(table, CONFIG)
    engine.decide(EvidenceBundle(TARGET, (_d1("d1:a"),)), EnforcementMode.ACTIVE, NOW)  # not recorded
    (second,) = engine.decide(EvidenceBundle(TARGET, (_d1("d1:b"),)), EnforcementMode.ACTIVE, NOW)

    assert second.ttl_seconds == CONFIG.block_ttl_seconds


def test_an_enforce_offender_needs_sustained_polls_before_rate_limit(table: PolicyTable) -> None:
    assert _strongest(
        _run(table, "enforce_pending", "none", False, False, EnforcementMode.ACTIVE), include_pending=True
    ) is (FirewallAction.MONITOR)
    decisions = _run(table, "enforce_sustained", "none", False, False, EnforcementMode.ACTIVE)
    assert _strongest(decisions, include_pending=True) is FirewallAction.RATE_LIMIT
    assert decisions[0].ttl_seconds == CONFIG.rate_limit_ttl_seconds


def test_assisted_submits_the_held_block_before_the_rate_limit(table: PolicyTable) -> None:
    decisions = _run(table, "none", "single", False, False, EnforcementMode.ASSISTED)

    assert [(item.action, item.requires_approval) for item in decisions] == [
        (FirewallAction.BLOCK, True),
        (FirewallAction.RATE_LIMIT, False),
    ]


@pytest.mark.parametrize("mode", MODES)
def test_scores_never_move_an_action(table: PolicyTable, mode: EnforcementMode) -> None:
    """D4: mutate every score; the actions must not change."""

    def actions(score_scale: float) -> list[tuple[FirewallAction, bool]]:
        engine = PolicyEngine(table, CONFIG)
        out: list[tuple[FirewallAction, bool]] = []
        bundles = [
            (_anomaly(-0.01 * score_scale),),
            (_classifier(min(0.81 + 0.01 * score_scale, 1.0)),),
            (_d1("d1:x", value=26.0 * score_scale),),
            (_d1("d1:y", D1Detector.FAILED_HANDSHAKE, value=0.9), _anomaly(-5 * score_scale)),
        ]
        for index, items in enumerate(bundles):
            target = RuleTarget(ip=IPv4Address(f"192.168.1.{100 + index}"), mac=f"02:00:00:00:01:{index:02x}")
            out.extend(
                (item.action, item.requires_approval)
                for item in engine.decide(EvidenceBundle(target, items), mode, NOW)
            )
        return out

    baseline = actions(1.0)
    for scale in (0.5, 2.0, 10.0, 1000.0):
        assert actions(scale) == baseline


# ---------------------------------------------------------------- the table file


def _write_table(tmp_path: Path, replace: tuple[str, str]) -> Path:
    text = TABLE_PATH.read_text(encoding="utf-8")
    assert replace[0] in text
    path = tmp_path / "table.toml"
    path.write_text(text.replace(replace[0], replace[1], 1), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "replace",
    [
        # An ML-only row raised above MONITOR.
        (
            'evidence = "ml_only"             # D2 and/or D3 with no D1\n'
            'shadow = ["log"]\nassisted = ["monitor"]',
            'evidence = "ml_only"\nshadow = ["log"]\nassisted = ["rate_limit"]',
        ),
        # SHADOW that writes.
        (
            'evidence = "k_observe"           # @offenders from an observe-mode guard\nshadow = ["log"]',
            'evidence = "k_observe"\nshadow = ["monitor"]',
        ),
        # The approval queue in ACTIVE.
        (
            'assisted = ["block_approval"]\nactive = ["block"]',
            'assisted = ["block_approval"]\nactive = ["block_approval"]',
        ),
        # A detector in both tiers.
        ('standard = ["failed_handshake"', 'standard = ["vertical_scan", "failed_handshake"'),
    ],
)
def test_a_table_that_breaks_a_ceiling_is_refused(tmp_path: Path, replace: tuple[str, str]) -> None:
    with pytest.raises(ConfigurationError):
        load_policy_table(_write_table(tmp_path, replace))


def test_a_table_missing_a_row_is_refused(tmp_path: Path) -> None:
    text = TABLE_PATH.read_text(encoding="utf-8")
    cut = text.index('[[row]]\nevidence = "ml_with_d1"')
    path = tmp_path / "table.toml"
    path.write_text(text[:cut], encoding="utf-8")

    with pytest.raises(ConfigurationError, match="ml_with_d1"):
        load_policy_table(path)

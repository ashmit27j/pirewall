"""The interim ML ceiling on the v1 path (ADDENDUM_4.md D4 applied to v1; KNOWN_ISSUES #1, #2).

While `threat.ml_evidence_can_enforce` is false, LightGBM and Isolation
Forest evidence may raise the reported score and level, and lift ALLOW to
MONITOR, but the action comes from behavior and protocol-signature evidence
alone. These run the real `assess_threat` -> `decide` path with the real
default weights, so a weight change that reopened the hole would fail here.
"""

import itertools
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from pirewall.config.loader import load_config
from pirewall.config.models import ThreatConfig
from pirewall.core.enums import BehaviorPatternType, FirewallAction, ThreatLevel
from pirewall.core.models.behavior import BehaviorAssessment
from pirewall.core.models.decision import FirewallDecision
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence, ProtocolSignatureEvidence
from pirewall.engine.decision import decide
from pirewall.engine.threat import assess_threat

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
CLIENT = IPv4Address("192.168.100.78")
SHOP = IPv4Address("23.227.38.74")
_REPO_ROOT = Path(__file__).resolve().parents[2]

_RANK = {
    FirewallAction.ALLOW: 0,
    FirewallAction.MONITOR: 1,
    FirewallAction.RATE_LIMIT: 2,
    FirewallAction.BLOCK: 3,
}

# The patterns one phone produced loading one shop page (KNOWN_ISSUES #3): 30 points.
PAGE_LOAD = (
    BehaviorPatternType.DESTINATION_DIVERSITY,
    BehaviorPatternType.REPEATED_CONNECTIONS,
    BehaviorPatternType.HIGH_FREQUENCY,
    BehaviorPatternType.BURST,
)
# The attack-lab nmap scan: 75 points, HIGH on its own.
SCAN = (BehaviorPatternType.SCANNING, BehaviorPatternType.BURST, BehaviorPatternType.HIGH_FREQUENCY)


def _known(predicted_class: str = "Bot", confidence: float = 0.9999974) -> KnownEvidence:
    return KnownEvidence(
        flow_id="flow-1",
        predicted_class=predicted_class,
        confidence=confidence,
        model_version="1.0.0",
        feature_schema_version="2.0.0",
        generated_at=NOW,
    )


def _anomaly() -> AnomalyEvidence:
    return AnomalyEvidence(
        flow_id="flow-1",
        anomaly_score=-0.12,
        threshold=0.0,
        is_anomaly=True,
        model_version="1.0.0",
        feature_schema_version="2.0.0",
        generated_at=NOW,
    )


def _behavior(patterns: tuple[BehaviorPatternType, ...]) -> BehaviorAssessment | None:
    if not patterns:
        return None
    return BehaviorAssessment(
        source_ip=CLIENT,
        detected_patterns=patterns,
        confidence=0.8,
        description="test",
        window_start=NOW,
        window_end=NOW,
    )


def _heartbleed() -> ProtocolSignatureEvidence:
    return ProtocolSignatureEvidence(
        flow_id="flow-1",
        signature="heartbleed",
        confidence=1.0,
        detail="claimed 65535 bytes, 16 present",
        generated_at=NOW,
    )


def _decide(
    *,
    known: KnownEvidence | None = None,
    anomaly: AnomalyEvidence | None = None,
    patterns: tuple[BehaviorPatternType, ...] = (),
    signature: ProtocolSignatureEvidence | None = None,
    ml_can_enforce: bool = False,
) -> FirewallDecision:
    assessment = assess_threat(
        ThreatConfig(ml_evidence_can_enforce=ml_can_enforce),
        flow_id="flow-1",
        source_ip=CLIENT,
        destination_ip=SHOP,
        known_evidence=known,
        anomaly_evidence=anomaly,
        behavior_assessment=_behavior(patterns),
        assessed_at=NOW,
        protocol_signature_evidence=signature,
    )
    return decide(assessment, NOW)


def test_the_ceiling_is_on_by_default_everywhere_a_config_comes_from() -> None:
    assert ThreatConfig().ml_evidence_can_enforce is False
    default = load_config(_REPO_ROOT / "config" / "default_config.toml")
    assert default.threat.ml_evidence_can_enforce is False


def test_a_saturated_false_bot_verdict_is_capped_at_monitor() -> None:
    """KNOWN_ISSUES #1: a saturated "Bot" verdict plus an anomaly flag scores exactly 75, RATE_LIMIT.

    The observed 99.99974% scores 74.9998, just under `high_threshold`; a
    verdict that saturates to 1.0 lands on it.
    """
    decision = _decide(known=_known(confidence=1.0), anomaly=_anomaly())
    assert decision.threat_level is ThreatLevel.HIGH, "the reported level is unchanged"
    assert decision.action is FirewallAction.MONITOR
    assert "action capped at monitor (would be rate_limit)" in decision.reason
    assert "ml_evidence_can_enforce" in decision.reason


def test_the_same_verdict_on_a_page_load_cannot_block() -> None:
    """With page-load behavior on top, the uncapped score is 100: CRITICAL, BLOCK."""
    uncapped = _decide(known=_known(), anomaly=_anomaly(), patterns=PAGE_LOAD, ml_can_enforce=True)
    assert uncapped.action is FirewallAction.BLOCK, "precondition: this is the hole being closed"

    capped = _decide(known=_known(), anomaly=_anomaly(), patterns=PAGE_LOAD)
    assert capped.threat_level is ThreatLevel.CRITICAL
    assert capped.action is FirewallAction.MONITOR


def test_turning_the_ceiling_off_restores_the_old_ladder() -> None:
    decision = _decide(known=_known(confidence=1.0), anomaly=_anomaly(), ml_can_enforce=True)
    assert decision.action is FirewallAction.RATE_LIMIT
    assert "capped" not in decision.reason


def test_a_scan_still_acts_on_its_behavior_alone() -> None:
    """D4's "D2/D3 + D1 -> RATE_LIMIT": ML on top of a scan adds nothing to the action."""
    decision = _decide(known=_known("PortScan", 0.99), anomaly=_anomaly(), patterns=SCAN)
    assert decision.threat_level is ThreatLevel.CRITICAL
    assert decision.action is FirewallAction.RATE_LIMIT


def test_behavior_only_decisions_are_untouched() -> None:
    decision = _decide(patterns=SCAN)
    assert decision.action is FirewallAction.RATE_LIMIT
    assert "capped" not in decision.reason


def test_a_protocol_signature_is_deterministic_evidence_and_still_acts() -> None:
    decision = _decide(signature=_heartbleed())
    assert decision.action is FirewallAction.RATE_LIMIT
    assert "capped" not in decision.reason


def test_anomaly_alone_is_not_lifted_to_monitor() -> None:
    """15 points is LOW: the MONITOR floor only applies where the full level was already MEDIUM+."""
    assert _decide(anomaly=_anomaly()).action is FirewallAction.ALLOW


def test_a_known_attack_alone_stays_monitor_without_a_cap_note() -> None:
    decision = _decide(known=_known())
    assert decision.action is FirewallAction.MONITOR
    assert "capped" not in decision.reason


_PATTERN_SETS: tuple[tuple[BehaviorPatternType, ...], ...] = (
    (),
    PAGE_LOAD,
    SCAN,
    (BehaviorPatternType.FLOOD,),
    (BehaviorPatternType.REPEATED_FAILURES,),
    (BehaviorPatternType.BURST,),
)


@pytest.mark.parametrize(
    ("known", "anomaly", "patterns", "signature"),
    list(
        itertools.product(
            (None, _known(), _known("BENIGN", 0.99), _known("DDoS", 0.85)),
            (None, _anomaly()),
            _PATTERN_SETS,
            (None, _heartbleed()),
        )
    ),
)
def test_ml_evidence_never_raises_an_action_past_monitor(
    known: KnownEvidence | None,
    anomaly: AnomalyEvidence | None,
    patterns: tuple[BehaviorPatternType, ...],
    signature: ProtocolSignatureEvidence | None,
) -> None:
    """The D4 matrix: with ML evidence added, the action is at most max(non-ML action, MONITOR)."""
    without_ml = _decide(patterns=patterns, signature=signature)
    with_ml = _decide(known=known, anomaly=anomaly, patterns=patterns, signature=signature)
    allowed = max(_RANK[without_ml.action], _RANK[FirewallAction.MONITOR])
    assert _RANK[with_ml.action] <= allowed
    if _RANK[without_ml.action] >= _RANK[FirewallAction.MONITOR]:
        assert with_ml.action is without_ml.action, "ML evidence must not lower a deterministic action"

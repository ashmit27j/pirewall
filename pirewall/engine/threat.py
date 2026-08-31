"""Produces the final, explainable `ThreatAssessment` (spec §18).

This is the last stop before a firewall decision could be made (Phase 6) —
and deliberately stops here: no `FirewallDecision`, no candidate rules, no
backend calls happen in this module or anything it calls.
"""

from datetime import datetime
from ipaddress import IPv4Address
from uuid import uuid4

from pirewall.config.models import ThreatConfig
from pirewall.core.enums import ThreatLevel
from pirewall.core.models.behavior import BehaviorAssessment
from pirewall.core.models.evidence import AnomalyEvidence, KnownEvidence, ProtocolSignatureEvidence
from pirewall.core.models.threat import ThreatAssessment
from pirewall.engine.scoring import ScoreBreakdown, score_evidence
from pirewall.ml.labels import is_attack_label


def assess_threat(
    config: ThreatConfig,
    flow_id: str,
    source_ip: IPv4Address,
    destination_ip: IPv4Address,
    known_evidence: KnownEvidence | None,
    anomaly_evidence: AnomalyEvidence | None,
    behavior_assessment: BehaviorAssessment | None,
    assessed_at: datetime,
    protocol_signature_evidence: ProtocolSignatureEvidence | None = None,
) -> ThreatAssessment:
    """Combine whichever evidence is available into one explainable `ThreatAssessment`.

    Deterministic: identical inputs always produce an identical
    `ThreatAssessment` (aside from the freshly generated `id`).
    """
    breakdown = score_evidence(
        config, known_evidence, anomaly_evidence, behavior_assessment, protocol_signature_evidence
    )
    level = _determine_level(breakdown.total, config)
    explanation, contributing_evidence = _explain(
        breakdown, known_evidence, anomaly_evidence, behavior_assessment, protocol_signature_evidence
    )
    confidence = _overall_confidence(
        known_evidence, anomaly_evidence, behavior_assessment, protocol_signature_evidence
    )

    return ThreatAssessment(
        id=str(uuid4()),
        flow_id=flow_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        threat_score=breakdown.total,
        threat_level=level,
        confidence=confidence,
        known_evidence=known_evidence,
        anomaly_evidence=anomaly_evidence,
        behavior_assessment=behavior_assessment,
        protocol_signature_evidence=protocol_signature_evidence,
        explanation=explanation,
        contributing_evidence=tuple(contributing_evidence),
        assessed_at=assessed_at,
    )


def _determine_level(score: float, config: ThreatConfig) -> ThreatLevel:
    if score >= config.critical_threshold:
        return ThreatLevel.CRITICAL
    if score >= config.high_threshold:
        return ThreatLevel.HIGH
    if score >= config.medium_threshold:
        return ThreatLevel.MEDIUM
    return ThreatLevel.LOW


def _explain(
    breakdown: ScoreBreakdown,
    known_evidence: KnownEvidence | None,
    anomaly_evidence: AnomalyEvidence | None,
    behavior_assessment: BehaviorAssessment | None,
    protocol_signature_evidence: ProtocolSignatureEvidence | None,
) -> tuple[str, list[str]]:
    parts: list[str] = []
    contributing: list[str] = []

    if known_evidence is not None and breakdown.known_attack_contribution > 0:
        parts.append(
            f"classified as {known_evidence.predicted_class!r} "
            f"with {known_evidence.confidence:.0%} confidence"
        )
        contributing.append(f"known_evidence:{known_evidence.predicted_class}")

    if anomaly_evidence is not None and breakdown.anomaly_contribution > 0:
        parts.append(f"anomalous traffic pattern (score={anomaly_evidence.anomaly_score:.3f})")
        contributing.append("anomaly_evidence:anomalous")

    if behavior_assessment is not None and breakdown.behavior_contribution > 0:
        pattern_names = ", ".join(pattern.value for pattern in behavior_assessment.detected_patterns)
        parts.append(f"behavioral patterns: {pattern_names}")
        contributing.extend(f"behavior:{pattern.value}" for pattern in behavior_assessment.detected_patterns)

    if protocol_signature_evidence is not None and breakdown.protocol_signature_contribution > 0:
        parts.append(f"protocol signature match: {protocol_signature_evidence.detail}")
        contributing.append(f"protocol_signature:{protocol_signature_evidence.signature}")

    explanation = "; ".join(parts) if parts else "no significant threat indicators observed"
    return explanation, contributing


def _overall_confidence(
    known_evidence: KnownEvidence | None,
    anomaly_evidence: AnomalyEvidence | None,
    behavior_assessment: BehaviorAssessment | None,
    protocol_signature_evidence: ProtocolSignatureEvidence | None,
) -> float:
    """The strongest single piece of corroborating evidence's own certainty."""
    candidates = [0.0]
    if known_evidence is not None and is_attack_label(known_evidence.predicted_class):
        candidates.append(known_evidence.confidence)
    if anomaly_evidence is not None and anomaly_evidence.is_anomaly:
        candidates.append(0.7)
    if behavior_assessment is not None and behavior_assessment.detected_patterns:
        candidates.append(behavior_assessment.confidence)
    if protocol_signature_evidence is not None:
        candidates.append(protocol_signature_evidence.confidence)
    return max(candidates)

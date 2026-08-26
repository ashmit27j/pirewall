"""Detection: known-attack classification, anomaly detection, behavior analysis (Phase 5)."""

from pirewall.detection.anomaly import detect as detect_anomaly
from pirewall.detection.behavior import BehaviorAnalyzer, SourceBehaviorState
from pirewall.detection.known_attack import classify as classify_known_attack

__all__ = [
    "BehaviorAnalyzer",
    "SourceBehaviorState",
    "classify_known_attack",
    "detect_anomaly",
]

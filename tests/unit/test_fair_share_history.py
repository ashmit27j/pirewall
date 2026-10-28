"""`FairShareHistory` and `CoreStateStore`'s use of it (KNOWN_ISSUES.md #21)."""

from datetime import UTC, datetime
from ipaddress import IPv4Address

import pytest

from pirewall.core.enums import ThreatLevel
from pirewall.core.models.detection_record import DetectionRecord
from pirewall.core.models.threat import ThreatAssessment
from pirewall.ipc.history import FairShareHistory
from pirewall.ipc.state import CoreStateStore

NOW = datetime(2026, 1, 1, tzinfo=UTC)
SCANNER = IPv4Address("198.51.100.7")
FLOODER = IPv4Address("203.0.113.66")


def _history(maxlen: int) -> FairShareHistory[tuple[str, int]]:
    return FairShareHistory(maxlen, key=lambda item: item[0])


def test_one_key_is_exactly_oldest_first() -> None:
    history = _history(3)
    for n in range(10):
        history.append(("a", n))

    assert list(history) == [("a", 7), ("a", 8), ("a", 9)]
    assert len(history) == 3
    assert history[0] == ("a", 7)
    assert history[-1] == ("a", 9)


def test_a_single_source_flood_evicts_only_its_own_records() -> None:
    """The observed #21 case: a scan, then a much larger flood from elsewhere."""
    history = _history(500)
    for n in range(40):
        history.append(("scanner", n))
    for n in range(10_000):
        history.append(("flooder", n))

    scanner = [item for item in history if item[0] == "scanner"]
    assert scanner == [("scanner", n) for n in range(40)]
    assert len(history) == 500
    # The flooder keeps its most recent records, in order.
    assert history[-1] == ("flooder", 9_999)


def test_iteration_stays_chronological_across_keys() -> None:
    history = _history(4)
    for item in [("a", 1), ("b", 1), ("a", 2), ("b", 2), ("a", 3)]:
        history.append(item)

    # "a" held the most, so its oldest went.
    assert list(history) == [("b", 1), ("a", 2), ("b", 2), ("a", 3)]


def test_equal_shares_evict_the_oldest_overall() -> None:
    """A source-spoofing flood gives every key one entry and degrades to oldest-first."""
    history = _history(3)
    for n in range(6):
        history.append((f"spoofed-{n}", n))

    assert list(history) == [("spoofed-3", 3), ("spoofed-4", 4), ("spoofed-5", 5)]


def test_an_explicit_key_overrides_the_key_function() -> None:
    history: FairShareHistory[str] = FairShareHistory(2, key=lambda _item: "same")
    history.append("x1", key="x")
    history.append("y1", key="y")
    history.append("x2", key="x")

    assert list(history) == ["y1", "x2"]


def test_maxlen_must_be_positive() -> None:
    with pytest.raises(ValueError, match="maxlen"):
        _history(0)


def _threat(n: int, source: IPv4Address) -> ThreatAssessment:
    return ThreatAssessment(
        id=f"threat-{n}",
        flow_id=f"flow-{n}",
        source_ip=source,
        destination_ip=IPv4Address("192.168.1.10"),
        threat_score=70.0,
        threat_level=ThreatLevel.HIGH,
        confidence=0.9,
        explanation="test",
        assessed_at=NOW,
    )


def test_core_state_keeps_a_scanners_records_through_a_flood() -> None:
    state = CoreStateStore(max_history=100, started_at=NOW)
    for n in range(10):
        state.record_detection(DetectionRecord(flow_id=f"scan-{n}", recorded_at=NOW), SCANNER)
        state.record_threat(_threat(n, SCANNER))
    for n in range(10, 5_000):
        state.record_detection(DetectionRecord(flow_id=f"flood-{n}", recorded_at=NOW), FLOODER)
        state.record_threat(_threat(n, FLOODER))

    assert len(state.detections) == 100
    assert len(state.threats) == 100
    assert [r.flow_id for r in state.detections][:10] == [f"scan-{n}" for n in range(10)]
    assert sum(1 for t in state.threats if t.source_ip == SCANNER) == 10

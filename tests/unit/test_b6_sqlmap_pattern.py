"""B6 (ADDENDUM_2.md): does the volumetric/behavioral layer indirectly catch sqlmap-style probing?

sqlmap can never be classified by *content* here (spec §7: no payload
inspection) — but its *rate pattern* (many rapid probe requests to one
endpoint) is structurally similar to the brute-force patterns
`pirewall.detection.behavior` already detects well (SSH-Patator,
FTP-Patator). This is a genuine empirical question, not a foregone
conclusion — see `docs/ADDENDUM_2.md` B6 for the reported result and its
honest caveats, which this file's test outcomes are the source of.

**Timing model.** Real request timing has jitter (network RTT, server
processing time) — a naive perfectly-regular synthetic timestamp sequence
would make `TEMPORAL_PATTERN` fire artificially in every scenario
regardless of realism (a machine-precision interval is not what real
traffic looks like even for an automated tool). Every scenario below
therefore applies bounded random jitter (a fixed seed, for a reproducible
test) around a base request interval, not a perfectly regular one, so a
result here reflects genuinely irregular-but-automated timing rather than
an artifact of clean test construction.

Drives real `FlowAggregator` + `BehaviorAnalyzer` wiring (the same
`on_new_flow` callback `pirewall.runtime.core.CoreDaemon` uses, per
ADDENDUM_2.md B1) with hand-built `PacketMetadata` carrying controlled
timestamps, rather than literal `FakePacketCapture` byte-level packets —
`FakePacketCapture.read_packets()` stamps every packet with the real wall
clock at read time, which would force this test to either lose control of
inter-arrival timing entirely or add several real seconds of
`time.sleep()`. This exercises the identical production call path
deterministically instead, matching every existing behavior-pattern
test's own convention (`tests/unit/test_behavior.py`).
"""

import random
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from pirewall.config.models import DetectionConfig, FlowConfig
from pirewall.core.enums import BehaviorPatternType
from pirewall.detection.behavior import BehaviorAnalyzer
from pirewall.flow.aggregator import FlowAggregator
from tests.helpers.flows import make_packet

T0 = datetime(2026, 1, 1, tzinfo=UTC)

_SOURCE = "203.0.113.200"
_DESTINATION = "10.0.0.80"
_PORT = 80


def _simulate_probe_sequence(
    analyzer: BehaviorAnalyzer,
    *,
    count: int,
    mean_interval_seconds: float,
    jitter_fraction: float,
    seed: int,
) -> None:
    """Feed `count` HTTP-shaped connections through the real wiring, `mean_interval_seconds`
    apart on average, each perturbed by up to `jitter_fraction` (reproducibly, via `seed`)."""
    rng = random.Random(seed)
    aggregator = FlowAggregator(
        FlowConfig(),
        on_new_flow=lambda signal: analyzer.observe_new_connection(
            signal.source_ip, signal.destination_ip, signal.destination_port, signal.timestamp
        ),
    )
    elapsed = 0.0
    for i in range(count):
        aggregator.process_packet(
            make_packet(
                source_ip=_SOURCE,
                destination_ip=_DESTINATION,
                source_port=40000 + i,  # a new connection per probe request, not keep-alive reuse
                destination_port=_PORT,
                timestamp=T0 + timedelta(seconds=elapsed),
            )
        )
        elapsed += mean_interval_seconds * (1 + rng.uniform(-jitter_fraction, jitter_fraction))


def test_a_full_multi_technique_sqlmap_scan_triggers_default_thresholds() -> None:
    """~5 requests/second for 8s, +-20% jitter: a full technique/payload sweep against one parameter.

    This is well within sqlmap's ordinary unthrottled request rate when
    testing multiple injection techniques (boolean-blind, time-blind,
    UNION, error-based) against a single parameter with no `--delay` set.
    Stable across 10 different jitter seeds when this test was developed
    (see docs/ADDENDUM_2.md B6) — not a lucky draw.
    """
    analyzer = BehaviorAnalyzer(DetectionConfig())  # shipped defaults, not tuned for this test
    _simulate_probe_sequence(
        analyzer, count=40, mean_interval_seconds=0.2, jitter_fraction=0.2, seed=0
    )

    assessment = analyzer.assess(IPv4Address(_SOURCE))

    assert assessment is not None
    assert assessment.detected_patterns != ()
    # B6 finding: caught by the volumetric signals, robustly, not by timing
    # regularity alone (see the moderate/light cases below for the
    # timing-only signal's actual reliability).
    assert BehaviorPatternType.REPEATED_CONNECTIONS in assessment.detected_patterns
    assert BehaviorPatternType.HIGH_FREQUENCY in assessment.detected_patterns
    assert BehaviorPatternType.BURST in assessment.detected_patterns


def test_a_moderate_two_technique_scan_is_not_reliably_caught() -> None:
    """~1.2 requests/second for ~15s, +-35% jitter: two techniques, no threading, default timing.

    B6 finding: at this intensity, `TEMPORAL_PATTERN` firing depends on
    exactly how regular this run's jitter happened to land — 1 of 10 seeds
    fired, 9 of 10 did not (see docs/ADDENDUM_2.md B6). This is the honest
    "not reliably caught" case, using a seed from that unfired majority.
    """
    analyzer = BehaviorAnalyzer(DetectionConfig())
    _simulate_probe_sequence(
        analyzer, count=18, mean_interval_seconds=0.85, jitter_fraction=0.35, seed=1
    )

    assessment = analyzer.assess(IPv4Address(_SOURCE))
    assert assessment is not None
    assert assessment.detected_patterns == ()


def test_a_light_single_payload_probe_does_not_trigger_default_thresholds() -> None:
    """~1 request/second for 8 requests, +-45% jitter: a single technique/payload, not a full sweep.

    B6 finding: never detected across 10 different jitter seeds — a light,
    targeted probe is genuinely below every default threshold, timing
    included.
    """
    analyzer = BehaviorAnalyzer(DetectionConfig())
    _simulate_probe_sequence(
        analyzer, count=8, mean_interval_seconds=1.0, jitter_fraction=0.45, seed=0
    )

    assessment = analyzer.assess(IPv4Address(_SOURCE))

    assert assessment is not None
    assert assessment.detected_patterns == ()

"""Export operational metrics to Netdata on the Admin PC (spec §33, ADDENDUM.md A3).

Pushes each field of a `NetdataMetricsSnapshot` as one StatsD gauge metric
(`name:value|g`) — the standard way for a non-web-server process to feed
Netdata's `statsd` collector, which turns each gauge into a chart without
pirewall needing to run its own scrape-able HTTP endpoint. `StatsdNetdataTransport`
requires a real Netdata instance with its StatsD listener enabled on the
Admin PC and is therefore **Environment-dependent** — see
`docs/PROGRESS.md`. `pirewall.integration.fake.FakeNetdataTransport`
exercises `NetdataExporter`'s payload shaping without any real network I/O.
"""

import socket
from typing import Protocol, runtime_checkable

from pirewall.core.exceptions import IntegrationError
from pirewall.core.models.metrics import NetdataMetricsSnapshot

_METRIC_PREFIX = "pirewall"


@runtime_checkable
class NetdataTransport(Protocol):
    """Contract for sending one named gauge metric value to Netdata."""

    def send_metric(self, name: str, value: float) -> None:
        """Deliver one metric. Raises `pirewall.core.exceptions.IntegrationError` on failure."""
        ...


def snapshot_to_metrics(snapshot: NetdataMetricsSnapshot) -> dict[str, float]:
    """Shape a `NetdataMetricsSnapshot` into `{metric_name: value}`, prefixed and flattened.

    Booleans (the three `*_health` fields) become `1.0`/`0.0` since StatsD
    gauges are numeric-only.
    """
    prefix = _METRIC_PREFIX
    return {
        f"{prefix}.cpu_percent": snapshot.cpu_percent,
        f"{prefix}.memory_percent": snapshot.memory_percent,
        f"{prefix}.packet_rate_per_second": snapshot.packet_rate_per_second,
        f"{prefix}.packet_drops": float(snapshot.packet_drops),
        f"{prefix}.active_flows": float(snapshot.active_flows),
        f"{prefix}.flow_creation_rate_per_second": snapshot.flow_creation_rate_per_second,
        f"{prefix}.flow_expiration_rate_per_second": snapshot.flow_expiration_rate_per_second,
        f"{prefix}.inference_count": float(snapshot.inference_count),
        f"{prefix}.inference_latency_ms": snapshot.inference_latency_ms,
        f"{prefix}.detection_count": float(snapshot.detection_count),
        f"{prefix}.block_count": float(snapshot.block_count),
        f"{prefix}.rule_count": float(snapshot.rule_count),
        f"{prefix}.rule_rejection_count": float(snapshot.rule_rejection_count),
        f"{prefix}.api_health": 1.0 if snapshot.api_health else 0.0,
        f"{prefix}.capture_health": 1.0 if snapshot.capture_health else 0.0,
        f"{prefix}.firewall_health": 1.0 if snapshot.firewall_health else 0.0,
        # ADDENDUM.md A3.
        f"{prefix}.adaptive_rule_creation_rate_per_window": float(
            snapshot.adaptive_rule_creation_rate_per_window
        ),
        f"{prefix}.adaptive_rule_budget_fraction": snapshot.adaptive_rule_budget_fraction,
    }


class NetdataExporter:
    """Shapes a `NetdataMetricsSnapshot` into gauges and pushes each through a `NetdataTransport`."""

    def __init__(self, transport: NetdataTransport, *, enabled: bool) -> None:
        self._transport = transport
        self._enabled = enabled

    def export(self, snapshot: NetdataMetricsSnapshot) -> None:
        """Push every metric in `snapshot`. A no-op when `enabled=False`."""
        if not self._enabled:
            return
        for name, value in snapshot_to_metrics(snapshot).items():
            self._transport.send_metric(name, value)


class StatsdNetdataTransport:
    """Real `NetdataTransport`: sends each metric as one StatsD gauge packet over UDP.

    UDP (not TCP) is deliberate and matches StatsD convention: a dropped
    metrics packet must never block or crash pirewall-core's own operation
    (spec §26 "malformed traffic/failures must never crash the entire
    system" applies equally to a metrics-export failure). Requires a real
    Netdata instance with its StatsD collector enabled on the Admin PC —
    **Environment-dependent**, cannot be exercised on a dev machine.
    """

    def __init__(self, host: str, port: int) -> None:
        self._address = (host, port)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_metric(self, name: str, value: float) -> None:
        packet = f"{name}:{value}|g".encode()
        try:
            self._socket.sendto(packet, self._address)
        except OSError as exc:
            raise IntegrationError(
                f"failed to send metric {name!r} to Netdata at {self._address}: {exc}"
            ) from exc

"""`NativeFlowAggregator`: the Rust flow table behind `FlowAggregator`'s interface.

`pirewall_native.FlowEngine` (native/src/flow.rs) is a port of
`pirewall.flow.{state,aggregator,timeout}` that runs per packet without the
GIL. This wrapper turns its plain records into the same domain objects the
Python aggregator produces — `Flow`, `NewFlowSignal`, `SlowConnectionCluster`
— and exposes the same sweep/snapshot/flush methods, so everything
downstream (detection, the sweep loop, the source-level fast path) is
unaware which one is running.

The two are held to field-for-field identical output by
`tests/unit/test_native_parity.py`. That matters beyond tidiness: feature
schema 2.0.0 exists because training and runtime once disagreed about what a
flow statistic meant, and two runtime implementations disagreeing would
reopen exactly that gap.

Optional: when the extension is not built (`uv sync --extra native`, see
docs/ARCHITECTURE.md), `native_engine_available()` is False and the daemon
uses the Python path.
"""

import importlib
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from typing import TYPE_CHECKING
from uuid import uuid4

from pirewall.capture.interfaces import TcpPayload
from pirewall.config.models import FlowConfig
from pirewall.core.enums import Protocol
from pirewall.core.models.flow import Flow
from pirewall.flow.aggregator import NewFlowSignal, SlowConnectionCluster

if TYPE_CHECKING:
    from pirewall_native import (  # pyright: ignore[reportMissingModuleSource]
        FlowEngine,
        FlowRecord,
    )


def _load_engine_class() -> "type[FlowEngine] | None":
    try:
        module = importlib.import_module("pirewall_native")
    except ImportError:  # the extension is optional; see the module docstring
        return None
    # `ModuleType` attributes are `Any` to the type checker; the stub in
    # typings/pirewall_native.pyi pins what this actually is.
    engine_class: type[FlowEngine] = module.FlowEngine
    return engine_class


_ENGINE_CLASS = _load_engine_class()

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_TLS_PORT = 443


def native_engine_available() -> bool:
    """Whether the `pirewall_native` extension is importable here."""
    return _ENGINE_CLASS is not None


def to_microseconds(moment: datetime) -> int:
    """Whole microseconds since the Unix epoch — the engine's clock, and `datetime`'s resolution."""
    delta = moment - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def from_microseconds(microseconds: int) -> datetime:
    """Inverse of `to_microseconds`, exact."""
    return _EPOCH + timedelta(microseconds=microseconds)


def mac_from_int(value: int) -> str:
    """A 48-bit integer (octets big-endian, as the engine reports MACs) as `aa:bb:cc:dd:ee:ff`.

    The same normalised form `pirewall.capture.parser` produces with
    `bytes.hex(":")`; the parity test holds the two to it.
    """
    return value.to_bytes(6, "big").hex(":")


def _flow_from_record(record: "FlowRecord") -> Flow:
    return Flow.model_validate(
        {
            "flow_id": str(uuid4()),
            "source_ip": IPv4Address(record.src),
            "destination_ip": IPv4Address(record.dst),
            "source_port": record.sport,
            "destination_port": record.dport,
            "protocol": Protocol(record.protocol),
            "first_seen": from_microseconds(record.first_seen_us),
            "last_seen": from_microseconds(record.last_seen_us),
            "packet_count": record.packet_count,
            "byte_count": record.byte_count,
            "forward_packet_count": record.forward_packet_count,
            "backward_packet_count": record.backward_packet_count,
            "forward_byte_count": record.forward_byte_count,
            "backward_byte_count": record.backward_byte_count,
            "tcp_flags": {
                "syn": record.syn,
                "ack": record.ack,
                "fin": record.fin,
                "rst": record.rst,
                "psh": record.psh,
                "urg": record.urg,
            },
            "packet_size_stats": {
                "min_bytes": round(record.size_min),
                "max_bytes": round(record.size_max),
                "mean_bytes": record.size_mean,
                "std_bytes": record.size_std,
            },
            "inter_arrival_stats": {
                "min_seconds": record.iat_min,
                "max_seconds": record.iat_max,
                "mean_seconds": record.iat_mean,
                "std_seconds": record.iat_sample_std,
            },
            "opened_by_initiation": record.opened_by_initiation,
            "source_mac": mac_from_int(record.src_mac),
            "destination_mac": mac_from_int(record.dst_mac),
            "payload_stats": {
                "forward_bytes": record.forward_payload_bytes,
                "backward_bytes": record.backward_payload_bytes,
                "min_bytes": round(record.payload_min),
                "max_bytes": round(record.payload_max),
                "mean_bytes": record.payload_mean,
                "std_bytes": record.payload_sample_std,
            },
        }
    )


class NativeBatch:
    """Everything the engine produced since the previous drain, as domain objects.

    Callers must handle them in this order — TLS payloads, then new-flow
    signals, then completed flows — so that a completing flow never reaches
    detection before the evidence and behavioral signals that preceded it on
    the wire (the same guarantee the Python capture loop gives by program
    order; see `CoreDaemon._detection_loop`).
    """

    __slots__ = ("completed", "new_flows", "tls_payloads")

    def __init__(
        self, completed: list[Flow], new_flows: list[NewFlowSignal], tls_payloads: list[TcpPayload]
    ) -> None:
        self.completed = completed
        self.new_flows = new_flows
        self.tls_payloads = tls_payloads


class NativeFlowAggregator:
    """`FlowAggregator`'s interface over the native engine. Thread-safe (the engine locks itself)."""

    def __init__(
        self,
        config: FlowConfig,
        protected_network: IPv4Network | None = None,
        max_pending_completed: int | None = None,
        max_pending_new_flows: int | None = None,
    ) -> None:
        """`max_pending_*` cap what one `drain` can return; the excess is counted (`shed`), not kept."""
        if _ENGINE_CLASS is None:
            raise RuntimeError(
                "pirewall_native is not installed; use pirewall.flow.aggregator.FlowAggregator"
            )
        protected = (
            None
            if protected_network is None
            else (int(protected_network.network_address), protected_network.prefixlen)
        )
        self._engine: FlowEngine = _ENGINE_CLASS(
            float(config.active_timeout_seconds),
            float(config.inactive_timeout_seconds),
            config.max_flows,
            protected,
            _TLS_PORT,
            max_pending_completed,
            max_pending_new_flows,
        )

    @property
    def engine(self) -> "FlowEngine":
        """The underlying handle, for a native capture to feed directly."""
        return self._engine

    def __len__(self) -> int:
        return len(self._engine)

    def feed(self, raw: bytes, captured_at: datetime) -> None:
        """Parse and aggregate one frame (replay and tests; live capture feeds from Rust)."""
        self._engine.feed(raw, to_microseconds(captured_at))

    def drain(self) -> NativeBatch:
        """Take every completed flow, new-flow signal and TLS candidate produced so far."""
        completed, new_flows, tls = self._engine.drain()
        return NativeBatch(
            completed=[_flow_from_record(record) for record in completed],
            new_flows=[
                NewFlowSignal(
                    source_ip=IPv4Address(signal.src),
                    destination_ip=IPv4Address(signal.dst),
                    destination_port=signal.dport,
                    protocol=Protocol(signal.protocol),
                    timestamp=from_microseconds(signal.ts_us),
                    source_mac=mac_from_int(signal.src_mac),
                    destination_mac=mac_from_int(signal.dst_mac),
                )
                for signal in new_flows
            ],
            tls_payloads=[
                TcpPayload(
                    source_ip=IPv4Address(candidate.src),
                    destination_ip=IPv4Address(candidate.dst),
                    source_port=candidate.sport,
                    destination_port=candidate.dport,
                    timestamp=from_microseconds(candidate.ts_us),
                    payload=candidate.payload,
                )
                for candidate in tls
            ],
        )

    def counters(self) -> tuple[int, int]:
        """`(packets seen, packets malformed or unsupported)`, cumulative."""
        return self._engine.counters()

    def shed(self) -> tuple[int, int]:
        """`(completed flows, new-flow signals)` discarded by the per-drain caps, cumulative."""
        return self._engine.shed()

    def sweep_timeouts(self, now: datetime) -> list[Flow]:
        """Same contract as `FlowAggregator.sweep_timeouts`."""
        return [_flow_from_record(record) for record in self._engine.sweep(to_microseconds(now))]

    def snapshot_slow_connection_clusters(
        self,
        now: datetime,
        min_duration_seconds: float,
        max_bytes_per_second: float,
        concurrent_threshold: int,
    ) -> list[SlowConnectionCluster]:
        """Same contract as `FlowAggregator.snapshot_slow_connection_clusters`."""
        return [
            SlowConnectionCluster(
                source_ip=IPv4Address(source),
                destination_ip=IPv4Address(destination),
                concurrent_count=count,
                representative_flow=_flow_from_record(record),
            )
            for source, destination, count, record in self._engine.slow_clusters(
                to_microseconds(now), min_duration_seconds, max_bytes_per_second, concurrent_threshold
            )
        ]

    def snapshot_open_flow_from(self, source_ip: IPv4Address) -> Flow | None:
        """Same contract as `FlowAggregator.snapshot_open_flow_from`."""
        record = self._engine.snapshot_open_flow_from(int(source_ip))
        return None if record is None else _flow_from_record(record)

    def flush(self) -> list[Flow]:
        """Same contract as `FlowAggregator.flush`."""
        return [_flow_from_record(record) for record in self._engine.flush()]

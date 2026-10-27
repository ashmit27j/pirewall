"""Type stub for the optional `pirewall_native` extension (native/src/lib.rs).

Lives in pyright's default `typings/` stub path so callers type-check
whether or not the extension is built on this machine; every import of it
is guarded at runtime (`pirewall.flow.native`, `pirewall.capture.native`).
"""

from typing import final

HAS_PACKET_RING: bool

@final
class FlowRecord:
    src: int
    dst: int
    sport: int | None
    dport: int | None
    protocol: str
    first_seen_us: int
    last_seen_us: int
    packet_count: int
    byte_count: int
    forward_packet_count: int
    backward_packet_count: int
    forward_byte_count: int
    backward_byte_count: int
    forward_payload_bytes: int
    backward_payload_bytes: int
    syn: int
    ack: int
    fin: int
    rst: int
    psh: int
    urg: int
    size_min: float
    size_max: float
    size_mean: float
    size_std: float
    payload_min: float
    payload_max: float
    payload_mean: float
    payload_sample_std: float
    iat_min: float
    iat_max: float
    iat_mean: float
    iat_sample_std: float
    opened_by_initiation: bool

@final
class NewFlowRecord:
    src: int
    dst: int
    dport: int | None
    protocol: str
    ts_us: int

@final
class TlsRecord:
    src: int
    dst: int
    sport: int | None
    dport: int | None
    ts_us: int
    payload: bytes

@final
class FlowEngine:
    def __init__(
        self,
        active_timeout_seconds: float,
        inactive_timeout_seconds: float,
        max_flows: int,
        protected_network: tuple[int, int] | None = None,
        tls_port: int = 443,
        max_pending_completed: int | None = None,
        max_pending_new_flows: int | None = None,
    ) -> None: ...
    def feed(self, frame: bytes, ts_us: int) -> None: ...
    def drain(self) -> tuple[list[FlowRecord], list[NewFlowRecord], list[TlsRecord]]: ...
    def sweep(self, now_us: int) -> list[FlowRecord]: ...
    def slow_clusters(
        self,
        now_us: int,
        min_duration_seconds: float,
        max_bytes_per_second: float,
        concurrent_threshold: int,
    ) -> list[tuple[int, int, int, FlowRecord]]: ...
    def snapshot_open_flow_from(self, src: int) -> FlowRecord | None: ...
    def flush(self) -> list[FlowRecord]: ...
    def counters(self) -> tuple[int, int]: ...
    def shed(self) -> tuple[int, int]: ...
    def __len__(self) -> int: ...

@final
class PacketRing:
    def __init__(
        self,
        interface: str,
        promiscuous: bool,
        block_size: int,
        block_count: int,
        block_timeout_ms: int,
    ) -> None: ...
    @property
    def interface(self) -> str: ...
    def poll(self, engine: FlowEngine, timeout_ms: int, max_packets: int) -> int: ...
    def kernel_drops(self) -> int: ...
    def close(self) -> None: ...

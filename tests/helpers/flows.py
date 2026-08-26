"""Factories for building `PacketMetadata`/`Flow` test fixtures without repetition."""

from datetime import UTC, datetime, timedelta

from pirewall.core.enums import AddressFamily, Protocol
from pirewall.core.models.common import TcpFlags
from pirewall.core.models.flow import Flow
from pirewall.core.models.packet import PacketMetadata

DEFAULT_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def make_packet(
    *,
    source_ip: str = "10.0.0.5",
    destination_ip: str = "10.0.0.10",
    source_port: int | None = 51234,
    destination_port: int | None = 443,
    protocol: Protocol = Protocol.TCP,
    timestamp: datetime = DEFAULT_TIME,
    total_length: int = 100,
    payload_length: int = 0,
    tcp_flags: TcpFlags | None = None,
    address_family: AddressFamily = AddressFamily.IPV4,
) -> PacketMetadata:
    return PacketMetadata.model_validate(
        {
            "timestamp": timestamp,
            "address_family": address_family,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "tcp_flags": tcp_flags,
            "total_length": total_length,
            "payload_length": payload_length,
        }
    )


def make_flow(
    *,
    flow_id: str = "flow-1",
    source_ip: str = "10.0.0.5",
    destination_ip: str = "10.0.0.10",
    source_port: int | None = 51234,
    destination_port: int | None = 443,
    protocol: Protocol = Protocol.TCP,
    first_seen: datetime = DEFAULT_TIME,
    duration_seconds: float = 10.0,
    packet_count: int = 10,
    byte_count: int = 1000,
    forward_packet_count: int = 6,
    backward_packet_count: int = 4,
    forward_byte_count: int = 600,
    backward_byte_count: int = 400,
    tcp_flags: dict[str, int] | None = None,
) -> Flow:
    return Flow.model_validate(
        {
            "flow_id": flow_id,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "first_seen": first_seen,
            "last_seen": first_seen + timedelta(seconds=duration_seconds),
            "packet_count": packet_count,
            "byte_count": byte_count,
            "forward_packet_count": forward_packet_count,
            "backward_packet_count": backward_packet_count,
            "forward_byte_count": forward_byte_count,
            "backward_byte_count": backward_byte_count,
            "tcp_flags": tcp_flags or {},
            "packet_size_stats": {
                "min_bytes": 40,
                "max_bytes": 1500,
                "mean_bytes": 100.0,
                "std_bytes": 20.0,
            },
            "inter_arrival_stats": {
                "min_seconds": 0.001,
                "max_seconds": 1.0,
                "mean_seconds": 0.1,
                "std_seconds": 0.05,
            },
        }
    )

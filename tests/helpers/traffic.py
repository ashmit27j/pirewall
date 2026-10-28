"""A deterministic, mixed Ethernet frame stream with capture timestamps, for replay tests.

Sessions, scans from a spoofing MAC, DNS, ICMP, broadcasts, IPv6, ARP,
truncated frames and long quiet gaps (so inactivity and active timeouts and
the sweep cadence all matter), stamped in whole microseconds.
"""

import random

from tests.helpers.packets import eth, ipv4_header, ipv6_header, mac_bytes, tcp_header, udp_header

T0_US = 1_772_366_400_000_000  # 2026-03-01 12:00:00 UTC
ATTACKER_MAC = "02:00:00:00:00:ee"
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def mac_of(address: str) -> bytes:
    """A distinct locally administered MAC per IPv4 address."""
    return b"\x02\x00" + bytes(int(part) for part in address.split("."))


def tcp(
    src: str, dst: str, sport: int, dport: int, flags: int, payload: bytes = b"", src_mac: bytes | None = None
) -> bytes:
    ip = ipv4_header(6, total_length=40 + len(payload), src=src, dst=dst)
    frame = eth(0x0800, src_mac=src_mac or mac_of(src), dst_mac=mac_of(dst))
    return frame + ip + tcp_header(sport, dport, flags=flags) + payload


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes = b"") -> bytes:
    ip = ipv4_header(17, total_length=28 + len(payload), src=src, dst=dst)
    return (
        eth(0x0800, src_mac=mac_of(src), dst_mac=mac_of(dst))
        + ip
        + udp_header(sport, dport, 8 + len(payload))
        + payload
    )


def mixed_stream(seed: int, sessions: int = 400) -> list[tuple[bytes, int]]:
    """`(frame, ts_us)` pairs, timestamps non-decreasing apart from rare small reorderings."""
    rng = random.Random(seed)
    lan = [f"192.168.100.{i}" for i in range(2, 20)]
    wan = [f"203.0.113.{i}" for i in range(1, 30)]
    clock = T0_US
    out: list[tuple[bytes, int]] = []

    def emit(frame: bytes, late: bool = False) -> None:
        nonlocal clock
        clock += rng.randint(0, 300_000)
        out.append((frame, clock - rng.randint(1, 4_000) if late else clock))

    for _ in range(sessions):
        kind = rng.random()
        client, server = rng.choice(lan), rng.choice(wan)
        sport, dport = rng.randint(1024, 65535), rng.choice([80, 443, 22, 8080])
        if kind < 0.4:
            emit(tcp(client, server, sport, dport, SYN))
            emit(tcp(server, client, dport, sport, SYN | ACK))
            for _ in range(rng.randint(0, 5)):
                body = bytes(rng.choice([0, 1, 100, 1448]))
                if rng.random() < 0.5:
                    emit(tcp(client, server, sport, dport, ACK | PSH, body), late=rng.random() < 0.1)
                else:
                    emit(tcp(server, client, dport, sport, ACK | PSH, body))
            if rng.random() < 0.8:
                emit(tcp(client, server, sport, dport, FIN | ACK))
                emit(tcp(server, client, dport, sport, FIN | ACK))
        elif kind < 0.5:
            spoofer = mac_bytes(ATTACKER_MAC) if rng.random() < 0.5 else None
            for port in range(rng.randint(2, 12)):
                emit(tcp(client, server, sport, 1 + port, SYN, src_mac=spoofer))
            emit(tcp(server, client, 1, sport, RST))
        elif kind < 0.7:
            emit(udp(client, server, sport, 53, bytes(rng.randint(0, 80))))
            emit(udp(server, client, 53, sport, bytes(rng.randint(0, 200))))
        elif kind < 0.76:
            emit(
                eth(0x0800, src_mac=mac_of(client), dst_mac=mac_of(server))
                + ipv4_header(1, total_length=28, src=client, dst=server)
                + bytes(8)
            )
        elif kind < 0.8:
            emit(udp(client, "192.168.100.255", 137, 137))
        elif kind < 0.84:
            emit(eth(0x86DD) + ipv6_header(17, 8) + udp_header(1, 2, 8))
        elif kind < 0.88:
            emit(eth(0x0806) + bytes(28))
        elif kind < 0.93:
            frame = tcp(client, server, sport, dport, ACK, bytes(20))
            emit(frame[: rng.randint(0, len(frame) - 1)])
        else:
            clock += rng.choice([31, 61, 125]) * 1_000_000
    return out

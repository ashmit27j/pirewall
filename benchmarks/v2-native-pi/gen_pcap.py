"""Write the synthetic capture `run.sh` replays onto a veth: a SYN flood or a UDP flood.

    uv run python benchmarks/v2-native-pi/gen_pcap.py --kind syn --frames 200000 --out /tmp/syn.pcap

Deterministic (fixed seed), stdlib only through `pirewall.capture.pcapio`.
Destination is 10.99.0.1 (the capture side of `run.sh`'s veth pair); each
frame has a distinct source port, so every frame opens a flow: the worst
case for the flow table, as in the 2026-10-15 benchmark's hping3 floods.
"""

import argparse
import random
import struct
from ipaddress import IPv4Address
from pathlib import Path

from pirewall.capture.pcapio import PcapWriter

_DST = IPv4Address("10.99.0.1")
_SRC = IPv4Address("10.99.0.2")
_DST_MAC = b"\x02\x00\x0a\x63\x00\x01"
_SRC_MAC = b"\x02\x00\x0a\x63\x00\x02"
_T0_US = 1_800_000_000_000_000


def _frame(kind: str, sport: int, rng: random.Random) -> bytes:
    if kind == "syn":
        l4 = struct.pack("!HHIIBBHHH", sport, 80, rng.getrandbits(32), 0, 5 << 4, 0x02, 64240, 0, 0)
        protocol = 6
    else:
        payload = bytes(rng.randint(0, 64))
        l4 = struct.pack("!HHHH", sport, 53, 8 + len(payload), 0) + payload
        protocol = 17
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(l4), 0, 0, 64, protocol, 0) + _SRC.packed + _DST.packed
    return _DST_MAC + _SRC_MAC + b"\x08\x00" + ip + l4


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("syn", "udp"), required=True)
    parser.add_argument("--frames", type=int, default=200_000)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rng = random.Random(15)
    with PcapWriter(args.out) as writer:
        for index in range(args.frames):
            writer.write(_frame(args.kind, 1024 + index % 64_000, rng), _T0_US + index * 10)


if __name__ == "__main__":
    main()

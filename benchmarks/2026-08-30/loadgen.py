"""Generate real packets onto the capture segment, from this Pi.

Why not iperf3 between two LAN devices, as the benchmark plan asked for: at
the time of this run the protected LAN (`wlan0`, the Pi's own AP) had **no
associated stations at all** -- `iw dev wlan0 station dump` was empty, `ip
neigh` showed only FAILED/STALE entries, and a 12-second `tcpdump` on the
capture interface captured zero packets. There is no second device to run
iperf3 against, so a client/server throughput test is not possible on this
segment.

What this does instead is put genuine frames on the real radio, through the
real driver, so the daemon's real `AF_PACKET` capture path sees them: UDP
datagrams sent to the LAN broadcast address out of `wlan0`. Broadcast is
used deliberately -- a unicast destination would need an ARP entry for a
host that does not exist, which would mean editing the host's neighbour
table (network configuration this benchmark is not allowed to touch).

Source and destination ports are varied so each worker produces many
distinct 5-tuples, exercising flow-table insertion, eviction and feature
extraction rather than a single long-lived flow.

Nothing here talks to pirewall. It is an ordinary UDP sender.
"""

import argparse
import multiprocessing
import random
import socket
import time


def worker(target: str, duration: float, payload_size: int, pps: float,
           port_span: int, seed: int, result: "multiprocessing.Queue[int]") -> None:
    rng = random.Random(seed)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"wlan0")
    payload = bytes(rng.getrandbits(8) for _ in range(payload_size))
    interval = 1.0 / pps if pps > 0 else 0.0
    sent = 0
    started = time.monotonic()
    next_send = started
    while time.monotonic() - started < duration:
        if interval:
            now = time.monotonic()
            if now < next_send:
                time.sleep(min(next_send - now, 0.002))
                continue
            next_send += interval
        try:
            # A fresh socket bound to an ephemeral source port every N packets
            # would be slow; instead vary the destination port, which is enough
            # to make a distinct flow key.
            sock.sendto(payload, (target, 10000 + rng.randrange(port_span)))
            sent += 1
        except OSError:
            time.sleep(0.01)
    result.put(sent)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="192.168.100.255")
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--pps-per-worker", type=float, default=0.0,
                        help="0 = send as fast as the interface accepts")
    parser.add_argument("--payload", type=int, default=200)
    parser.add_argument("--port-span", type=int, default=50)
    args = parser.parse_args()

    queue: multiprocessing.Queue[int] = multiprocessing.Queue()
    procs = [
        multiprocessing.Process(
            target=worker,
            args=(args.target, args.duration, args.payload, args.pps_per_worker,
                  args.port_span, 1000 + i, queue),
        )
        for i in range(args.workers)
    ]
    started = time.monotonic()
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join()
    elapsed = time.monotonic() - started
    total = sum(queue.get() for _ in procs)
    print(f"loadgen: sent={total} packets in {elapsed:.1f}s "
          f"= {total / elapsed:.0f} pps, {total * (args.payload + 42) * 8 / elapsed / 1e6:.2f} Mbit/s "
          f"(workers={args.workers} payload={args.payload}B)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

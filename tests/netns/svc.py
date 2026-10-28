"""Tiny test services for the netns testbed (ported from docs/v2/v2/svc.py).

    svc.py udp-echo HOST PORT COUNTFILE   reply to every datagram; keep the receive count in COUNTFILE
    svc.py tcp-listen HOST PORT COUNTFILE accept and close connections; count accepts

Run with the system python inside a namespace (`ip netns exec`); it imports
nothing from pirewall.
"""

import contextlib
import socket
import sys
import threading
import time


def _write_count(path: str, holder: list[int]) -> None:
    while True:
        with open(path, "w", encoding="ascii") as handle:
            handle.write(str(holder[0]))
        time.sleep(0.2)


def main() -> None:
    """Entry point: `svc.py MODE HOST PORT COUNTFILE`."""
    mode, host, port, countfile = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    count = [0]
    threading.Thread(target=_write_count, args=(countfile, count), daemon=True).start()
    if mode == "udp-echo":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        sock.bind((host, port))
        while True:
            data, peer = sock.recvfrom(65535)
            count[0] += 1
            with contextlib.suppress(OSError):
                sock.sendto(data[:64] or b"x", peer)
    elif mode == "tcp-listen":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(4096)
        while True:
            conn, _ = sock.accept()
            count[0] += 1
            conn.close()
    else:
        raise SystemExit(f"unknown mode {mode}")


if __name__ == "__main__":
    main()

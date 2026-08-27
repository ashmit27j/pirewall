"""Shared wire framing for the RPC transport: one JSON message per connection.

Both `pirewall.ipc.server` and `pirewall.ipc.client` use one-shot
connections (connect, send the full request, half-close, read the full
response) rather than a persistent multi-message stream — simple, and
sufficient for the control panel's request volume.
"""

import socket

_READ_CHUNK_SIZE = 65536


def read_all(sock: socket.socket) -> bytes:
    """Read from `sock` until the peer closes its write side."""
    chunks: list[bytes] = []
    while True:
        chunk = sock.recv(_READ_CHUNK_SIZE)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)

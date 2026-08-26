# Phase 2 — Packet capture & packet parsing

Read `CLAUDE.md` and `docs/MASTER_SPEC.md` sections 6, 7 before starting.
Also read `docs/ADDENDUM.md` item **A5** (IPv4-only v1 scope) — it affects
this phase narrowly: parse both IPv4 and IPv6 (it's cheap and spec §7 lists
both), but tag `PacketMetadata` with its address family so Phase 3 can
correctly exclude IPv6 from the adaptive pipeline later. Confirm Phase 1 is
marked complete in `docs/PROGRESS.md`; if it isn't, stop and report that
instead of proceeding.

## Goal

Get raw traffic off the wire and into typed, validated packet metadata —
without ever crashing on malformed input and without payload inspection.

## Deliverables

1. **`pirewall/capture/interfaces.py`** — a `PacketCapture` `Protocol`
   (or ABC) defining: bind to a configured interface, start/stop capture,
   yield packet metadata (raw bytes + timestamp, or a thin wrapper), expose
   capture statistics (packets seen, packets dropped, malformed count),
   graceful shutdown. No implementation here — contract only.

2. **`pirewall/capture/af_packet.py`** — the real implementation using
   Linux `AF_PACKET`/libpcap-style capture (per spec §6: not eBPF/BCC/Scapy
   as the capture foundation). Binds to the interface named in config. Must
   not retain raw packet bytes longer than needed to parse them. Detects and
   counts drops where the OS/socket exposes that information.

3. **`FakePacketCapture`** (same module or `pirewall/capture/fake.py`) — a
   test double implementing the same `Protocol` that yields packets from an
   in-memory list/generator supplied by tests, so all downstream logic (and
   later phases) can be tested without root privileges or a real NIC.

4. **`pirewall/capture/parser.py`** — parses Ethernet → IPv4/IPv6 → TCP/UDP/
   ICMP/ICMPv6 into a typed `PacketMetadata` model (add this model to
   `pirewall/core/models/` if it doesn't already fit an existing one — keep
   it in the core models package, not local to `capture/`). Include for TCP:
   source port, destination port, and the SYN/ACK/FIN/RST/PSH/URG flags.
   Explicitly do **not** parse or inspect application payload — stop at L3/L4
   headers per spec §7.

5. **Malformed/truncated packet handling** — the parser must never raise an
   uncaught exception on garbage input; it raises `PacketParseError` (from
   Phase 1's exception hierarchy) or returns a typed "unparseable" result,
   and the capture loop must catch this, count it, log it, and continue.

## Explicit non-goals for this phase

No flow aggregation, no feature extraction. `PacketMetadata` is the last
thing this phase produces.

## Tests (`tests/unit/` and `tests/security/`)

- Parser: hand-built byte sequences for valid Ethernet/IPv4/IPv6/TCP/UDP/ICMP
  packets parse to the expected `PacketMetadata`.
- Parser: truncated packets (cut off mid-header at several points), packets
  with invalid header lengths, and unsupported ethertypes/protocols all
  produce a handled error/typed result — never an uncaught exception, never a
  crash of the capture loop (`tests/security/`).
- `FakePacketCapture`-driven test proving the capture→parse pipeline runs
  end-to-end on a scripted sequence of good and bad packets, with drop/
  malformed counters incrementing correctly.
- Capture statistics are queryable and accurate after a run.

## Definition of done

Everything in `CLAUDE.md` → "Definition of done for a phase". Update
`docs/PROGRESS.md` row for Phase 2. Note in `docs/PROGRESS.md` that
`af_packet.py` is **Environment-dependent** (needs real interface/root to
fully exercise) versus **Tested** (via `FakePacketCapture`) — be explicit
about which parts of this phase got which label.

"""Connection starts: the unit D1 counts (docs/V2_CONTRACTS.md "Connection start").

Frozen by phase 11, implemented by phase 15:
`scripts/dataset/pcap_to_flows.py` writes a `connection_start` column, and
phase 17's D1 detectors import the *same* class. One definition, two
callers, the CLAUDE.md "one canonical module" rule: if training-time and
runtime counted connection starts differently, thresholds learned from
benign pcaps would not mean the same thing live.

**Definition.** A flow record is a connection start when both hold:

1. its initiator sent a SYN: the record is TCP and its opening packet was a
   SYN without ACK/RST (`Flow.opened_by_initiation`, native
   `FlowState.initiated`); and
2. no earlier record for the same 5-tuple (source IP, destination IP,
   source port, destination port, protocol) has been observed.

A long connection split by the active timeout yields one start, not one
per record. UDP and ICMP records are never connection starts; floods of
those are the kernel meters' job.

"Earlier" is bounded: the tracker remembers at most `max_tracked` 5-tuples
(least recently seen evicted first). An evicted tuple seen again counts as
a new start. That errs toward over-counting, which is visible in the
eviction counter rather than silent.
"""

from collections import OrderedDict
from ipaddress import IPv4Address

from pirewall.core.enums import Protocol
from pirewall.core.models.flow import Flow

# (source IP, destination IP, source port, destination port); the protocol is always TCP.
type _FiveTuple = tuple[IPv4Address, IPv4Address, int | None, int | None]


class ConnectionStartTracker:
    """Decides, in record order, whether each flow record is a connection start.

    Not thread-safe: one tracker belongs to one record stream.
    """

    def __init__(self, max_tracked: int) -> None:
        """Track at most `max_tracked` 5-tuples (`flow.connection_start_max_tracked`)."""
        if max_tracked <= 0:
            raise ValueError("max_tracked must be positive")
        self._max_tracked = max_tracked
        self._seen: OrderedDict[_FiveTuple, None] = OrderedDict()
        self._evictions = 0

    def observe(self, flow: Flow) -> bool:
        """Record `flow` and return True if it is a connection start (see module docstring).

        Only TCP records are tracked: the 5-tuple includes the protocol, so a
        UDP or ICMP record could never make a TCP record "not first", and it
        can never be a start itself. Every TCP record is remembered, whether
        or not it opened with a SYN, so a later SYN on a tuple already seen
        (a retransmission after a timeout split) is not a new start.
        """
        if flow.protocol is not Protocol.TCP:
            return False
        key: _FiveTuple = (flow.source_ip, flow.destination_ip, flow.source_port, flow.destination_port)
        first = key not in self._seen
        if first:
            self._seen[key] = None
            if len(self._seen) > self._max_tracked:
                self._seen.popitem(last=False)
                self._evictions += 1
        else:
            self._seen.move_to_end(key)
        return first and flow.opened_by_initiation

    @property
    def evictions(self) -> int:
        """5-tuples forgotten to stay within `max_tracked` since construction."""
        return self._evictions

    def __len__(self) -> int:
        """5-tuples currently remembered."""
        return len(self._seen)

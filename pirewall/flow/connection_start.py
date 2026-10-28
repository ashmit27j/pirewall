"""Connection starts: the unit D1 counts (docs/V2_CONTRACTS.md "Connection start").

Contract stub frozen by phase 11. Phase 15 implements it, because
`scripts/dataset/pcap_to_flows.py` writes a `connection_start` column;
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

from pirewall.core.models.flow import Flow


class ConnectionStartTracker:
    """Decides, in record order, whether each flow record is a connection start."""

    def __init__(self, max_tracked: int) -> None:
        """Track at most `max_tracked` 5-tuples. Phase 15 takes the bound from config."""
        if max_tracked <= 0:
            raise ValueError("max_tracked must be positive")
        self._max_tracked = max_tracked

    def observe(self, flow: Flow) -> bool:
        """Record `flow` and return True if it is a connection start (see module docstring)."""
        raise NotImplementedError("phase 15 implements connection-start tracking")

    @property
    def evictions(self) -> int:
        """5-tuples forgotten to stay within `max_tracked` since construction."""
        raise NotImplementedError("phase 15 implements connection-start tracking")

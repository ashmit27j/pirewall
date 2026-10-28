"""Names of every v2 nftables object, copied exactly from the reviewed templates (ADDENDUM_4.md D1).

The source of truth is `deploy/firewall/pirewall_static.nft.template` and
`deploy/firewall/pirewall_adaptive.nft.template`, ported by phase 13 from
the sandbox-tested copies in `docs/v2/v2/`. `tests/unit/test_v2_contracts.py`
parses the deployed templates as text and fails if a name here drifts from
them, so code never spells a set or chain name inline.

This lives in `pirewall.core`, not `pirewall.firewall`, because two layers
need it: the firewall backend writes these objects, and the phase-17 kernel
poller (`pirewall.detection_v2`) reads `offenders` and the drop counters.
Detection importing from the firewall package would point the dependency
arrow backwards (CLAUDE.md "No circular imports").

Pure data: no I/O, no nft calls.
"""

from collections.abc import Mapping
from enum import IntEnum
from types import MappingProxyType
from typing import Final

from pirewall.core.enums import GuardName

# --- tables -------------------------------------------------------------------

STATIC_TABLE: Final = "pirewall_static"
"""`table inet pirewall_static`: reviewed static guards. Template-only except the guard verdicts (D1)."""
ADAPTIVE_TABLE: Final = "pirewall_adaptive"
"""`table inet pirewall_adaptive`: adaptive sets, written only by `FirewallManager` (D1)."""
STATIC_ARP_TABLE: Final = "pirewall_static_arp"
"""`table arp pirewall_static_arp`: ARP anti-impersonation, the static table's companion (D3)."""

INET_FAMILY: Final = "inet"
ARP_FAMILY: Final = "arp"

BASE_TABLE: Final = "pirewall_base"
"""v1 static posture. v2 code never writes it; panic leaves it in place (D5)."""
PORTAL_TABLE: Final = "pirewall_portal"
"""Captive portal gate (ADDENDUM_3.md C2). v2 code outside the portal path never writes it."""

PANIC_TABLES: Final[tuple[tuple[str, str], ...]] = (
    (INET_FAMILY, ADAPTIVE_TABLE),
    (INET_FAMILY, STATIC_TABLE),
    (ARP_FAMILY, STATIC_ARP_TABLE),
)
"""(family, table) pairs panic deletes, in this order (ADDENDUM_4.md D5). Nothing else is ever deleted."""

# --- pirewall_static chains -------------------------------------------------------

CHAIN_PREROUTING_FRAG: Final = "prerouting_frag"
CHAIN_PREROUTING_RAW: Final = "prerouting_raw"
CHAIN_INPUT_GUARD: Final = "input_guard"
CHAIN_FORWARD_GUARD: Final = "forward_guard"
CHAIN_DHCP_GATE: Final = "dhcp_gate"
CHAIN_UNBOUND: Final = "unbound"
CHAIN_FLOOD_METERS: Final = "flood_meters"
CHAIN_GUARD_VERDICT_RAW: Final = "guard_verdict_raw"
CHAIN_GUARD_VERDICT_INPUT: Final = "guard_verdict_input"
CHAIN_GUARD_VERDICT_FORWARD: Final = "guard_verdict_forward"

STATIC_CHAINS: Final = frozenset(
    {
        CHAIN_PREROUTING_FRAG,
        CHAIN_PREROUTING_RAW,
        CHAIN_INPUT_GUARD,
        CHAIN_FORWARD_GUARD,
        CHAIN_DHCP_GATE,
        CHAIN_UNBOUND,
        CHAIN_FLOOD_METERS,
        CHAIN_GUARD_VERDICT_RAW,
        CHAIN_GUARD_VERDICT_INPUT,
        CHAIN_GUARD_VERDICT_FORWARD,
    }
)

GUARD_VERDICT_CHAINS: Final[Mapping[GuardName, str]] = MappingProxyType(
    {
        GuardName.RAW: CHAIN_GUARD_VERDICT_RAW,
        GuardName.INPUT: CHAIN_GUARD_VERDICT_INPUT,
        GuardName.FORWARD: CHAIN_GUARD_VERDICT_FORWARD,
    }
)
"""The only chains in `pirewall_static` whose contents core may replace, via `set_guard_mode` (D1)."""

# --- pirewall_static sets -----------------------------------------------------------

SET_BOUND4: Final = "bound4"
SET_MACBIND: Final = "macbind"
SET_ALLOW_BOUND: Final = "allow_bound"
SET_DHCP_METER: Final = "dhcp_meter"
SET_UNBOUND_METER: Final = "unbound_meter"
SET_SYN_METER: Final = "syn_meter"
SET_UDP_METER: Final = "udp_meter"
SET_ICMP_METER: Final = "icmp_meter"
SET_PPS_METER: Final = "pps_meter"
SET_DNS_METER: Final = "dns_meter"
SET_CLOSED_METER: Final = "closed_meter"
SET_PORTAL_CONC: Final = "portal_conc"
SET_NEWCONN_METER: Final = "newconn_meter"
SET_NEWCONN_DST_METER: Final = "newconn_dst_meter"
SET_UDP_FWD_METER: Final = "udp_fwd_meter"
SET_OFFENDERS: Final = "offenders"
SET_UNBOUND_SEEN: Final = "unbound_seen"

STATIC_BINDING_SETS: Final = frozenset({SET_BOUND4, SET_MACBIND})
"""Written only by `FirewallManager.sync_bindings` (phase 14), in `pirewall_static` and the arp table."""

STATIC_METER_SETS: Final = frozenset(
    {
        SET_DHCP_METER,
        SET_UNBOUND_METER,
        SET_SYN_METER,
        SET_UDP_METER,
        SET_ICMP_METER,
        SET_PPS_METER,
        SET_DNS_METER,
        SET_CLOSED_METER,
        SET_PORTAL_CONC,
        SET_NEWCONN_METER,
        SET_NEWCONN_DST_METER,
        SET_UDP_FWD_METER,
    }
)
"""Kernel-maintained token buckets. Every active source has an element; membership is NOT evidence."""

STATIC_SETS: Final = (
    STATIC_BINDING_SETS | STATIC_METER_SETS | {SET_ALLOW_BOUND, SET_OFFENDERS, SET_UNBOUND_SEEN}
)

EVIDENCE_SET: Final = SET_OFFENDERS
"""The one kernel set whose membership is evidence (`ether_addr . inet_service` = MAC . offender code)."""

# --- pirewall_static counters (read by the phase-17 kernel poller) ----------------------

STATIC_COUNTERS: Final = frozenset(
    {
        "c_ipv6",
        "c_frag",
        "c_bogon",
        "c_rpf",
        "c_spoof",
        "c_bk_syn",
        "c_bk_udp",
        "c_bk_icmp",
        "c_bk_unbound",
        "c_bk_newconn",
        "c_dns_bypass",
        "c_verdict_raw",
        "c_verdict_input",
        "c_verdict_forward",
    }
)

GUARD_VERDICT_COUNTERS: Final[Mapping[GuardName, str]] = MappingProxyType(
    {
        GuardName.RAW: "c_verdict_raw",
        GuardName.INPUT: "c_verdict_input",
        GuardName.FORWARD: "c_verdict_forward",
    }
)
"""Per-guard meter-hit counters. They count in both modes; in ENFORCE every hit is also a drop."""

# --- pirewall_static_arp ----------------------------------------------------------------

CHAIN_ARP_INPUT: Final = "input"
ARP_CHAINS: Final = frozenset({CHAIN_ARP_INPUT})
ARP_SETS: Final = frozenset({SET_BOUND4, SET_MACBIND})
ARP_COUNTERS: Final = frozenset({"c_arp_spoof"})

# --- pirewall_adaptive --------------------------------------------------------------

CHAIN_PREROUTING_ADAPTIVE: Final = "prerouting_adaptive"
ADAPTIVE_CHAINS: Final = frozenset({CHAIN_PREROUTING_ADAPTIVE})

SET_INFRA4: Final = "infra4"
SET_BLOCK_MAC: Final = "block_mac"
SET_BLOCK4: Final = "block4"
SET_RATELIMIT_MAC: Final = "ratelimit_mac"
SET_RL_METER: Final = "rl_meter"
# Added by phase 13: the IP-keyed rate limit for targets with no resolved MAC
# (phase-13 prompt; until phase 14 every target is IP-only).
SET_RATELIMIT4: Final = "ratelimit4"
SET_RL4_METER: Final = "rl4_meter"

ADAPTIVE_ENFORCEMENT_SETS: Final = frozenset({SET_BLOCK_MAC, SET_BLOCK4, SET_RATELIMIT_MAC, SET_RATELIMIT4})
"""Written only by `FirewallManager` after the validator chain. The kill switch flushes exactly these (D5)."""

ADAPTIVE_BLOCK_SETS: Final = frozenset({SET_BLOCK_MAC, SET_BLOCK4})
"""The enforcement sets that cut a device off (block-over-ratelimit precedence, D4)."""

ADAPTIVE_SETS: Final = ADAPTIVE_ENFORCEMENT_SETS | {SET_INFRA4, SET_ALLOW_BOUND, SET_RL_METER, SET_RL4_METER}

ADAPTIVE_COUNTERS: Final = frozenset({"c_block_mac", "c_block4", "c_ratelimit", "c_ratelimit4"})


# --- offender codes -------------------------------------------------------------------


class OffenderCode(IntEnum):
    """The `inet_service` half of an `@offenders` element: which meter a MAC exceeded.

    Integers are fixed by the template's `update @offenders { ether saddr . N }`
    rules; names follow the template header comment. Not a port number, even
    where the value happens to match one (53, 67, 8080).
    """

    SYN_PPS = 1
    """SYN packets/s, all destinations."""
    UDP_LOCAL_PPS = 2
    """UDP packets/s to the Pi itself."""
    ICMP_PPS = 3
    """ICMP packets/s, all destinations."""
    LOCAL_PPS = 4
    """Total packets/s to the Pi itself."""
    CLOSED_PORT = 5
    """New connections to ports the Pi does not offer to the LAN (scan of the Pi)."""
    NEWCONN = 6
    """Forwarded new connections/s."""
    NEWCONN_DST = 7
    """Forwarded new connections/s per (MAC, destination)."""
    UDP_FWD = 8
    """Forwarded UDP packets/s per (MAC, destination)."""
    UNBOUND = 10
    """Traffic from a protected-network source that holds no binding."""
    DNS_QPS = 53
    """DNS queries/s to the Pi."""
    DHCP = 67
    """DHCP requests/minute (lease-starvation brake)."""
    PORTAL_CONCURRENCY = 8080
    """Concurrent connections to the portal ports."""


OFFENDER_GUARD: Final[Mapping[OffenderCode, GuardName]] = MappingProxyType(
    {
        OffenderCode.SYN_PPS: GuardName.RAW,
        OffenderCode.UDP_LOCAL_PPS: GuardName.RAW,
        OffenderCode.ICMP_PPS: GuardName.RAW,
        OffenderCode.LOCAL_PPS: GuardName.RAW,
        OffenderCode.UNBOUND: GuardName.RAW,
        OffenderCode.DHCP: GuardName.RAW,
        OffenderCode.CLOSED_PORT: GuardName.INPUT,
        OffenderCode.DNS_QPS: GuardName.INPUT,
        OffenderCode.PORTAL_CONCURRENCY: GuardName.INPUT,
        OffenderCode.NEWCONN: GuardName.FORWARD,
        OffenderCode.NEWCONN_DST: GuardName.FORWARD,
        OffenderCode.UDP_FWD: GuardName.FORWARD,
    }
)
"""Which guard's verdict chain each offender code's meter rule jumps to.

Evidence for a code carries *that* guard's mode at poll time, which is what
caps observe-mode offenders at MONITOR (ADDENDUM_4.md D4).
"""

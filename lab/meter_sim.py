"""Kernel-meter simulator: the static guards' per-MAC token buckets, replayed offline over pcaps.

The offline G5 check (`lab/benign_fp.py`, PLAN_v3 §2) has to say what the
`pirewall_static` meters *would* have done to benign traffic before anyone
enables the forward guard. This module reproduces those meters packet by
packet.

**Numbers are never retyped.** `TemplateSpec.from_config` renders
`deploy/firewall/pirewall_static.nft.template` with
`scripts.deployment.render_templates.render_template` (the function
`pirewall-start` loads the kernel from) and parses every rate, burst, unit,
set timeout, set size, port list, offender code and verdict from the
rendered text. A template change therefore changes the simulator, and
`tests/unit/test_lab_meter_sim.py` fails if a meter rule stops parsing.

**Semantics, as the kernel implements them** (reasoned from `nft_limit.c`
and `nft_dynset.c`, and consistent with the sandbox results in
`docs/v2/v2/RESULTS.md`: a 40-packet DHCP burst let exactly `burst` = 5
through, and a 3 s flood fitted inside a 40k burst):

* `limit rate over R/unit burst B packets` is a token bucket holding at
  most `B` packets, created full, refilled at `R` per `unit`. A packet
  takes a token when one is there and does not match; with none left it
  matches ("over"), takes nothing, and the rule's `update @offenders` and
  `jump guard_verdict_<guard>` run.
* A meter element is created by `add @set { key limit ... }` with the set's
  timeout. `add` never refreshes that timeout (only `update` does), so an
  element expires `timeout` after it was created and the next packet makes
  a fresh, full bucket.
* A **full** meter set cannot create an element: the rule stops there and
  the packet is not policed (**fail-open**, RESULTS.md finding 1). Counted
  in `failopen`.
* `@offenders` elements are written with `update`, so each trip refreshes
  the element's timeout. A full `@offenders` cannot take a new key: that
  rule breaks before its verdict, counted in `offenders_full`.
* A guard in **enforce** drops the packet on a trip (processing stops); in
  **observe** the verdict chain is empty and the packet goes on to the next
  rule, as in the kernel.
* Keyless global backstops are one bucket each.

**What the simulator has to approximate**, documented rather than hidden:

* *Direction.* A capture on the LAN interface sees both directions.
  LAN-ingress frames are those whose Ethernet source is not the Pi's own
  MAC (`--pi-mac`, or learnt from the first frame the Pi's LAN IP sent).
  Until it is known, a frame is ingress when its IPv4 source is in the
  protected network and is not the Pi.
* *Bindings.* `bound4`/`macbind` come from a lease file when one is given,
  else every IP is bound to the first unicast MAC seen sending from it.
  That assumes every device holds a lease, so it undercounts the `unbound`
  class for static-IP devices.
* *Local vs forwarded.* `fib daddr type local` is "the destination is the
  Pi's LAN address". Broadcast and multicast are delivered to `input_guard`
  (conservative: more chances to trip). Traffic between two LAN clients
  never reaches the Pi's stack (firmware bridging, PLAN_FINAL §1 fact 1) and
  is ignored.
* *Conntrack.* A minimal table: a packet is `ct state new` until its
  connection has seen a reply (so unanswered UDP stays new, as in the
  kernel). Timeouts: TCP 120 s unanswered or after FIN/RST, 432000 s
  established; UDP 30 s unanswered, 120 s answered; ICMP 30 s.
* *Not simulated:* the allowlist (`allow_bound`), the reverse-path check,
  the adaptive table (`rl_meter`), and anything outside the LAN interface.
"""

import re
import struct
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Final, Literal

from scripts.deployment.render_templates import render_template

from pirewall.config.models import PirewallConfig
from pirewall.core import nft_names
from pirewall.core.enums import GuardMode, GuardName
from pirewall.core.nft_names import OFFENDER_GUARD, OffenderCode

__all__ = [
    "STATIC_TEMPLATE",
    "MeterRule",
    "MeterSimulator",
    "SimKernelReader",
    "TemplateParseError",
    "TemplateSpec",
    "Trip",
]

STATIC_TEMPLATE: Final = (
    Path(__file__).resolve().parents[1] / "deploy" / "firewall" / "pirewall_static.nft.template"
)

Key = Literal["mac", "mac_daddr"]
_PROTO_ICMP, _PROTO_TCP, _PROTO_UDP = 1, 6, 17
_FIN, _SYN, _RST, _ACK = 0x01, 0x02, 0x04, 0x10
_BROADCAST: Final = IPv4Address("255.255.255.255")
_MULTICAST: Final = IPv4Network("224.0.0.0/4")
_UNSPECIFIED: Final = IPv4Address("0.0.0.0")
_TCP_UNREPLIED, _TCP_ESTABLISHED, _TCP_CLOSING = 120.0, 432000.0, 120.0
_UDP_UNREPLIED, _UDP_REPLIED, _ICMP_TIMEOUT = 30.0, 120.0, 30.0
_CT_SWEEP_SECONDS: Final = 10.0


class TemplateParseError(Exception):
    """The rendered static template no longer has the shape the simulator reads."""


@dataclass(frozen=True, slots=True)
class MeterRule:
    """One `add @set { key limit rate over ... } update @offenders { ... } jump guard_verdict_*` rule."""

    set_name: str
    code: OffenderCode
    guard: GuardName
    key: Key
    rate_per_second: float
    burst: int


@dataclass(frozen=True, slots=True)
class Backstop:
    """One keyless `limit rate over ... counter name c_bk_* jump guard_verdict_*` rule."""

    counter: str
    guard: GuardName
    rate_per_second: float
    burst: int


@dataclass(frozen=True, slots=True)
class SetDecl:
    """A dynamic set's timeout (None for no timeout) and size."""

    timeout_seconds: float | None
    size: int


_SET = re.compile(r"set (\w+) \{ type [^;]+; flags ([^;]+);(?: timeout (\d+)s;)? size (\d+); \}")
_LIMIT = re.compile(
    r"add @(\w+) \{ ether saddr( \. ip daddr)? limit rate over (\d+)/(second|minute) burst (\d+) packets \}"
    r" update @offenders \{ ether saddr \. (\d+) \} jump guard_verdict_(\w+)"
)
_CT_COUNT = re.compile(
    r"add @(\w+) \{ ether saddr ct count over (\d+) \} update @offenders \{ ether saddr \. (\d+) \}"
    r" jump guard_verdict_(\w+)"
)
_BACKSTOP = re.compile(
    r"limit rate over (\d+)/(second|minute) burst (\d+) packets "
    r"counter name (c_bk_\w+) jump guard_verdict_(\w+)"
)
_PORT_LIST = r"\{ ([\d, ]+) \}"
_CLOSED_TCP = re.compile(r"ct state new tcp dport != " + _PORT_LIST + r" add @closed_meter")
_CLOSED_UDP = re.compile(r"ct state new udp dport != " + _PORT_LIST + r" add @closed_meter")
_PORTAL_TCP = re.compile(r"ct state new tcp dport " + _PORT_LIST + r" add @portal_conc")
_DNS_BYPASS = re.compile(r"th dport " + _PORT_LIST + r" counter name c_dns_bypass drop")
_VERDICT = re.compile(r"counter name c_verdict_(\w+)( drop)?\s*\n")
_UNITS: Final = {"second": 1.0, "minute": 60.0}


def _ports(pattern: re.Pattern[str], text: str, what: str) -> frozenset[int]:
    match = pattern.search(text)
    if match is None:
        raise TemplateParseError(f"the static template has no {what} rule")
    return frozenset(int(item) for item in match.group(1).replace(" ", "").split(","))


@dataclass(frozen=True, slots=True)
class TemplateSpec:
    """Everything the simulator takes from the rendered static template."""

    meters: Mapping[OffenderCode, MeterRule]
    portal_concurrency: int
    backstops: Mapping[str, Backstop]
    sets: Mapping[str, SetDecl]
    closed_tcp_exempt: frozenset[int]
    closed_udp_exempt: frozenset[int]
    portal_ports: frozenset[int]
    dns_bypass_ports: frozenset[int]
    guard_modes: Mapping[GuardName, GuardMode]

    @classmethod
    def parse(cls, rendered: str) -> "TemplateSpec":
        """Parse a rendered `pirewall_static.nft`. Raises `TemplateParseError`."""
        text = rendered.replace("\r\n", "\n")
        sets: dict[str, SetDecl] = {}
        for name, _flags, timeout, size in _SET.findall(text):
            sets[name] = SetDecl(float(timeout) if timeout else None, int(size))
        meters: dict[OffenderCode, MeterRule] = {}
        for set_name, pair, rate, unit, burst, code, guard in _LIMIT.findall(text):
            offender = OffenderCode(int(code))
            rule = MeterRule(
                set_name,
                offender,
                GuardName(guard),
                "mac_daddr" if pair else "mac",
                int(rate) / _UNITS[unit],
                int(burst),
            )
            if offender in meters and meters[offender] != rule:
                raise TemplateParseError(f"offender code {offender.name} has two different meter rules")
            meters[offender] = rule
        conc = _CT_COUNT.search(text)
        if conc is None:
            raise TemplateParseError("the static template has no portal concurrency rule")
        backstops = {
            counter: Backstop(counter, GuardName(guard), int(rate) / _UNITS[unit], int(burst))
            for rate, unit, burst, counter, guard in _BACKSTOP.findall(text)
        }
        expected = set(OffenderCode) - {OffenderCode(int(conc.group(3)))}
        missing = sorted(code.name for code in expected - set(meters))
        if missing:
            raise TemplateParseError(f"no meter rule parsed for offender codes {missing}")
        for rule in meters.values():
            if rule.guard is not OFFENDER_GUARD[rule.code]:
                raise TemplateParseError(
                    f"{rule.code.name} jumps to {rule.guard}, not {OFFENDER_GUARD[rule.code]}"
                )
            if rule.set_name not in sets:
                raise TemplateParseError(f"meter set {rule.set_name} is not declared")
        modes = {
            GuardName(name): GuardMode.ENFORCE if drop else GuardMode.OBSERVE
            for name, drop in _VERDICT.findall(text)
        }
        if set(modes) != set(GuardName):
            raise TemplateParseError("the guard verdict chains did not all parse")
        return cls(
            meters=meters,
            portal_concurrency=int(conc.group(2)),
            backstops=backstops,
            sets=sets,
            closed_tcp_exempt=_ports(_CLOSED_TCP, text, "closed-port TCP"),
            closed_udp_exempt=_ports(_CLOSED_UDP, text, "closed-port UDP"),
            portal_ports=_ports(_PORTAL_TCP, text, "portal concurrency"),
            dns_bypass_ports=_ports(_DNS_BYPASS, text, "DNS bypass"),
            guard_modes=modes,
        )

    @classmethod
    def from_config(cls, config: PirewallConfig, template: Path = STATIC_TEMPLATE) -> "TemplateSpec":
        """Render the static template with `config` (as `pirewall-start` does) and parse it."""
        return cls.parse(render_template(template.read_text(encoding="utf-8"), config))


# ---------------------------------------------------------------- frames


@dataclass(frozen=True, slots=True)
class _Frame:
    src_mac: str
    dst_mac: str
    kind: Literal["ipv4", "ipv6", "arp", "other"]
    src: IPv4Address | None = None
    dst: IPv4Address | None = None
    proto: int = 0
    fragment: bool = False
    sport: int | None = None
    dport: int | None = None
    flags: int = 0
    arp_sender_mac: str | None = None


def _mac(raw: bytes) -> str:
    return raw.hex(":")


def parse_frame(data: bytes) -> _Frame | None:
    """Header fields only, tolerant of snaplen truncation (a `-s 128` capture keeps every header)."""
    if len(data) < 14:
        return None
    dst_mac, src_mac = _mac(data[0:6]), _mac(data[6:12])
    ethertype = struct.unpack_from("!H", data, 12)[0]
    if ethertype == 0x86DD:
        return _Frame(src_mac, dst_mac, "ipv6")
    if ethertype == 0x0806:
        if len(data) < 14 + 28:
            return None
        return _Frame(
            src_mac,
            dst_mac,
            "arp",
            src=IPv4Address(data[28:32]),
            dst=IPv4Address(data[38:42]),
            arp_sender_mac=_mac(data[22:28]),
        )
    if ethertype != 0x0800 or len(data) < 34:
        return _Frame(src_mac, dst_mac, "other")
    ihl = (data[14] & 0x0F) * 4
    proto = data[23]
    fragment = (struct.unpack_from("!H", data, 20)[0] & 0x3FFF) != 0
    src, dst = IPv4Address(data[26:30]), IPv4Address(data[30:34])
    l4 = 14 + ihl
    sport = dport = None
    flags = 0
    if not fragment and proto in (_PROTO_TCP, _PROTO_UDP) and len(data) >= l4 + 4:
        sport, dport = struct.unpack_from("!HH", data, l4)
        if proto == _PROTO_TCP and len(data) >= l4 + 14:
            flags = data[l4 + 13]
    return _Frame(src_mac, dst_mac, "ipv4", src, dst, proto, fragment, sport, dport, flags)


# ------------------------------------------------------------- state


@dataclass(slots=True)
class _Bucket:
    tokens: float
    last: float
    expires_at: float | None


@dataclass(slots=True)
class _Conn:
    origin: tuple[IPv4Address, int | None]
    replied: bool
    last: float
    closing: bool = False

    def timeout(self, proto: int) -> float:
        if proto == _PROTO_TCP:
            if self.closing or not self.replied:
                return _TCP_CLOSING if self.closing else _TCP_UNREPLIED
            return _TCP_ESTABLISHED
        if proto == _PROTO_UDP:
            return _UDP_REPLIED if self.replied else _UDP_UNREPLIED
        return _ICMP_TIMEOUT


@dataclass(slots=True)
class Trip:
    """Every over-limit hit of one (MAC, offender code): what `@offenders` would have recorded."""

    mac: str
    code: OffenderCode
    hits: int = 0
    first_at: float = 0.0
    last_at: float = 0.0


@dataclass(slots=True)
class SimCounters:
    """Static drops and meter health, per kind."""

    frames: int = 0
    ingress: int = 0
    static_drops: dict[str, int] = field(default_factory=dict[str, int])
    static_drops_by_mac: dict[str, dict[str, int]] = field(default_factory=dict[str, dict[str, int]])
    verdict_hits: dict[GuardName, int] = field(default_factory=dict[GuardName, int])
    backstop_hits: dict[str, int] = field(default_factory=dict[str, int])
    guard_drops: dict[GuardName, int] = field(default_factory=dict[GuardName, int])
    failopen: dict[str, int] = field(default_factory=dict[str, int])
    offenders_full: int = 0


class MeterSimulator:
    """Feed frames in capture order; read offenders and counters at any time.

    Not thread-safe. Times are capture seconds (float).
    """

    def __init__(
        self,
        spec: TemplateSpec,
        *,
        pi_ip: IPv4Address,
        protected: IPv4Network,
        guard_modes: Mapping[GuardName, GuardMode] | None = None,
        bindings: Mapping[IPv4Address, str] | None = None,
        pi_mac: str | None = None,
    ) -> None:
        """`bindings` (IP -> MAC) are fixed when given; else learnt from the first sender of each IP."""
        self.spec = spec
        self._pi_ip = pi_ip
        self._protected = protected
        self._lan_broadcast = protected.broadcast_address
        self.guard_modes: dict[GuardName, GuardMode] = dict(guard_modes or spec.guard_modes)
        self._fixed_bindings = bindings is not None
        self.bindings: dict[IPv4Address, str] = dict(bindings or {})
        self.pi_mac = pi_mac
        self._buckets: dict[str, dict[object, _Bucket]] = {}
        self._global: dict[str, _Bucket] = {}
        self._offenders: dict[tuple[str, OffenderCode], float] = {}
        offender_set = spec.sets.get(nft_names.SET_OFFENDERS)
        self._offender_timeout = offender_set.timeout_seconds if offender_set else 120.0
        self._offender_size = offender_set.size if offender_set else None
        self._ct: dict[tuple[object, ...], _Conn] = {}
        self._portal: dict[str, set[tuple[object, ...]]] = {}
        self._next_sweep: float | None = None
        self.trips: dict[tuple[str, OffenderCode], Trip] = {}
        self.counters = SimCounters()

    # ------------------------------------------------------------ input

    def feed(self, data: bytes, at: float) -> None:
        """One captured frame at capture time `at` (seconds)."""
        self.counters.frames += 1
        frame = parse_frame(data)
        if frame is None:
            return
        if self._next_sweep is None or at >= self._next_sweep:
            self._sweep(at)
            self._next_sweep = at + _CT_SWEEP_SECONDS
        if frame.kind == "ipv4" and frame.src == self._pi_ip and self.pi_mac is None:
            self.pi_mac = frame.src_mac
        if not self._is_ingress(frame):
            if frame.kind == "ipv4":
                self._conntrack(frame, at)
            return
        self.counters.ingress += 1
        if frame.kind == "ipv6":
            self._static_drop("c_ipv6", frame.src_mac)
            return
        if frame.kind == "arp":
            self._arp(frame)
            return
        if frame.kind != "ipv4":
            return
        if frame.fragment:
            self._static_drop("c_frag", frame.src_mac)
            return
        if not self._prerouting_raw(frame, at):
            return
        if not self._hook(frame, at):
            return
        self._conntrack(frame, at)

    def _is_ingress(self, frame: _Frame) -> bool:
        if self.pi_mac is not None:
            return frame.src_mac != self.pi_mac
        if frame.kind != "ipv4" or frame.src is None:
            return frame.kind in ("ipv6", "arp") and frame.src != self._pi_ip
        return frame.src != self._pi_ip and (frame.src in self._protected or frame.src == _UNSPECIFIED)

    # ------------------------------------------------------- the chains

    def _prerouting_raw(self, frame: _Frame, at: float) -> bool:
        """`prerouting_raw` (+ `dhcp_gate`, `unbound`, `flood_meters`). False when the packet is dropped."""
        assert frame.src is not None and frame.dst is not None
        mac = frame.src_mac
        if frame.proto == _PROTO_UDP and frame.sport == 68 and frame.dport == 67:
            if not self._meter(OffenderCode.DHCP, mac, frame, at):
                return False
            if frame.src == _UNSPECIFIED:
                return True
        if frame.dst == _BROADCAST or frame.dst in _MULTICAST or frame.dst == self._lan_broadcast:
            return True
        if frame.src not in self._protected or frame.src == self._pi_ip:
            return self._static_drop("c_bogon", mac)
        bound = self.bindings.get(frame.src)
        if bound is None and not self._fixed_bindings and _is_unicast(mac):
            self.bindings[frame.src] = mac
            bound = mac
        if bound is not None and bound != mac:
            return self._static_drop("c_spoof", mac)
        if bound is None:
            if not self._meter(OffenderCode.UNBOUND, mac, frame, at):
                return False
            if not self._backstop("c_bk_unbound", at):
                return False
        local = frame.dst == self._pi_ip
        syn = frame.proto == _PROTO_TCP and frame.flags & (_FIN | _SYN | _RST | _ACK) == _SYN
        if syn and not self._meter(OffenderCode.SYN_PPS, mac, frame, at):
            return False
        if frame.proto == _PROTO_ICMP and not self._meter(OffenderCode.ICMP_PPS, mac, frame, at):
            return False
        if (
            local
            and frame.proto == _PROTO_UDP
            and not self._meter(OffenderCode.UDP_LOCAL_PPS, mac, frame, at)
        ):
            return False
        if local and not self._meter(OffenderCode.LOCAL_PPS, mac, frame, at):
            return False
        if syn and not self._backstop("c_bk_syn", at):
            return False
        if frame.proto == _PROTO_ICMP and not self._backstop("c_bk_icmp", at):
            return False
        return not (local and frame.proto == _PROTO_UDP and not self._backstop("c_bk_udp", at))

    def _hook(self, frame: _Frame, at: float) -> bool:
        """`input_guard` for the Pi (and broadcast/multicast), `forward_guard` for the Internet."""
        assert frame.dst is not None
        mac = frame.src_mac
        new = self._is_new(frame, at)
        if (
            frame.dst == self._pi_ip
            or frame.dst == _BROADCAST
            or frame.dst in _MULTICAST
            or frame.dst == self._lan_broadcast
        ):
            if (
                frame.proto == _PROTO_UDP
                and frame.dport == 53
                and not self._meter(OffenderCode.DNS_QPS, mac, frame, at)
            ):
                return False
            if (
                new
                and frame.proto == _PROTO_TCP
                and frame.dport not in self.spec.closed_tcp_exempt
                and not self._meter(OffenderCode.CLOSED_PORT, mac, frame, at)
            ):
                return False
            if (
                new
                and frame.proto == _PROTO_UDP
                and frame.dport not in self.spec.closed_udp_exempt
                and not self._meter(OffenderCode.CLOSED_PORT, mac, frame, at)
            ):
                return False
            if new and frame.proto == _PROTO_TCP and frame.dport in self.spec.portal_ports:
                return self._portal_concurrency(frame, at)
            return True
        if frame.dst in self._protected:
            return False  # client <-> client: bridged in firmware, never reaches the Pi
        if frame.proto in (_PROTO_TCP, _PROTO_UDP) and frame.dport in self.spec.dns_bypass_ports:
            return self._static_drop("c_dns_bypass", mac)
        if new and not self._meter(OffenderCode.NEWCONN, mac, frame, at):
            return False
        if new and not self._meter(OffenderCode.NEWCONN_DST, mac, frame, at):
            return False
        if frame.proto == _PROTO_UDP and not self._meter(OffenderCode.UDP_FWD, mac, frame, at):
            return False
        return not (new and not self._backstop("c_bk_newconn", at))

    def _arp(self, frame: _Frame) -> None:
        sender_ip, sender_mac = frame.src, frame.arp_sender_mac
        if sender_ip is None or sender_mac is None:
            return
        if sender_ip == self._pi_ip:
            self._static_drop("c_arp_spoof", frame.src_mac)
            return
        bound = self.bindings.get(sender_ip)
        if bound is not None and bound != sender_mac:
            self._static_drop("c_arp_spoof", frame.src_mac)

    # ------------------------------------------------------ the meters

    def _meter(self, code: OffenderCode, mac: str, frame: _Frame, at: float) -> bool:
        """One meter rule. False when it tripped and its guard enforces (the packet is dropped)."""
        rule = self.spec.meters[code]
        key: object = mac if rule.key == "mac" else (mac, frame.dst)
        bucket = self._element(rule.set_name, key, rule.burst, at)
        if bucket is None:
            self.counters.failopen[rule.set_name] = self.counters.failopen.get(rule.set_name, 0) + 1
            return True
        if _take(bucket, rule.rate_per_second, rule.burst, at):
            return True
        return self._trip(rule.code, rule.guard, mac, at)

    def _portal_concurrency(self, frame: _Frame, at: float) -> bool:
        """`ct count over N` per MAC: open connections to the portal ports, this one included."""
        mac = frame.src_mac
        key = _ct_key(frame)
        connections = self._portal.setdefault(mac, set())
        connections.add(key)
        if len(connections) <= self.spec.portal_concurrency:
            return True
        passed = self._trip(OffenderCode.PORTAL_CONCURRENCY, GuardName.INPUT, mac, at)
        if not passed:
            connections.discard(key)  # dropped before conntrack: never counted
        return passed

    def _trip(self, code: OffenderCode, guard: GuardName, mac: str, at: float) -> bool:
        key = (mac, code)
        if key not in self._offenders and self._offender_size is not None:
            self._expire_offenders(at)
            if len(self._offenders) >= self._offender_size:
                self.counters.offenders_full += 1
                return True  # the update fails, the rule breaks before its verdict
        self._offenders[key] = at + (self._offender_timeout or 0.0)
        trip = self.trips.get(key)
        if trip is None:
            trip = self.trips[key] = Trip(mac, code, first_at=at)
        trip.hits += 1
        trip.last_at = at
        return self._verdict(guard)

    def _backstop(self, counter: str, at: float) -> bool:
        backstop = self.spec.backstops.get(counter)
        if backstop is None:
            return True
        bucket = self._global.get(counter)
        if bucket is None:
            bucket = self._global[counter] = _Bucket(float(backstop.burst), at, None)
        if _take(bucket, backstop.rate_per_second, backstop.burst, at):
            return True
        self.counters.backstop_hits[counter] = self.counters.backstop_hits.get(counter, 0) + 1
        return self._verdict(backstop.guard)

    def _verdict(self, guard: GuardName) -> bool:
        self.counters.verdict_hits[guard] = self.counters.verdict_hits.get(guard, 0) + 1
        if self.guard_modes.get(guard) is GuardMode.ENFORCE:
            self.counters.guard_drops[guard] = self.counters.guard_drops.get(guard, 0) + 1
            return False
        return True

    def _element(self, set_name: str, key: object, burst: int, at: float) -> _Bucket | None:
        elements = self._buckets.setdefault(set_name, {})
        bucket = elements.get(key)
        if bucket is not None and (bucket.expires_at is None or bucket.expires_at > at):
            return bucket
        if bucket is not None:
            del elements[key]
        declaration = self.spec.sets[set_name]
        if len(elements) >= declaration.size:
            for stale in [k for k, b in elements.items() if b.expires_at is not None and b.expires_at <= at]:
                del elements[stale]
            if len(elements) >= declaration.size:
                return None
        timeout = declaration.timeout_seconds
        bucket = elements[key] = _Bucket(float(burst), at, None if timeout is None else at + timeout)
        return bucket

    def _static_drop(self, counter: str, mac: str) -> bool:
        self.counters.static_drops[counter] = self.counters.static_drops.get(counter, 0) + 1
        by_mac = self.counters.static_drops_by_mac.setdefault(mac, {})
        by_mac[counter] = by_mac.get(counter, 0) + 1
        return False

    # ------------------------------------------------------- conntrack

    def _is_new(self, frame: _Frame, at: float) -> bool:
        connection = self._ct.get(_ct_key(frame))
        if connection is None or connection.last + connection.timeout(frame.proto) <= at:
            return True
        return not connection.replied and connection.origin == (frame.src, frame.sport)

    def _conntrack(self, frame: _Frame, at: float) -> None:
        if frame.src is None or frame.proto not in (_PROTO_TCP, _PROTO_UDP, _PROTO_ICMP):
            return
        key = _ct_key(frame)
        connection = self._ct.get(key)
        if connection is not None and connection.last + connection.timeout(frame.proto) <= at:
            self._forget(key)
            connection = None
        if connection is None:
            connection = self._ct[key] = _Conn((frame.src, frame.sport), False, at)
        elif connection.origin != (frame.src, frame.sport):
            connection.replied = True
        connection.last = at
        if frame.proto == _PROTO_TCP and frame.flags & (_FIN | _RST):
            connection.closing = True

    def _forget(self, key: tuple[object, ...]) -> None:
        del self._ct[key]
        for keys in self._portal.values():
            keys.discard(key)

    def _sweep(self, at: float) -> None:
        for key, connection in list(self._ct.items()):
            proto = key[0]
            assert isinstance(proto, int)
            if connection.last + connection.timeout(proto) <= at:
                self._forget(key)
        self._expire_offenders(at)

    def _expire_offenders(self, at: float) -> None:
        for key in [key for key, expires in self._offenders.items() if expires <= at]:
            del self._offenders[key]

    # ---------------------------------------------------------- reads

    def offenders(self, at: float) -> list[tuple[str, int]]:
        """`@offenders` at capture time `at`, as `(mac, code)` like `FirewallManager.kernel_offenders`."""
        self._expire_offenders(at)
        return sorted((mac, int(code)) for mac, code in self._offenders)

    def set_fill(self, set_name: str, at: float) -> tuple[int, int | None]:
        """(live elements, declared size) of one static meter set."""
        declaration = self.spec.sets.get(set_name)
        elements = self._buckets.get(set_name, {})
        live = sum(1 for bucket in elements.values() if bucket.expires_at is None or bucket.expires_at > at)
        if set_name == nft_names.SET_OFFENDERS:
            live = len(self.offenders(at))
        return live, None if declaration is None else declaration.size


def _take(bucket: _Bucket, rate_per_second: float, burst: int, at: float) -> bool:
    """Refill, then take one token if there is one. False: the limit is exceeded ("over" matches)."""
    bucket.tokens = min(float(burst), bucket.tokens + max(at - bucket.last, 0.0) * rate_per_second)
    bucket.last = max(bucket.last, at)
    if bucket.tokens >= 1.0:
        bucket.tokens -= 1.0
        return True
    return False


def _ct_key(frame: _Frame) -> tuple[object, ...]:
    assert frame.src is not None and frame.dst is not None
    a = (int(frame.src), frame.sport or 0)
    b = (int(frame.dst), frame.dport or 0)
    low, high = (a, b) if a <= b else (b, a)
    return (frame.proto, *low, *high)


def _is_unicast(mac: str) -> bool:
    first = int(mac[:2], 16)
    return not first & 1 and mac != "00:00:00:00:00:00"


class SimKernelReader:
    """`pirewall.detection_v2.kernel.KernelReader` over a simulator: the real `KernelPoller`, offline."""

    def __init__(self, simulator: MeterSimulator) -> None:
        self._sim = simulator
        self.now = 0.0

    def offenders(self) -> Sequence[tuple[str, int]]:
        """`@offenders` at `self.now`."""
        return self._sim.offenders(self.now)

    def counters(self, names: Iterable[str]) -> Mapping[str, int]:
        """The per-guard verdict counters (`c_verdict_*`)."""
        by_name = {
            counter: self._sim.counters.verdict_hits.get(guard, 0)
            for guard, counter in nft_names.GUARD_VERDICT_COUNTERS.items()
        }
        return {name: by_name[name] for name in names if name in by_name}

    def guard_modes(self) -> Mapping[GuardName, GuardMode]:
        """The simulated guard modes."""
        return dict(self._sim.guard_modes)

    def static_table_present(self) -> bool:
        """Always: the simulated table never goes away."""
        return True

    def set_fill(self, table: str, set_name: str) -> tuple[int, int | None]:
        """Static meter sets and `@offenders` from the simulator; the adaptive sets stay empty offline."""
        if table == nft_names.STATIC_TABLE:
            return self._sim.set_fill(set_name, self.now)
        return 0, None

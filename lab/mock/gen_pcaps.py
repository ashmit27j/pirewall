"""Generate the `mock` data set: seeded synthetic pcaps with ground truth (ADDENDUM_4.md D7, PLAN_v3 §4).

    uv sync --extra lab                         # scapy, dev/lab only
    uv run python lab/mock/gen_pcaps.py --seed 1 [--out lab/mock/out] [--scale 1.0] \
        [--only CLASS ...] [--force]

Writes, into `--out` (default `lab/mock/out/`, gitignored):

* `00_benign.pcap`: benign sessions over six fake unicast MACs: web
  browsing (DNS through the Pi, then HTTPS), NTP, a phone waking up (DHCP
  renew, then a burst of parallel HTTPS connections), an OS update (one
  long download), P2P (a few TCP peers and slow UDP to many peers), and
  mDNS/SSDP chatter.
* one `NN_<class>.pcap` per attack class (`ATTACK_CLASSES`), each in its own
  time slot after the previous file's, so the directory replays as one
  continuous capture (`pirewall.capture.replay`: name order). Light benign
  background runs through every slot.
* `ground_truth.jsonl`, one window per attacker MAC and class, in exactly
  the format `scripts/dataset/pcap_to_flows.py --ground-truth` reads
  (`{"mac", "start", "end", "label"}`, Unix seconds) plus `pcap`,
  `tool` and (not for MAC churn) the attacker's `ip`, which it ignores.
* `manifest.json` (`lab/manifest.py`, kind `dataset`, env tag `mock`).

**Deterministic.** Same `--seed` and `--scale` ⇒ byte-identical files
(`tests/unit/test_lab_gen_pcaps.py`). Every field scapy would otherwise
pick (IP id, TCP sequence numbers, DNS id, DHCP xid) is set from the
seeded generator, and timestamps start at a fixed epoch.

**scapy only builds frames** (CLAUDE.md v2 dependencies: dev/lab only, and
this is the only file that imports it); `pirewall.capture.pcapio.PcapWriter`
writes the files.

Addresses come from the config's `[network]` (default
`config/default_config.toml`, the one `pirewall-start --data-mode mock`
runs with): LAN clients and attackers inside `protected_network`, the Pi
at `pirewall_lan_ip`, the forward-path victim at the `[lab]` victim
address, and documentation ranges for the Internet.
"""

import argparse
import importlib
import json
import random
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any, Final

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # `python lab/mock/gen_pcaps.py`

from lab.common import REPO_ROOT, LabError, check_output_location
from lab.manifest import Manifest, write_manifest
from pirewall.capture.pcapio import PcapWriter
from pirewall.config.loader import load_config

TOOL: Final = "lab/mock/gen_pcaps.py"
DEFAULT_OUT: Final = REPO_ROOT / "lab" / "mock" / "out"
T0_US: Final = 1_772_409_600_000_000  # 2026-03-02 00:00:00 UTC, fixed so output is reproducible
PI_MAC: Final = "02:00:00:00:00:02"
BENIGN_SECONDS: Final = 300.0
SLOT_SECONDS: Final = 60.0
ATTACK_OFFSET_SECONDS: Final = 5.0
WAN: Final = IPv4Network("198.51.100.0/24")
SCAN_NET: Final = IPv4Network("203.0.113.0/24")

FIN, SYN, RST, PSH, ACK = "F", "S", "R", "P", "A"


def _scapy() -> Any:  # Any: scapy ships no usable type information
    try:
        return importlib.import_module("scapy.all")
    except ImportError as exc:
        raise LabError("scapy is not installed; it is a dev/lab-only extra:  uv sync --extra lab") from exc


class Frames:
    """Frame bytes from scapy, with every otherwise-random field pinned."""

    def __init__(self, rng: random.Random) -> None:
        self._s = _scapy()
        self._rng = rng
        self._ip_id = 0

    def _ip(self, src: IPv4Address | str, dst: IPv4Address | str) -> Any:  # Any: a scapy layer
        self._ip_id = (self._ip_id + 1) & 0xFFFF
        return self._s.IP(src=str(src), dst=str(dst), id=self._ip_id, ttl=64)

    def _ether(self, src: str, dst: str) -> Any:  # Any: a scapy layer
        return self._s.Ether(src=src, dst=dst)

    def tcp(
        self,
        smac: str,
        dmac: str,
        src: IPv4Address | str,
        dst: IPv4Address | str,
        sport: int,
        dport: int,
        flags: str,
        seq: int = 0,
        ack: int = 0,
        payload: bytes = b"",
    ) -> bytes:
        """One TCP segment."""
        layer = self._s.TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=64240)
        packet = self._ether(smac, dmac) / self._ip(src, dst) / layer
        if payload:
            packet = packet / self._s.Raw(load=payload)
        return bytes(packet)

    def udp(
        self,
        smac: str,
        dmac: str,
        src: IPv4Address | str,
        dst: IPv4Address | str,
        sport: int,
        dport: int,
        payload: bytes = b"",
    ) -> bytes:
        """One UDP datagram."""
        packet = self._ether(smac, dmac) / self._ip(src, dst) / self._s.UDP(sport=sport, dport=dport)
        if payload:
            packet = packet / self._s.Raw(load=payload)
        return bytes(packet)

    def dns(
        self,
        smac: str,
        dmac: str,
        src: IPv4Address,
        dst: IPv4Address,
        sport: int,
        name: str,
        reply: bool = False,
    ) -> bytes:
        """A DNS query (or its answer, from `src`)."""
        query = self._s.DNS(
            id=self._rng.randrange(1 << 16), rd=1, qr=int(reply), qd=self._s.DNSQR(qname=name)
        )
        if reply:
            sport, dport = 53, sport
        else:
            dport = 53
        layer = self._ether(smac, dmac) / self._ip(src, dst) / self._s.UDP(sport=sport, dport=dport) / query
        return bytes(layer)

    def icmp_echo(
        self,
        smac: str,
        dmac: str,
        src: IPv4Address | str,
        dst: IPv4Address | str,
        ident: int,
        seq: int,
        reply: bool = False,
    ) -> bytes:
        """An ICMP echo request (or reply)."""
        icmp = self._s.ICMP(type=0 if reply else 8, id=ident, seq=seq)
        return bytes(self._ether(smac, dmac) / self._ip(src, dst) / icmp / self._s.Raw(load=b"\x00" * 32))

    def dhcp(self, mac: str, kind: str) -> bytes:
        """A DHCP DISCOVER/REQUEST from an unconfigured client (0.0.0.0 -> broadcast)."""
        chaddr = bytes.fromhex(mac.replace(":", ""))
        packet = (
            self._ether(mac, "ff:ff:ff:ff:ff:ff")
            / self._ip("0.0.0.0", "255.255.255.255")
            / self._s.UDP(sport=68, dport=67)
            / self._s.BOOTP(chaddr=chaddr, xid=self._rng.randrange(1 << 32), flags=0x8000)
            / self._s.DHCP(options=[("message-type", kind), "end"])
        )
        return bytes(packet)

    def arp_reply(self, smac: str, claimed_ip: IPv4Address, target_mac: str, target_ip: IPv4Address) -> bytes:
        """An unsolicited ARP reply claiming `claimed_ip` is at `smac` (poisoning)."""
        arp = self._s.ARP(op=2, hwsrc=smac, psrc=str(claimed_ip), hwdst=target_mac, pdst=str(target_ip))
        return bytes(self._ether(smac, target_mac) / arp)


@dataclass(slots=True)
class Capture:
    """Frames of one pcap, stamped in microseconds; sorted before writing."""

    frames: list[tuple[int, int, bytes]] = field(default_factory=list[tuple[int, int, bytes]])

    def add(self, at: float, frame: bytes) -> None:
        """Add a frame at `at` seconds after T0. Ties keep insertion order."""
        self.frames.append((T0_US + round(at * 1_000_000), len(self.frames), frame))

    def write(self, path: Path) -> None:
        """Write a classic microsecond pcap."""
        with PcapWriter(path) as writer:
            for ts_us, _order, frame in sorted(self.frames):
                writer.write(frame, ts_us)


@dataclass(frozen=True, slots=True)
class Net:
    """The addresses every generator uses."""

    pi: IPv4Address
    protected: IPv4Network
    victim: IPv4Address
    portal_port: int

    def lan(self, host: int) -> IPv4Address:
        """The `host`-th address of the protected network."""
        return self.protected.network_address + host


@dataclass(frozen=True, slots=True)
class Device:
    """A fake LAN device."""

    name: str
    mac: str
    ip: IPv4Address


def benign_devices(net: Net) -> tuple[Device, ...]:
    """The six benign devices (MACs `02:00:00:00:b0:0N`, locally administered unicast)."""
    names = ("laptop", "phone", "tv", "desktop", "p2p", "tablet")
    return tuple(Device(name, f"02:00:00:00:b0:{i + 1:02x}", net.lan(21 + i)) for i, name in enumerate(names))


def attacker(index: int, net: Net) -> Device:
    """The attacker for attack class number `index` (`02:00:00:00:a0:NN`)."""
    return Device(f"attacker{index}", f"02:00:00:00:a0:{index + 1:02x}", net.lan(100 + index))


# ------------------------------------------------------------- benign


class Benign:
    """Benign session generators; every reply comes from the Pi's MAC (it is the LAN's gateway)."""

    def __init__(self, frames: Frames, rng: random.Random, net: Net) -> None:
        self.f = frames
        self.rng = rng
        self.net = net
        self._port = 40000

    def _sport(self) -> int:
        self._port = 40000 + (self._port - 40000 + self.rng.randint(1, 37)) % 20000
        return self._port

    def _wan(self) -> IPv4Address:
        return WAN.network_address + self.rng.randint(1, 60)

    def dns(self, cap: Capture, at: float, device: Device) -> None:
        """A DNS lookup through the Pi."""
        sport = self._sport()
        name = f"site{self.rng.randint(1, 40)}.example."
        cap.add(at, self.f.dns(device.mac, PI_MAC, device.ip, self.net.pi, sport, name))
        cap.add(at + 0.004, self.f.dns(PI_MAC, device.mac, self.net.pi, device.ip, sport, name, reply=True))

    def tcp_session(
        self,
        cap: Capture,
        at: float,
        device: Device,
        server: IPv4Address,
        dport: int,
        up: int,
        down: int,
        segments: int = 3,
        gap: float = 0.02,
    ) -> float:
        """A complete TCP connection; returns when it ended."""
        sport = self._sport()
        c_seq, s_seq = self.rng.randrange(1 << 31), self.rng.randrange(1 << 31)
        mac, ip = device.mac, device.ip
        t = at
        cap.add(t, self.f.tcp(mac, PI_MAC, ip, server, sport, dport, SYN, c_seq))
        t += 0.015
        cap.add(t, self.f.tcp(PI_MAC, mac, server, ip, dport, sport, SYN + ACK, s_seq, c_seq + 1))
        t += 0.001
        cap.add(t, self.f.tcp(mac, PI_MAC, ip, server, sport, dport, ACK, c_seq + 1, s_seq + 1))
        c_seq += 1
        s_seq += 1
        for _ in range(segments):
            t += gap
            cap.add(t, self.f.tcp(mac, PI_MAC, ip, server, sport, dport, PSH + ACK, c_seq, s_seq, b"q" * up))
            c_seq += up
            t += gap
            cap.add(
                t, self.f.tcp(PI_MAC, mac, server, ip, dport, sport, PSH + ACK, s_seq, c_seq, b"r" * down)
            )
            s_seq += down
        t += gap
        cap.add(t, self.f.tcp(mac, PI_MAC, ip, server, sport, dport, FIN + ACK, c_seq, s_seq))
        t += 0.015
        cap.add(t, self.f.tcp(PI_MAC, mac, server, ip, dport, sport, FIN + ACK, s_seq, c_seq + 1))
        t += 0.001
        cap.add(t, self.f.tcp(mac, PI_MAC, ip, server, sport, dport, ACK, c_seq + 1, s_seq + 1))
        return t

    def web(self, cap: Capture, at: float, device: Device) -> None:
        """A page load: two lookups, then four HTTPS connections to three servers."""
        servers = [self._wan() for _ in range(3)]
        self.dns(cap, at, device)
        self.dns(cap, at + 0.01, device)
        for i in range(4):
            self.tcp_session(
                cap,
                at + 0.05 + i * 0.03,
                device,
                servers[i % 3],
                443,
                self.rng.randint(200, 600),
                self.rng.randint(800, 1400),
                segments=self.rng.randint(2, 6),
            )

    def ntp(self, cap: Capture, at: float, device: Device) -> None:
        """One SNTP exchange with an Internet server."""
        server = self._wan()
        cap.add(at, self.f.udp(device.mac, PI_MAC, device.ip, server, 123, 123, b"\x23" + b"\x00" * 47))
        cap.add(
            at + 0.03, self.f.udp(PI_MAC, device.mac, server, device.ip, 123, 123, b"\x24" + b"\x00" * 47)
        )

    def phone_wakes(self, cap: Capture, at: float, device: Device) -> None:
        """DHCP renew, then a burst of parallel HTTPS connections to a handful of hosts."""
        cap.add(at, self.f.dhcp(device.mac, "request"))
        hosts = [self._wan() for _ in range(6)]
        for i in range(14):
            self.tcp_session(
                cap,
                at + 0.3 + i * 0.12,
                device,
                hosts[i % 6],
                443,
                self.rng.randint(150, 500),
                self.rng.randint(500, 1400),
            )

    def update(self, cap: Capture, at: float, device: Device, seconds: float) -> None:
        """An OS update: one long download on one connection."""
        server = self._wan()
        segments = max(int(seconds * 40), 20)
        self.tcp_session(
            cap, at, device, server, 443, 300, 1400, segments=segments, gap=seconds / segments / 2
        )

    def p2p(self, cap: Capture, at: float, device: Device, seconds: float) -> None:
        """A few TCP peers on high ports, and slow UDP to many peers (most of whom answer)."""
        peers = [WAN.network_address + 100 + i for i in range(30)]
        for i in range(4):
            self.tcp_session(cap, at + i * 0.5, device, peers[i], 6881 + i, 400, 1200, segments=4)
        t = at
        while t < at + seconds:
            peer = peers[self.rng.randrange(len(peers))]
            cap.add(
                t, self.f.udp(device.mac, PI_MAC, device.ip, peer, 51413, 6881, b"d1:ad2:id20:" + b"x" * 40)
            )
            if self.rng.random() < 0.8:
                cap.add(
                    t + 0.05,
                    self.f.udp(PI_MAC, device.mac, peer, device.ip, 6881, 51413, b"d1:rd2:id20:" + b"y" * 40),
                )
            t += self.rng.uniform(0.5, 2.0)

    def chatter(self, cap: Capture, at: float, device: Device) -> None:
        """mDNS and SSDP: link-local multicast, exempt from anti-spoof."""
        cap.add(
            at,
            self.f.udp(device.mac, "01:00:5e:00:00:fb", device.ip, "224.0.0.251", 5353, 5353, b"\x00" * 30),
        )
        cap.add(
            at + 0.2,
            self.f.udp(
                device.mac,
                "01:00:5e:7f:ff:fa",
                device.ip,
                "239.255.255.250",
                50000,
                1900,
                b"M-SEARCH * HTTP/1.1\r\n",
            ),
        )

    def background(self, cap: Capture, start: float, seconds: float, devices: Sequence[Device]) -> None:
        """Every benign behaviour, spread over [start, start + seconds)."""
        laptop, phone, tv, desktop, p2p, tablet = devices
        t = start
        while t < start + seconds:
            device = self.rng.choice([laptop, desktop, tablet, tv])
            self.web(cap, t, device)
            t += self.rng.uniform(2.0, 9.0)
        for device in devices:
            self.ntp(cap, start + self.rng.uniform(0, seconds), device)
            self.chatter(cap, start + self.rng.uniform(0, seconds), device)
        self.phone_wakes(cap, start + self.rng.uniform(0, seconds / 2), phone)
        self.update(cap, start + seconds * 0.2, desktop, min(seconds * 0.3, 60.0))
        self.p2p(cap, start + 1.0, p2p, seconds - 2.0)


# ------------------------------------------------------------- attacks


@dataclass(slots=True)
class Attack:
    """What one attack generator wrote: its windows for the ground truth."""

    label: str
    windows: list[tuple[str, float, float]] = field(default_factory=list[tuple[str, float, float]])


class Attacks:
    """One generator per attack class. `at` is the attack start, `seconds` its duration."""

    def __init__(
        self, frames: Frames, rng: random.Random, net: Net, benign: Benign, neighbour: Device
    ) -> None:
        self.f = frames
        self.rng = rng
        self.net = net
        self.benign = benign
        self.neighbour = neighbour
        self.churned: list[tuple[str, float, float]] = []

    def _random_source(self) -> IPv4Address:
        return IPv4Address(self.rng.randrange(1 << 24, 0xE0000000))  # hping3 --rand-source: any unicast

    def _flood(
        self, cap: Capture, at: float, seconds: float, rate: float, make: Callable[[int], bytes]
    ) -> None:
        for i in range(max(int(seconds * rate), 1)):
            cap.add(at + i / rate, make(i))

    def syn_flood_fixed(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """hping3 -S -p 80 -i u600 <pi>: one source, incrementing source port."""
        self._flood(
            cap,
            at,
            seconds,
            1500.0,
            lambda i: self.f.tcp(
                me.mac, PI_MAC, me.ip, self.net.pi, 1024 + i % 60000, 80, SYN, self.rng.randrange(1 << 31)
            ),
        )

    def syn_flood_random(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """hping3 -S --rand-source -p 80 <pi>."""
        self._flood(
            cap,
            at,
            seconds,
            1500.0,
            lambda i: self.f.tcp(
                me.mac,
                PI_MAC,
                self._random_source(),
                self.net.pi,
                1024 + i % 60000,
                80,
                SYN,
                self.rng.randrange(1 << 31),
            ),
        )

    def udp_flood_fixed(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """hping3 --udp -p 5555 -i u300 <pi>."""
        self._flood(
            cap,
            at,
            seconds,
            3000.0,
            lambda i: self.f.udp(me.mac, PI_MAC, me.ip, self.net.pi, 2000 + i % 50000, 5555, b"\x00" * 64),
        )

    def udp_flood_random(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """hping3 --udp --rand-source -p 5555 <pi>."""
        self._flood(
            cap,
            at,
            seconds,
            3000.0,
            lambda i: self.f.udp(
                me.mac, PI_MAC, self._random_source(), self.net.pi, 2000 + i % 50000, 5555, b"\x00" * 64
            ),
        )

    def icmp_flood_fixed(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """hping3 --icmp -i u2000 <pi>."""
        self._flood(
            cap,
            at,
            seconds,
            500.0,
            lambda i: self.f.icmp_echo(me.mac, PI_MAC, me.ip, self.net.pi, 0x1234, i & 0xFFFF),
        )

    def icmp_flood_random(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """hping3 --icmp --rand-source <pi>."""
        self._flood(
            cap,
            at,
            seconds,
            500.0,
            lambda i: self.f.icmp_echo(
                me.mac, PI_MAC, self._random_source(), self.net.pi, 0x1234, i & 0xFFFF
            ),
        )

    def _syn_scan(
        self,
        cap: Capture,
        at: float,
        me: Device,
        target: IPv4Address,
        ports: Sequence[int],
        interval: float,
        open_ports: frozenset[int] = frozenset({22, 80}),
    ) -> None:
        sport = 50000 + self.rng.randrange(10000)
        for i, port in enumerate(ports):
            t = at + i * interval
            seq = self.rng.randrange(1 << 31)
            cap.add(t, self.f.tcp(me.mac, PI_MAC, me.ip, target, sport, port, SYN, seq))
            if port in open_ports:
                cap.add(
                    t + 0.001,
                    self.f.tcp(
                        PI_MAC,
                        me.mac,
                        target,
                        me.ip,
                        port,
                        sport,
                        SYN + ACK,
                        self.rng.randrange(1 << 31),
                        seq + 1,
                    ),
                )
                cap.add(t + 0.0015, self.f.tcp(me.mac, PI_MAC, me.ip, target, sport, port, RST, seq + 1))
            else:
                cap.add(
                    t + 0.001, self.f.tcp(PI_MAC, me.mac, target, me.ip, port, sport, RST + ACK, 0, seq + 1)
                )

    def _ports(self, count: int) -> list[int]:
        ports = list(range(1, 1025))
        self.rng.shuffle(ports)
        return ports[:count]

    def vertical_scan_t4(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """nmap -sS -T4 <victim>: hundreds of ports a second."""
        self._syn_scan(cap, at, me, self.net.victim, self._ports(max(int(seconds * 150), 60)), 1 / 300)

    def vertical_scan_t3(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """nmap -sS -T3 <victim>."""
        self._syn_scan(cap, at, me, self.net.victim, self._ports(max(int(seconds * 50), 40)), 1 / 60)

    def vertical_scan_t2(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """nmap -sS -T2 <victim>: one probe every 0.4 s."""
        self._syn_scan(cap, at, me, self.net.victim, self._ports(max(int(seconds / 0.4), 30)), 0.4)

    def horizontal_scan(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """nmap -sS -p 22 <a /24>: one port, many hosts; most never answer."""
        sport = 50000 + self.rng.randrange(10000)
        hosts = [SCAN_NET.network_address + i for i in range(1, 255)][: max(int(seconds * 20), 40)]
        for i, host in enumerate(hosts):
            t = at + i * 0.04
            seq = self.rng.randrange(1 << 31)
            cap.add(t, self.f.tcp(me.mac, PI_MAC, me.ip, host, sport, 22, SYN, seq))
            if i % 7 == 0:
                cap.add(t + 0.02, self.f.tcp(PI_MAC, me.mac, host, me.ip, 22, sport, RST + ACK, 0, seq + 1))

    def masscan_like(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """masscan -p 22,80,443 --rate 5000: fixed source port, randomised order (held-out tool)."""
        targets = [(SCAN_NET.network_address + h, p) for h in range(1, 255) for p in (22, 80, 443)]
        self.rng.shuffle(targets)
        for i, (host, port) in enumerate(targets[: max(int(seconds * 5000), 300)]):
            cap.add(
                at + i / 5000,
                self.f.tcp(me.mac, PI_MAC, me.ip, host, 61000, port, SYN, self.rng.randrange(1 << 31)),
            )

    def _brute(
        self,
        cap: Capture,
        at: float,
        seconds: float,
        me: Device,
        target: IPv4Address,
        port: int,
        rate: float,
        up: int,
        down: int,
    ) -> None:
        count = max(int(seconds * rate), 30)
        for i in range(count):
            self.benign.tcp_session(cap, at + i / rate, me, target, port, up, down, segments=3, gap=0.01)

    def ssh_bruteforce(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """hydra -t 4 ssh://<victim>: short, same-size connections."""
        self._brute(cap, at, seconds, me, self.net.victim, 22, 6.0, 120, 480)

    def http_bruteforce(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """hydra http-post-form against <victim>:80."""
        self._brute(cap, at, seconds, me, self.net.victim, 80, 8.0, 260, 400)

    def portal_bruteforce(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """Repeated POST /portal/login to the Pi's portal port."""
        self._brute(cap, at, seconds, me, self.net.pi, self.net.portal_port, 5.0, 240, 900)

    def slowloris(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """slowloris: 150 sockets opened as fast as it can, each trickling a header line every 10 s."""
        victim = self.net.victim
        sockets: list[tuple[int, int, int]] = []
        for i in range(150):
            t = at + i * 0.005
            sport, c_seq, s_seq = 30000 + i, self.rng.randrange(1 << 31), self.rng.randrange(1 << 31)
            cap.add(t, self.f.tcp(me.mac, PI_MAC, me.ip, victim, sport, 80, SYN, c_seq))
            cap.add(
                t + 0.001, self.f.tcp(PI_MAC, me.mac, victim, me.ip, 80, sport, SYN + ACK, s_seq, c_seq + 1)
            )
            cap.add(
                t + 0.002, self.f.tcp(me.mac, PI_MAC, me.ip, victim, sport, 80, ACK, c_seq + 1, s_seq + 1)
            )
            sockets.append((sport, c_seq + 1, s_seq + 1))
        tick = at + 10.0
        while tick < at + max(seconds, 12.0):
            for sport, c_seq, s_seq in sockets:
                cap.add(
                    tick,
                    self.f.tcp(
                        me.mac, PI_MAC, me.ip, victim, sport, 80, PSH + ACK, c_seq, s_seq, b"X-a: b\r\n"
                    ),
                )
            tick += 10.0

    def ip_spoof_neighbour(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """hping3 -S -a <neighbour> <victim>: frames from my MAC, a bound neighbour's IP."""
        self._flood(
            cap,
            at,
            seconds,
            800.0,
            lambda i: self.f.tcp(
                me.mac,
                PI_MAC,
                self.neighbour.ip,
                self.net.victim,
                1024 + i % 60000,
                80,
                SYN,
                self.rng.randrange(1 << 31),
            ),
        )

    def arp_poisoning(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """arpspoof: claim the neighbour's IP to the Pi, and the Pi's IP to the neighbour, twice a second."""
        t = at
        while t < at + seconds:
            cap.add(t, self.f.arp_reply(me.mac, self.neighbour.ip, PI_MAC, self.net.pi))
            cap.add(t + 0.01, self.f.arp_reply(me.mac, self.net.pi, self.neighbour.mac, self.neighbour.ip))
            t += 0.5

    def mac_churn(self, cap: Capture, at: float, seconds: float, me: Device) -> None:
        """Lease starvation: a new random MAC every 0.5 s, each DISCOVERs, then opens one connection."""
        del me  # every frame uses a fresh MAC; the windows name each of them
        count = max(int(seconds * 2), 20)
        for i in range(count):
            mac = "02:" + ":".join(f"{self.rng.randrange(256):02x}" for _ in range(5))
            churner = Device(f"churn{i}", mac, self.net.lan(150 + i % 90))
            t = at + i * 0.5
            cap.add(t, self.f.dhcp(mac, "discover"))
            self.benign.tcp_session(
                cap, t + 0.2, churner, WAN.network_address + 200, 443, 100, 300, segments=1
            )
            self.churned.append((mac, t, t + 0.4))


ATTACK_CLASSES: Final[tuple[str, ...]] = (
    "syn_flood_fixed",
    "syn_flood_random",
    "udp_flood_fixed",
    "udp_flood_random",
    "icmp_flood_fixed",
    "icmp_flood_random",
    "vertical_scan_t4",
    "vertical_scan_t3",
    "vertical_scan_t2",
    "horizontal_scan",
    "masscan_like",
    "ssh_bruteforce",
    "http_bruteforce",
    "portal_bruteforce",
    "slowloris",
    "ip_spoof_neighbour",
    "arp_poisoning",
    "mac_churn",
)
"""Every attack class, in file order. The label in `ground_truth.jsonl` is the class name."""

_DURATIONS: Final = {"vertical_scan_t2": 30.0, "slowloris": 25.0, "mac_churn": 20.0}
_DEFAULT_DURATION: Final = 6.0


@dataclass(frozen=True, slots=True)
class Generated:
    """What `generate` wrote."""

    pcaps: tuple[Path, ...]
    ground_truth: Path
    windows: int


def generate(out: Path, seed: int, scale: float, only: Sequence[str], config_path: Path) -> Generated:
    """Write every pcap, the ground truth and the manifest into `out` (must be empty or absent)."""
    if not 0.05 <= scale <= 10.0:
        raise LabError("--scale must be within [0.05, 10]")
    unknown = sorted(set(only) - set(ATTACK_CLASSES))
    if unknown:
        raise LabError(f"unknown attack classes {unknown}; choose from {', '.join(ATTACK_CLASSES)}")
    config = load_config(config_path)
    lab_hosts = list(config.lab.victim_network.hosts())
    net = Net(
        config.network.pirewall_lan_ip,
        config.network.protected_network,
        lab_hosts[-1],
        config.portal.listen_port,
    )
    rng = random.Random(seed)
    frames = Frames(rng)
    benign = Benign(frames, rng, net)
    devices = benign_devices(net)
    attacks = Attacks(frames, rng, net, benign, neighbour=devices[0])
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    truth: list[dict[str, object]] = []

    capture = Capture()
    benign_seconds = max(BENIGN_SECONDS * scale, 30.0)
    benign.background(capture, 0.0, benign_seconds, devices)
    path = out / "00_benign.pcap"
    capture.write(path)
    written.append(path)

    slot_start = benign_seconds + 5.0
    for index, name in enumerate(ATTACK_CLASSES):
        if only and name not in only:
            continue
        me = attacker(index, net)
        seconds = max(_DURATIONS.get(name, _DEFAULT_DURATION) * scale, 1.0)
        slot = max(SLOT_SECONDS * scale, seconds + ATTACK_OFFSET_SECONDS + 10.0)
        capture = Capture()
        benign.background(capture, slot_start, slot, devices)
        before = len(capture.frames)
        at = slot_start + ATTACK_OFFSET_SECONDS
        getattr(attacks, name)(capture, at, seconds, me)
        attack_ts = [ts for ts, _order, _frame in capture.frames[before:]]
        start_s, end_s = min(attack_ts) / 1e6, max(attack_ts) / 1e6
        pcap_name = f"{index + 1:02d}_{name}.pcap"
        if name == "mac_churn":
            for mac, first, last in attacks.churned:
                truth.append(
                    {
                        "mac": mac,
                        "start": T0_US / 1e6 + first,
                        "end": T0_US / 1e6 + last + 1.0,
                        "label": name,
                        "pcap": pcap_name,
                        "tool": TOOL,
                    }
                )
            attacks.churned.clear()
        else:
            truth.append(
                {
                    "mac": me.mac,
                    "ip": str(me.ip),
                    "start": start_s,
                    "end": end_s,
                    "label": name,
                    "pcap": pcap_name,
                    "tool": TOOL,
                }
            )
        path = out / pcap_name
        capture.write(path)
        written.append(path)
        slot_start += slot + 5.0

    ground_truth = out / "ground_truth.jsonl"
    ground_truth.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in truth), encoding="utf-8", newline="\n"
    )
    write_manifest(
        out,
        Manifest(
            # created_at is pinned so the whole directory, manifest included, is a function of the seed.
            kind="dataset",
            env_tag="mock",
            tool=TOOL,
            created_at="1970-01-01T00:00:00+00:00",
            extra={
                "seed": seed,
                "scale": scale,
                "classes": [name for name in ATTACK_CLASSES if not only or name in only],
                "benign_macs": [device.mac for device in devices],
                "pi_mac": PI_MAC,
                "network": {
                    "protected": str(net.protected),
                    "pi": str(net.pi),
                    "victim": str(net.victim),
                    "portal_port": net.portal_port,
                },
            },
        ),
    )
    return Generated(tuple(written), ground_truth, len(truth))


def _clear(out: Path) -> None:
    """Remove a previous generation: only the files this script writes, never anything else."""
    for path in out.iterdir():
        if path.is_file() and (
            path.suffix == ".pcap" or path.name in ("ground_truth.jsonl", "manifest.json")
        ):
            path.unlink()


def main(argv: Sequence[str] | None = None) -> int:
    """Exit 0 on success, 2 on a refusal."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--scale", type=float, default=1.0, help="durations x scale (rates are fixed)")
    parser.add_argument("--only", action="append", default=[], help="generate only these attack classes")
    parser.add_argument("--config", type=Path, default=REPO_ROOT / "config" / "default_config.toml")
    parser.add_argument("--force", action="store_true", help="replace a previous generation in --out")
    args = parser.parse_args(argv)
    try:
        out = check_output_location(args.out)
        if out.exists() and any(out.iterdir()):
            if not args.force:
                raise LabError(f"{out} is not empty; pass --force to replace a previous generation")
            _clear(out)
        result = generate(out, args.seed, args.scale, args.only, args.config)
    except LabError as exc:
        print(f"gen_pcaps: {exc}", file=sys.stderr)
        return 2
    print(
        f"wrote {len(result.pcaps)} pcaps and {result.windows} ground-truth windows to {out} (env tag mock)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

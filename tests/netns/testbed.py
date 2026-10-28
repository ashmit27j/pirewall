"""The v2 netns testbed, in Python (ported from docs/v2/v2/netns_testbed.sh; env=sandbox).

Topology (every namespace prefixed `pw_`), unchanged from the sandbox run:

    pw_a (attacker .20, 02:..:20) -+
    pw_l (legit    .10, 02:..:10) -+- br0 in pw_sw -- lan0 -+
    pw_w (allowed  .30, 02:..:30) -+   192.168.100.0/24     |
                                                           pw_r (router: base +
    pw_ad (admin 192.168.101.2, 02:..:02) -- adm0 ---------+    pirewall_static + adaptive)
    pw_v (victim 10.99.0.2, WAN side) ------- wan0 --------+

What changed from the sandbox script, on purpose:

* The rulesets are rendered from the **deployed** templates
  (`deploy/firewall/`) by **our** renderer (`render_templates.py`) from a
  real `PirewallConfig`, not by `docs/v2/v2/render.py`.
* Bindings and the allowlist are seeded through `NftablesSetBackend`, the
  path `FirewallManager.sync_bindings` will use in phase 14.
* The router's ruleset is driven by `FirewallManager` + `NftablesSetBackend`
  running *inside* `pw_r` (`in_namespace`), so both transports really hit
  the namespace's kernel tables. Nothing here touches the host's own
  network namespace or ruleset.

The router's kernel `rp_filter` is off, so nft has to catch spoofing itself.
"""

import contextlib
import json
import os
import shlex
import shutil
import subprocess
import time
from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from scripts.deployment.render_templates import render_template

from pirewall.config.models import PirewallConfig
from tests.helpers.config import make_config

REPO = Path(__file__).resolve().parents[2]
SVC = Path(__file__).resolve().parent / "svc.py"
NAMESPACES = ("pw_r", "pw_sw", "pw_a", "pw_l", "pw_w", "pw_v", "pw_ad")
MAC = {
    "a": "02:00:00:00:00:20",
    "l": "02:00:00:00:00:10",
    "w": "02:00:00:00:00:30",
    "ad": "02:00:00:00:00:02",
}
IP = {
    "a": "192.168.100.20",
    "l": "192.168.100.10",
    "w": "192.168.100.30",
    "r": "192.168.100.1",
    "v": "10.99.0.2",
    "adm_r": "192.168.101.1",
    "ad": "192.168.101.2",
}
ROUTER_LAN_MAC = "02:00:00:00:01:01"
ST = "inet pirewall_static"
AD = "inet pirewall_adaptive"
KERNEL_SETS = (
    "dhcp_meter",
    "unbound_meter",
    "syn_meter",
    "udp_meter",
    "icmp_meter",
    "pps_meter",
    "dns_meter",
    "closed_meter",
    "portal_conc",
    "newconn_meter",
    "newconn_dst_meter",
    "udp_fwd_meter",
    "offenders",
    "unbound_seen",
)
_CLONE_NEWNET = 0x40000000
# The system interpreter (it has scapy). Under `uv run`, a bare `python3` on
# PATH is the venv's, which has neither scapy nor anything the clients need.
SYSTEM_PYTHON = "/usr/bin/python3"
_SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def tools_missing() -> list[str]:
    """What this host lacks for the netns tier (empty when it can run)."""
    missing = [tool for tool in ("ip", "nft", "hping3", "curl", "conntrack") if shutil.which(tool) is None]
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        missing.append("root")
    if not hasattr(os, "setns"):
        missing.append("os.setns")
    if (
        not Path(SYSTEM_PYTHON).is_file()
        or subprocess.run([SYSTEM_PYTHON, "-c", "import scapy"], capture_output=True, check=False).returncode
    ):
        missing.append(f"{SYSTEM_PYTHON} with scapy")
    return missing


def testbed_config() -> PirewallConfig:
    """The router's config: the sandbox topology, with the sandbox's test-only threshold overrides.

    Lower than production so a ~10k pps hping3 trips them
    (docs/v2/v2/RESULTS.md: FORWARD_VERDICT=drop UDP_FWD_PPS=2000
    UDP_FWD_BURST=4000 METER_SIZE=64 GLOBAL_UNBOUND_PPS=200 GLOBAL_SYN_PPS=500).
    """
    return make_config(
        network={
            "wan_interface": "wan0",
            "lan_interface": "lan0",
            "admin_interface": "adm0",
            "protected_network": "192.168.100.0/24",
            "upstream_gateway": "10.99.0.254",
            "pirewall_lan_ip": IP["r"],
        },
        capture={"interface": "lan0"},
        admin={"admin_pc_ip": IP["ad"], "admin_pc_mac": MAC["ad"]},
        api={"port": 8443},
        portal={"listen_port": 8080, "listen_host": IP["r"]},
        firewall={"enforcement_mode": "active"},
        guards={
            "forward_mode": "enforce",
            "udp_fwd": {"rate": 2000, "burst": 4000},
            "meter_set_size": 64,
            "global_unbound": {"rate": 200, "burst": 1000},
            "global_syn": {"rate": 500, "burst": 4000},
        },
    )


def sh(ns: str, command: str, timeout: float = 120, check: bool = False) -> subprocess.CompletedProcess[str]:
    """Run `command` in namespace `ns` (bash -c), with the system PATH so `python3` is `SYSTEM_PYTHON`."""
    return subprocess.run(
        ["ip", "netns", "exec", ns, "env", f"PATH={_SYSTEM_PATH}", "bash", "-c", command],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def nft(command: str) -> str:
    """`nft <command>` in the router namespace. Test scaffolding only: core writes go through the backend."""
    return sh("pw_r", f"nft {command}", check=True).stdout


def nft_batch(text: str, state: Path) -> None:
    path = state / "batch.nft"
    path.write_text(text, encoding="utf-8")
    result = sh("pw_r", f"nft -f {path}")
    if result.returncode:
        raise RuntimeError(result.stderr)


def counter(table: str, name: str) -> int:
    data = json.loads(nft(f"-j list counter {table} {name}"))
    for item in data["nftables"]:
        if "counter" in item:
            return int(item["counter"]["packets"])
    raise KeyError(name)


def elems(table: str, name: str) -> list[Any]:  # Any: nft JSON element values are str or concat tuples
    data: Any = json.loads(nft(f"-j list set {table} {name}"))  # Any: parsed nft JSON
    for item in data["nftables"]:
        if "set" in item:
            out: list[Any] = []
            raw: list[Any] = item["set"].get("elem", [])
            for element in raw:
                value: Any = element
                if isinstance(value, dict) and "elem" in value:
                    value = cast("dict[str, Any]", value)["elem"]["val"]
                if isinstance(value, dict) and "concat" in value:
                    value = tuple(cast("dict[str, list[Any]]", value)["concat"])
                out.append(value)
            return out
    return []


def offender_codes(mac: str) -> set[int]:
    pairs = [cast("tuple[str, int]", e) for e in elems(ST, "offenders") if isinstance(e, tuple)]
    return {int(code) for owner, code in pairs if owner == mac}


def accusatory_sets_holding(mac: str) -> list[str]:
    """Sets that *accuse* `mac`. Meter sets hold every source seen, so they are not accusations."""
    hits = [
        name
        for name in ("offenders", "unbound_seen")
        if any(mac in (e if isinstance(e, tuple) else (e,)) for e in elems(ST, name))
    ]
    hits += [name for name in ("block_mac", "ratelimit_mac") if mac in elems(AD, name)]
    return hits


def hping(ns: str, args: str, timeout: float = 90) -> str:
    return sh(ns, f"hping3 {args} 2>&1", timeout=timeout).stdout


def curl_ok(ns: str, url: str) -> bool:
    out = sh(ns, f"curl -s -m 3 -o /dev/null -w '%{{http_code}}' {url}")
    return out.stdout.strip() == "200"


def scapy(ns: str, program: str, timeout: float = 300) -> None:
    """Run a scapy program with the system python in `ns` (`from scapy.all import *` is prepended)."""
    script = shlex.quote("from scapy.all import *\n" + program)
    result = sh(ns, f"python3 -c {script}", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"scapy in {ns} failed: {result.stderr.strip()[-2000:]}")


@contextlib.contextmanager
def in_namespace(name: str) -> Generator[None]:
    """Move this thread into network namespace `name` and back. Subprocesses inherit it."""
    original = os.open("/proc/self/ns/net", os.O_RDONLY)
    target = os.open(f"/var/run/netns/{name}", os.O_RDONLY)
    try:
        os.setns(target, _CLONE_NEWNET)  # pyright: ignore[reportAttributeAccessIssue]
        yield
    finally:
        os.setns(original, _CLONE_NEWNET)  # pyright: ignore[reportAttributeAccessIssue]
        os.close(target)
        os.close(original)


@dataclass
class Testbed:
    """A running testbed. `up()` builds it; `down()` removes every namespace it made."""

    __test__ = False  # not a pytest test class, despite the name

    state: Path
    config: PirewallConfig = field(default_factory=testbed_config)
    _services: list[subprocess.Popen[bytes]] = field(default_factory=list[subprocess.Popen[bytes]])

    def up(self) -> None:
        self.down()
        self.state.mkdir(parents=True, exist_ok=True)
        run = _run
        for ns in NAMESPACES:
            run("ip", "netns", "add", ns)
            run("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")

        def x(ns: str, *command: str) -> None:
            run("ip", "netns", "exec", ns, *command)

        x("pw_sw", "ip", "link", "add", "br0", "type", "bridge")
        x("pw_sw", "ip", "link", "set", "br0", "up")
        run(
            "ip",
            "link",
            "add",
            "lan0",
            "netns",
            "pw_r",
            "type",
            "veth",
            "peer",
            "name",
            "p_r",
            "netns",
            "pw_sw",
        )
        for client, octet in (("a", "20"), ("l", "10"), ("w", "30")):
            run(
                "ip", "link", "add", "eth0", "netns", f"pw_{client}", "address", f"02:00:00:00:00:{octet}",
                "type", "veth", "peer", "name", f"p_{client}", "netns", "pw_sw",
            )  # fmt: skip
            x(
                f"pw_{client}",
                "ip",
                "addr",
                "add",
                f"192.168.100.{octet}/24",
                "brd",
                "192.168.100.255",
                "dev",
                "eth0",
            )
            x(f"pw_{client}", "ip", "link", "set", "eth0", "up")
            x(f"pw_{client}", "ip", "route", "add", "default", "via", IP["r"])
            x("pw_sw", "ip", "link", "set", f"p_{client}", "master", "br0", "up")
        x("pw_sw", "ip", "link", "set", "p_r", "master", "br0", "up")
        x("pw_r", "ip", "link", "set", "lan0", "address", ROUTER_LAN_MAC)
        x("pw_r", "ip", "addr", "add", f"{IP['r']}/24", "brd", "192.168.100.255", "dev", "lan0")
        x("pw_r", "ip", "link", "set", "lan0", "up")
        run(
            "ip",
            "link",
            "add",
            "wan0",
            "netns",
            "pw_r",
            "type",
            "veth",
            "peer",
            "name",
            "eth0",
            "netns",
            "pw_v",
        )
        x("pw_r", "ip", "addr", "add", "10.99.0.1/24", "dev", "wan0")
        x("pw_r", "ip", "link", "set", "wan0", "up")
        x("pw_v", "ip", "addr", "add", f"{IP['v']}/24", "dev", "eth0")
        x("pw_v", "ip", "link", "set", "eth0", "up")
        run(
            "ip", "link", "add", "adm0", "netns", "pw_r", "type", "veth", "peer", "name", "eth0",
            "netns", "pw_ad", "address", MAC["ad"],
        )  # fmt: skip
        x("pw_r", "ip", "addr", "add", f"{IP['adm_r']}/24", "dev", "adm0")
        x("pw_r", "ip", "link", "set", "adm0", "up")
        x("pw_ad", "ip", "addr", "add", f"{IP['ad']}/24", "dev", "eth0")
        x("pw_ad", "ip", "link", "set", "eth0", "up")
        x("pw_ad", "ip", "route", "add", "default", "via", IP["adm_r"])
        x("pw_r", "sysctl", "-qw", "net.ipv4.ip_forward=1")
        for key in ("all", "default", "lan0", "wan0", "adm0"):
            x("pw_r", "sysctl", "-qw", f"net.ipv4.conf.{key}.rp_filter=0")
        nat = self.state / "nat.nft"
        nat.write_text(
            "table ip nat_shared {\n chain post {\n  type nat hook postrouting priority 100; policy accept;\n"
            '  oifname "wan0" masquerade\n }\n}\n',
            encoding="utf-8",
        )
        x("pw_r", "nft", "-f", str(nat))
        self._start_services()
        time.sleep(1.0)
        self.load()

    def _start_services(self) -> None:
        svc = [SYSTEM_PYTHON, str(SVC)]
        specs: list[tuple[str, list[str]]] = [
            ("pw_r", [*svc, "udp-echo", IP["r"], "53", str(self.state / "r_udp53")]),
            ("pw_r", [SYSTEM_PYTHON, "-m", "http.server", "8080", "--bind", "0.0.0.0"]),
            ("pw_r", [SYSTEM_PYTHON, "-m", "http.server", "8443", "--bind", IP["adm_r"]]),
            ("pw_v", [SYSTEM_PYTHON, "-m", "http.server", "80", "--bind", IP["v"]]),
            ("pw_v", [*svc, "udp-echo", IP["v"], "9999", str(self.state / "v_udp9999")]),
            ("pw_v", [*svc, "udp-echo", IP["v"], "53", str(self.state / "v_udp53")]),
            ("pw_v", [*svc, "tcp-listen", IP["v"], "853", str(self.state / "v_tcp853")]),
        ]
        for ns, command in specs:
            self._services.append(
                subprocess.Popen(
                    ["ip", "netns", "exec", ns, *command],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )

    def render(self) -> dict[str, Path]:
        """Render base, static and adaptive from the deployed templates with our renderer."""
        paths: dict[str, Path] = {}
        for stem in ("base", "pirewall_static", "pirewall_adaptive"):
            text = (REPO / "deploy" / "firewall" / f"{stem}.nft.template").read_text(encoding="utf-8")
            path = self.state / f"{stem}.nft"
            path.write_text(render_template(text, self.config), encoding="utf-8")
            paths[stem] = path
        return paths

    def load(self) -> None:
        """What `pirewall-start` does: load base, then static, then adaptive (never `delete table`)."""
        for path in self.render().values():
            _run("ip", "netns", "exec", "pw_r", "nft", "-f", str(path))
        observation = self.state / "obs.nft"
        observation.write_text(_OBSERVATION_TABLE, encoding="utf-8")
        sh("pw_r", "nft delete table inet obs 2>/dev/null; true")
        _run("ip", "netns", "exec", "pw_r", "nft", "-f", str(observation))

    def reset(self) -> None:
        """Flush kernel meter state and adaptive sets, zero counters, flush conntrack (test scaffolding)."""
        batch = "".join(f"flush set {ST} {name}\n" for name in KERNEL_SETS)
        batch += "".join(
            f"flush set {AD} {name}\n"
            for name in ("rl_meter", "rl4_meter", "block_mac", "block4", "ratelimit_mac", "ratelimit4")
        )
        nft_batch(batch, self.state)
        sh("pw_r", "nft reset counters >/dev/null; conntrack -F 2>/dev/null; true")

    def readcount(self, name: str) -> int:
        try:
            return int((self.state / name).read_text(encoding="ascii") or 0)
        except (FileNotFoundError, ValueError):
            return 0

    def down(self) -> None:
        for process in self._services:
            process.kill()
        self._services.clear()
        for ns in NAMESPACES:
            pids = subprocess.run(
                ["ip", "netns", "pids", ns], capture_output=True, text=True, check=False
            ).stdout
            for pid in pids.split():
                with contextlib.suppress(ProcessLookupError, ValueError, PermissionError):
                    os.kill(int(pid), 9)
            subprocess.run(["ip", "netns", "del", ns], capture_output=True, check=False)


def _run(*command: str) -> None:
    subprocess.run(list(command), check=True, capture_output=True)


_OBSERVATION_TABLE = """table inet obs {
	chain in { type filter hook input priority 100; policy accept;
		tcp dport 8080 tcp flags & (syn|ack) == syn counter name syn8080
		udp dport 53 counter name udp53_in
		udp dport 67 counter name dhcp67_in
		tcp dport 8443 counter name api8443_in
	}
	chain forward_obs { type filter hook forward priority 100; policy accept;
		ip daddr 10.99.0.2 tcp dport 80 tcp flags & (syn|ack) == syn counter name syn_victim
	}
	counter syn8080 { }
	counter udp53_in { }
	counter dhcp67_in { }
	counter api8443_in { }
	counter syn_victim { }
}
"""

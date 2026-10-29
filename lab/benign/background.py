"""Scripted benign traffic from a LAN client device, with ground truth (pi-scripted, PLAN_v3 §4).

    python3 lab/benign/background.py --profile mixed --env-tag pi-scripted [--mac MAC] \\
        [--duration 3600] [--segment 300] [--victim 10.250.0.2] [--sites FILE] \\
        [--download-url URL] [--out lab/runs]
    python3 lab/benign/background.py --profile probe --client-kind wifi --stdout [--victim IP]

Runs **on the client devices** (laptops, the Kali box between campaigns),
not on the Pi, so it is **stdlib only**: copy the `lab/` directory over and
run it with any Python 3.12+. External tools are optional and detected
(`iperf3`); nothing is installed.

Profiles:

* `web`: page loads (`urllib`, HTTPS) over a top-sites list, with think time.
* `video`: one long, steady download, read in chunks (a stream).
* `update`: large downloads back to back (`--download-url`).
* `dns-burst`: bursts of lookups for many names, as a phone waking up does.
* `idle`: one SNTP query a minute, nothing else.
* `iperf`: `iperf3 -c <victim>` (the lab victim, through the forward path).
* `mixed`: the above in turn, one `--segment` each, for `--duration`.
* `probe`: the legitimate-client probe a campaign runs during each attack
  (`lab/run_campaign.py --legit-client`): every second, one HTTP GET of the
  victim (`http_ms`) and, with `iperf3`, one second of throughput
  (`throughput_mbps`), as JSON lines `{"t", "client", "kind", "value"}` on
  stdout. Failures are recorded as `value: null`, never dropped.

**Ground truth.** Each segment appends one window to
`<run>/ground_truth.jsonl`: `{"mac", "start", "end", "label":
"benign:<profile>", "host"}`, Unix seconds from this device's clock (keep
it synced; the campaign preflight records chrony offsets). The format is
what `scripts/dataset/pcap_to_flows.py --ground-truth` reads. The run
directory is sealed (`kind = "scripted-benign"`).

**Env tag.** `--env-tag` is required and never defaults (D7). The pi-*
host check of the other lab scripts does not apply: this device is not
the Pi, and the tag names the data set the Pi's capture of this traffic
belongs to. The Pi-side capture is checked when it is sealed.
"""

import argparse
import contextlib
import json
import random
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol, TextIO

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # `python3 lab/benign/background.py`

from lab.common import REPO_ROOT, LabError, new_run_dir
from lab.manifest import ENV_TAGS, Json, Manifest, write_manifest

TOOL: Final = "lab/benign/background.py"
PROFILES: Final = ("web", "video", "update", "dns-burst", "idle", "iperf", "mixed", "probe")
MIXED_ORDER: Final = ("web", "dns-burst", "video", "idle", "update", "iperf")
DEFAULT_SITES: Final = (
    "www.wikipedia.org",
    "www.debian.org",
    "www.python.org",
    "www.kernel.org",
    "www.raspberrypi.com",
    "www.gnu.org",
    "www.mozilla.org",
    "www.openstreetmap.org",
    "news.ycombinator.com",
    "www.bbc.co.uk",
    "www.github.com",
    "www.cloudflare.com",
    "www.apache.org",
    "www.rust-lang.org",
    "www.ietf.org",
)
DEFAULT_DOWNLOAD: Final = "https://deb.debian.org/debian/ls-lR.gz"
NTP_SERVER: Final = "pool.ntp.org"


class Network(Protocol):
    """The traffic a profile makes. `RealNetwork` does it; tests pass a fake."""

    def fetch(self, url: str, limit_bytes: int | None, deadline: float) -> int: ...
    def resolve(self, name: str) -> bool: ...
    def ntp(self, server: str) -> bool: ...
    def iperf(self, server: str, seconds: float) -> float | None: ...


@dataclass(slots=True)
class RealNetwork:
    """Plain stdlib traffic. Every call is bounded by a timeout; failures return, never raise."""

    timeout: float = 10.0

    def fetch(self, url: str, limit_bytes: int | None, deadline: float) -> int:
        """GET `url`, reading until EOF, `limit_bytes` or the monotonic `deadline`. Bytes read."""
        read = 0
        try:
            context = ssl.create_default_context()
            request = urllib.request.Request(url, headers={"User-Agent": "pirewall-lab-benign/1"})
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as reply:
                while time.monotonic() < deadline and (limit_bytes is None or read < limit_bytes):
                    chunk = reply.read(65536)
                    if not chunk:
                        break
                    read += len(chunk)
        except (OSError, ValueError):
            pass
        return read

    def resolve(self, name: str) -> bool:
        """One lookup through the system resolver (the Pi's DNS)."""
        try:
            socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
        except OSError:
            return False
        return True

    def ntp(self, server: str) -> bool:
        """One SNTP v4 client query."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.sendto(b"\x23" + b"\x00" * 47, (server, 123))
                data, _peer = sock.recvfrom(512)
                return len(data) >= 48 and struct.unpack("!B", data[:1])[0] & 0x07 == 4
        except OSError:
            return False

    def iperf(self, server: str, seconds: float) -> float | None:
        """Mbit/s received from `iperf3 -c server -R -t seconds`, or None without iperf3 or on failure."""
        if shutil.which("iperf3") is None:
            return None
        try:
            done = subprocess.run(
                ["iperf3", "-c", server, "-R", "-J", "-t", f"{max(seconds, 1.0):g}"],
                capture_output=True,
                text=True,
                timeout=seconds + 15,
                check=False,
            )
            report = json.loads(done.stdout)
            return float(report["end"]["sum_received"]["bits_per_second"]) / 1e6
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
            return None


@dataclass(slots=True)
class Context:
    """What every profile gets."""

    net: Network
    rng: random.Random
    sites: Sequence[str]
    download_url: str
    victim: str | None
    clock: Callable[[], float] = time.time
    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    counts: dict[str, int] = field(default_factory=dict[str, int])

    def count(self, what: str, n: int = 1) -> None:
        """Tally one action, for the run manifest."""
        self.counts[what] = self.counts.get(what, 0) + n


def _until(ctx: Context, seconds: float) -> Iterator[float]:
    """Yield the remaining time until `seconds` have passed."""
    end = ctx.monotonic() + seconds
    while (left := end - ctx.monotonic()) > 0:
        yield left


def web(ctx: Context, seconds: float) -> None:
    """Page loads with think time."""
    for left in _until(ctx, seconds):
        site = ctx.rng.choice(list(ctx.sites))
        ctx.net.resolve(site)
        ctx.net.fetch(f"https://{site}/", 2_000_000, ctx.monotonic() + min(left, 15.0))
        ctx.count("page_loads")
        ctx.sleep(min(ctx.rng.uniform(2.0, 12.0), max(left, 0.0)))


def video(ctx: Context, seconds: float) -> None:
    """One long download, read as a stream."""
    for left in _until(ctx, seconds):
        ctx.count("stream_bytes", ctx.net.fetch(ctx.download_url, None, ctx.monotonic() + left))
        ctx.sleep(min(1.0, max(left, 0.0)))


def update(ctx: Context, seconds: float) -> None:
    """Large downloads back to back."""
    for left in _until(ctx, seconds):
        ctx.count("download_bytes", ctx.net.fetch(ctx.download_url, 200_000_000, ctx.monotonic() + left))
        ctx.count("downloads")


def dns_burst(ctx: Context, seconds: float) -> None:
    """A burst of 20-60 lookups every 10-40 s."""
    for left in _until(ctx, seconds):
        for _ in range(ctx.rng.randint(20, 60)):
            ctx.net.resolve(ctx.rng.choice(list(ctx.sites)))
            ctx.count("lookups")
        ctx.sleep(min(ctx.rng.uniform(10.0, 40.0), max(left, 0.0)))


def idle(ctx: Context, seconds: float) -> None:
    """One SNTP query a minute."""
    for left in _until(ctx, seconds):
        ctx.net.ntp(NTP_SERVER)
        ctx.count("ntp_queries")
        ctx.sleep(min(60.0, max(left, 0.0)))


def iperf(ctx: Context, seconds: float) -> None:
    """iperf3 to the lab victim in 10 s pieces; idles when there is no victim or no iperf3."""
    for left in _until(ctx, seconds):
        result = ctx.net.iperf(ctx.victim, min(10.0, left)) if ctx.victim else None
        if result is None:
            ctx.sleep(min(10.0, max(left, 0.0)))
        else:
            ctx.count("iperf_runs")


RUNNERS: Final[dict[str, Callable[[Context, float], None]]] = {
    "web": web,
    "video": video,
    "update": update,
    "dns-burst": dns_burst,
    "idle": idle,
    "iperf": iperf,
}


def segments(profile: str, duration: float, segment: float) -> list[tuple[str, float]]:
    """The (profile, seconds) plan. `mixed` cycles `MIXED_ORDER`."""
    plan: list[tuple[str, float]] = []
    remaining = duration
    index = 0
    while remaining > 0:
        length = min(segment, remaining)
        name = MIXED_ORDER[index % len(MIXED_ORDER)] if profile == "mixed" else profile
        plan.append((name, length))
        remaining -= length
        index += 1
    return plan


def run_profile(
    ctx: Context, profile: str, duration: float, segment: float, mac: str, host: str, truth: TextIO
) -> int:
    """Run the plan, one ground-truth window per segment. Returns the number of windows."""
    windows = 0
    for name, seconds in segments(profile, duration, segment):
        start = ctx.clock()
        RUNNERS[name](ctx, seconds)
        truth.write(
            json.dumps(
                {"mac": mac, "start": start, "end": ctx.clock(), "label": f"benign:{name}", "host": host},
                sort_keys=True,
            )
            + "\n"
        )
        truth.flush()
        windows += 1
    return windows


def probe(ctx: Context, client: str, out: TextIO, seconds: float | None) -> int:
    """The legitimate-client probe: one sample of each kind a second. Returns samples written."""
    url = f"http://{ctx.victim}/" if ctx.victim else f"https://{ctx.sites[0]}/"
    written = 0
    end = None if seconds is None else ctx.monotonic() + seconds
    while end is None or ctx.monotonic() < end:
        tick = ctx.monotonic()
        started = ctx.monotonic()
        got = ctx.net.fetch(url, 1_000_000, started + 2.0)
        http_ms: float | None = (ctx.monotonic() - started) * 1000.0 if got > 0 else None
        samples: list[tuple[str, float | None]] = [("http_ms", http_ms)]
        if ctx.victim:
            samples.append(("throughput_mbps", ctx.net.iperf(ctx.victim, 1.0)))
        for kind, value in samples:
            out.write(json.dumps({"t": ctx.clock(), "client": client, "kind": kind, "value": value}) + "\n")
            written += 1
        out.flush()
        ctx.sleep(max(0.0, 1.0 - (ctx.monotonic() - tick)))
    return written


def local_mac() -> str | None:
    """The MAC of the interface holding the default route (Linux only), else None."""
    try:
        for line in Path("/proc/net/route").read_text(encoding="utf-8").splitlines()[1:]:
            fields = line.split()
            if len(fields) > 2 and fields[1] == "00000000":
                return Path(f"/sys/class/net/{fields[0]}/address").read_text(encoding="utf-8").strip().lower()
    except OSError:
        return None
    return None


def main(argv: Sequence[str] | None = None) -> int:
    """0 when the run completed (or was interrupted and sealed), 2 on a refusal."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument(
        "--env-tag", choices=ENV_TAGS, help="required except for --profile probe (no default)"
    )
    parser.add_argument("--mac", help="this device's LAN MAC (default: the default-route interface's, Linux)")
    parser.add_argument("--duration", type=float, default=3600.0)
    parser.add_argument("--segment", type=float, default=300.0, help="seconds per ground-truth window")
    parser.add_argument("--victim", help="the lab victim's IP (iperf3, probe)")
    parser.add_argument("--sites", type=Path, help="one host name per line (default: a built-in list)")
    parser.add_argument("--download-url", default=DEFAULT_DOWNLOAD)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "lab" / "runs")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--client-kind", choices=("wired", "wifi"), default="wifi", help="probe only")
    parser.add_argument("--stdout", action="store_true", help="probe only: samples to stdout")
    args = parser.parse_args(argv)
    sites = DEFAULT_SITES
    if args.sites is not None:
        sites = tuple(
            line.strip() for line in args.sites.read_text(encoding="utf-8").splitlines() if line.strip()
        )
    ctx = Context(RealNetwork(), random.Random(args.seed), sites, args.download_url, args.victim)
    if args.profile == "probe":
        with contextlib.suppress(KeyboardInterrupt):
            probe(ctx, args.client_kind, sys.stdout, None if args.stdout else args.duration)
        return 0
    try:
        if args.env_tag is None:
            raise LabError("--env-tag is required (pi-scripted for the Pi campaign data; never defaulted)")
        mac = (args.mac or local_mac() or "").lower()
        if not mac:
            raise LabError("cannot find this device's MAC; pass --mac")
        run_dir = new_run_dir(args.out, f"scripted-{args.profile}")
    except LabError as exc:
        print(f"background: {exc}", file=sys.stderr)
        return 2
    host = socket.gethostname()
    windows = 0
    with (run_dir / "ground_truth.jsonl").open("w", encoding="utf-8", newline="\n") as truth:
        try:
            windows = run_profile(ctx, args.profile, args.duration, args.segment, mac, host, truth)
        except KeyboardInterrupt:
            print("interrupted; sealing what ran", file=sys.stderr)
    extra: dict[str, Json] = {
        "profile": args.profile,
        "mac": mac,
        "host": host,
        "windows": windows,
        "counts": dict[str, Json](ctx.counts),
        "victim": args.victim,
    }
    write_manifest(
        run_dir,
        Manifest(
            kind="scripted-benign",
            env_tag=args.env_tag,
            tool=TOOL,
            extra=extra,
            tool_versions={"iperf3": "present" if shutil.which("iperf3") else "missing"},
        ),
    )
    print(f"{windows} ground-truth windows -> {run_dir / 'ground_truth.jsonl'} (env tag {args.env_tag})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

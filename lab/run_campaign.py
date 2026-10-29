"""Run an attack campaign on the Pi: randomised runs, victim capture, polling, cooldown (PLAN_FINAL §5).

    sudo uv run python lab/run_campaign.py lab/campaigns/dev.toml --attacker kali@10.0.0.50 \\
        --attacker-ip 192.168.4.66 --attacker-mac 02:..:66 [--legit-client user@host --legit-kind wifi] \\
        [--param neighbour_ip=192.168.4.21 --param attacker_iface=eth0 --param wordlist=/path ...] \\
        [--config config/local_config.toml] [--start-manifest /var/lib/pirewall/manifest.json] \\
        [--out lab/runs] [--dry-run]

**Per run**, in the campaign's seeded random order:

1. start the victim-side capture (`lab/capture.sh start --side input|forward`);
2. start the legitimate-client probe (`lab/benign/background.py --profile
   probe` over SSH on `--legit-client`), if given;
3. poll core read-only every second into `poll.jsonl` (`lab/poll_state.py`);
4. after `pre_attack_seconds`, mark `t_start` and trigger the attack on the
   attacker host over SSH (`bash <attacker-lab-dir>/attacks/<script> ...`;
   the script itself refuses any target outside the lab);
5. mark `t_end` when it exits, keep polling `post_attack_seconds`, stop
   everything, write `ground_truth.jsonl` and `attack.log`, and seal the
   run directory (`kind = "run"`);
6. **cool down** until core shows no live RATE_LIMIT/BLOCK rule and an empty
   `@offenders` for `cooldown_quiet_polls` polls in a row. It only polls:
   it never flushes a set and never uses the kill switch. If the sets do not
   drain within `cooldown_timeout_seconds` the campaign stops.

**Env tag** comes from `pirewall-start`'s manifest (its `--data-mode`), not
from a flag, and a `pi-*` tag is refused off a Pi (`lab.common.require_env_tag`).
**`phase = "eval"`** refuses to start unless the D1 thresholds file is
frozen (`lab/verify_manifest.py`'s check), and records the thresholds and
policy-table hashes in every run manifest.

`--dry-run` prints the run order and every command, touches nothing and
needs no root. Everything with a side effect (SSH, capture, probe, core
reads, the clock) is injected, so `tests/unit/test_lab_run_campaign.py`
runs the real loop against fakes.
"""

import argparse
import json
import random
import re
import shlex
import subprocess
import sys
import threading
import time
import tomllib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import IO, Final, Literal, Protocol, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # `python lab/run_campaign.py`

from lab.common import REPO_ROOT, LabError, Provenance, new_run_dir, project_provenance, require_env_tag
from lab.manifest import Json, Manifest, git_state, write_manifest
from lab.poll_state import CoreReader, Poller, ReadOnlyCore, sets_empty
from lab.verify_manifest import frozen_thresholds_problem

TOOL: Final = "lab/run_campaign.py"
ATTACKS_DIR: Final = Path(__file__).resolve().parent / "attacks"
DEFAULT_START_MANIFEST: Final = Path("/var/lib/pirewall/manifest.json")

Side = Literal["input", "forward"]


# ------------------------------------------------------------------ spec


@dataclass(frozen=True, slots=True)
class AttackSpec:
    """One `[[attack]]` table."""

    id: str
    script: str
    runs: int
    target: str
    side: Side
    duration: float
    offered_rate_pps: float | None
    args: tuple[str, ...]
    victim_filter: dict[str, Json]


@dataclass(frozen=True, slots=True)
class CampaignSpec:
    """A campaign file (`lab/campaigns/*.toml`)."""

    name: str
    phase: Literal["dev", "eval"]
    seed: int
    attacks: tuple[AttackSpec, ...]
    pre_attack_seconds: float = 10.0
    post_attack_seconds: float = 30.0
    cooldown_poll_seconds: float = 2.0
    cooldown_quiet_polls: int = 3
    cooldown_timeout_seconds: float = 900.0
    source: str = ""


def load_campaign(path: Path) -> CampaignSpec:
    """Read and check a campaign file. Raises `LabError`."""
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise LabError(f"{path}: {exc}") from exc
    phase = raw.get("phase")
    if phase not in ("dev", "eval"):
        raise LabError(f'{path}: phase must be "dev" or "eval"')
    attacks: list[AttackSpec] = []
    for item in raw.get("attack", []):
        script = str(item["script"])
        if "/" in script or not (ATTACKS_DIR / script).is_file():
            raise LabError(f"{path}: attack {item.get('id')!r}: no script lab/attacks/{script}")
        side = item.get("side", "forward")
        if side not in ("input", "forward"):
            raise LabError(f"{path}: attack {item.get('id')!r}: side must be input or forward")
        rate = item.get("offered_rate_pps")
        attacks.append(
            AttackSpec(
                id=str(item["id"]),
                script=script,
                runs=int(item["runs"]),
                target=str(item["target"]),
                side=side,
                duration=float(item["duration"]),
                offered_rate_pps=None if rate is None else float(rate),
                args=tuple(str(arg) for arg in item.get("args", [])),
                victim_filter=dict(item.get("victim_filter", {})),
            )
        )
    if not attacks:
        raise LabError(f"{path}: no [[attack]] tables")
    ids = [attack.id for attack in attacks]
    if len(set(ids)) != len(ids):
        raise LabError(f"{path}: attack ids must be unique")
    defaults = CampaignSpec("", "dev", 0, ())
    return CampaignSpec(
        name=str(raw.get("name", path.stem)),
        phase=phase,
        seed=int(raw["seed"]),
        attacks=tuple(attacks),
        pre_attack_seconds=float(raw.get("pre_attack_seconds", defaults.pre_attack_seconds)),
        post_attack_seconds=float(raw.get("post_attack_seconds", defaults.post_attack_seconds)),
        cooldown_poll_seconds=float(raw.get("cooldown_poll_seconds", defaults.cooldown_poll_seconds)),
        cooldown_quiet_polls=int(raw.get("cooldown_quiet_polls", defaults.cooldown_quiet_polls)),
        cooldown_timeout_seconds=float(
            raw.get("cooldown_timeout_seconds", defaults.cooldown_timeout_seconds)
        ),
        source=path.read_text(encoding="utf-8"),
    )


_PLACEHOLDER: Final = re.compile(r"\{([a-z_]+)\}")


def expand_args(args: Sequence[str], params: Mapping[str, str]) -> list[str]:
    """`args` with every `{name}` replaced from `params`. Raises `LabError` naming a missing one.

    Campaign files are shared between labs, so the lab-specific values (a
    bound neighbour's IP, the attacker's interface, a wordlist path) are
    placeholders, filled from `--param name=value` and from the Pi's config
    (`pi_ip`, `victim_net`, `victim_ip`, `protected_net`).
    """
    expanded: list[str] = []
    for arg in args:
        missing = sorted({name for name in _PLACEHOLDER.findall(arg) if name not in params})
        if missing:
            raise LabError(f"campaign argument {arg!r} needs --param {missing[0]}=VALUE")
        expanded.append(_PLACEHOLDER.sub(lambda match: params[match.group(1)], arg))
    return expanded


def parse_params(items: Sequence[str]) -> dict[str, str]:
    """`--param name=value` flags. Raises `LabError`."""
    params: dict[str, str] = {}
    for item in items:
        name, sep, value = item.partition("=")
        if not sep or not re.fullmatch(r"[a-z_]+", name) or not value:
            raise LabError(f"--param {item!r}: expected name=value (name in [a-z_])")
        params[name] = value
    return params


def victim_filter(attack: AttackSpec, attacker_ip: str | None, params: Mapping[str, str]) -> dict[str, Json]:
    """What `score_run.py` counts as attack packets at the victim.

    The attacker's source IP unless the campaign sets `src = "any"` (random-source
    floods) or another address (a spoofed neighbour, as a placeholder), plus the
    campaign's protocol and port.
    """
    wanted: dict[str, Json] = {"src": attacker_ip}
    for key, value in attack.victim_filter.items():
        wanted[key] = expand_args([value], params)[0] if isinstance(value, str) else value
    if wanted.get("src") == "any":
        del wanted["src"]
    return wanted


def run_order(spec: CampaignSpec) -> list[tuple[AttackSpec, int]]:
    """Every (attack, repetition), shuffled by the campaign seed: a pure function of the spec."""
    order = [(attack, rep) for attack in spec.attacks for rep in range(1, attack.runs + 1)]
    random.Random(spec.seed).shuffle(order)
    return order


# ------------------------------------------------------------ the world


@dataclass(frozen=True, slots=True)
class AttackOutcome:
    """What the attacker host reported."""

    argv: tuple[str, ...]
    returncode: int
    output: str


class Attacker(Protocol):
    """Runs a lab/attacks script on the attacker host."""

    def run(self, script: str, args: Sequence[str], timeout: float) -> AttackOutcome: ...


class Background(Protocol):
    """Something started before the attack and stopped after (capture, probe)."""

    def start(self, out: Path) -> None: ...
    def stop(self) -> None: ...


@dataclass(slots=True)
class SshAttacker:
    """`ssh <host> bash <lab-dir>/attacks/<script> <args>`; the lab directory is copied there beforehand."""

    host: str
    lab_dir: str = "lab"

    def command(self, script: str, args: Sequence[str]) -> list[str]:
        """The argv run locally."""
        remote = " ".join(shlex.quote(part) for part in ("bash", f"{self.lab_dir}/attacks/{script}", *args))
        return ["ssh", "-o", "BatchMode=yes", self.host, remote]

    def run(self, script: str, args: Sequence[str], timeout: float) -> AttackOutcome:
        """Run it to completion."""
        argv = self.command(script, args)
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            return AttackOutcome(tuple(argv), 124, f"timed out after {timeout}s: {exc}")
        return AttackOutcome(tuple(argv), done.returncode, done.stdout + done.stderr)


@dataclass(slots=True)
class VictimCapture:
    """`lab/capture.sh start|stop` for one side."""

    side: Side
    config: Path

    def _argv(self, command: str) -> list[str]:
        return [
            "bash",
            str(Path(__file__).parent / "capture.sh"),
            command,
            "--side",
            self.side,
            "--config",
            str(self.config),
            "--python",
            sys.executable,
        ]

    def start(self, out: Path) -> None:
        """Start capturing into `out` (`victim.pcap`)."""
        subprocess.run([*self._argv("start"), "--out", str(out)], check=True)

    def stop(self) -> None:
        """Stop and flush."""
        subprocess.run(self._argv("stop"), check=True)


@dataclass(slots=True)
class RemoteProbe:
    """The legit-client probe over SSH; its stdout (JSON lines) becomes the run's `probe.jsonl`."""

    argv: list[str]
    _stream: IO[bytes] | None = None
    _process: subprocess.Popen[bytes] | None = None

    def start(self, out: Path) -> None:
        """Start the remote probe, streaming into `out`."""
        self._stream = out.open("wb")
        self._process = subprocess.Popen(self.argv, stdout=self._stream, stderr=subprocess.DEVNULL)

    def stop(self) -> None:
        """Stop it (closing SSH ends the remote profile) and close the file."""
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
        if self._stream is not None:
            self._stream.close()
            self._stream = None


@dataclass(slots=True)
class World:
    """Every side effect `Campaign` has, injectable."""

    attacker: Attacker
    core: CoreReader
    capture: Callable[[Side], Background | None]
    probe: Background | None = None
    clock: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    poll_interval: float = 1.0
    log: Callable[[str], None] = print


# ------------------------------------------------------------- campaign


@dataclass(frozen=True, slots=True)
class LabTargets:
    """The only places an attack may point (the attack scripts enforce the same rule)."""

    pi_ip: IPv4Address
    victim_network: IPv4Network
    protected: IPv4Network

    def resolve(self, target: str) -> tuple[IPv4Address, list[str]]:
        """(target IP, the script flags that name it and the lab bounds)."""
        bounds = [
            "--pi-ip",
            str(self.pi_ip),
            "--victim-net",
            str(self.victim_network),
            "--protected-net",
            str(self.protected),
        ]
        if target == "pi":
            return self.pi_ip, ["--target", str(self.pi_ip), *bounds]
        if target == "victim":
            victim = list(self.victim_network.hosts())[-1]
            return victim, ["--target", str(victim), *bounds]
        address = IPv4Address(target)
        if address not in self.protected:
            raise LabError(f"target {target} is outside the protected network; not a lab target")
        return address, ["--lab-target", str(address), *bounds]


@dataclass(frozen=True, slots=True)
class Identity:
    """The attacker as the ground truth records it."""

    ip: str | None
    mac: str | None


@dataclass(slots=True)
class Campaign:
    """One campaign: the loop, independent of how its side effects are done."""

    spec: CampaignSpec
    world: World
    targets: LabTargets
    attacker: Identity
    env_tag: str
    provenance: Provenance
    start_manifest: dict[str, Json] = field(default_factory=dict[str, Json])
    tool_versions: dict[str, str] = field(default_factory=dict[str, str])
    params: dict[str, str] = field(default_factory=dict[str, str])

    def check_eval(self) -> None:
        """`phase = "eval"` needs frozen thresholds. Raises `LabError`."""
        if self.spec.phase != "eval":
            return
        path = self.provenance.thresholds_path
        if path is None:
            raise LabError("eval campaign: no D1 thresholds file is configured")
        problem = frozen_thresholds_problem(Path(path))
        if problem is not None:
            raise LabError(f"eval campaign refused: {problem}")

    def sets_empty(self) -> bool:
        """No live RATE_LIMIT/BLOCK rule and no offender, per one read of core."""
        return sets_empty(self.world.core)

    def cooldown(self) -> float:
        """Poll until the sets stay empty `cooldown_quiet_polls` times running. Returns seconds waited."""
        started = self.world.clock()
        quiet = 0
        while quiet < self.spec.cooldown_quiet_polls:
            if self.world.clock() - started > self.spec.cooldown_timeout_seconds:
                raise LabError(
                    f"the adaptive sets did not drain within {self.spec.cooldown_timeout_seconds:g}s; "
                    "campaign stopped (never kill-switch to force it: wait for the TTLs, then resume "
                    "with a new campaign)"
                )
            quiet = quiet + 1 if self.sets_empty() else 0
            if quiet < self.spec.cooldown_quiet_polls:
                self.world.sleep(self.spec.cooldown_poll_seconds)
        return self.world.clock() - started

    def run(self, out_root: Path) -> Path:
        """Every run, in order. Returns the sealed campaign directory."""
        self.check_eval()
        order = run_order(self.spec)
        for attack in self.spec.attacks:  # refuse a missing --param before anything starts
            expand_args(attack.args, self.params)
            victim_filter(attack, self.attacker.ip, self.params)
        directory = new_run_dir(out_root, self.spec.name)
        (directory / "campaign.toml").write_text(self.spec.source, encoding="utf-8", newline="\n")
        (directory / "plan.json").write_text(
            json.dumps(
                [
                    {"index": i, "attack": attack.id, "rep": rep}
                    for i, (attack, rep) in enumerate(order, start=1)
                ],
                indent=2,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        self.world.log(
            f"campaign {self.spec.name} ({self.spec.phase}, env {self.env_tag}): {len(order)} runs"
        )
        self.world.log(f"cooldown before the first run: {self.cooldown():.0f}s")
        for index, (attack, rep) in enumerate(order, start=1):
            self.world.log(f"[{index}/{len(order)}] {attack.id} rep {rep}")
            self._one(directory / f"{index:03d}-{attack.id}-r{rep}", attack, rep, index)
            waited = self.cooldown()
            self.world.log(f"  cooled down in {waited:.0f}s")
        write_manifest(directory, self._manifest("campaign", {"runs": len(order), "seed": self.spec.seed}))
        return directory

    def _one(self, run_dir: Path, attack: AttackSpec, rep: int, index: int) -> None:
        run_dir.mkdir()
        target, target_args = self.targets.resolve(attack.target)
        args = [*target_args, "--duration", f"{attack.duration:g}", *expand_args(attack.args, self.params)]
        capture = self.world.capture(attack.side)
        stop_polling = threading.Event()
        poller = Poller(self.world.core, clock=self.world.clock)
        poll_path = run_dir / "poll.jsonl"

        def poll_loop() -> None:
            with poll_path.open("a", encoding="utf-8") as stream:
                while not stop_polling.is_set():
                    stream.write(json.dumps(poller.poll(), default=str) + "\n")
                    stream.flush()
                    stop_polling.wait(self.world.poll_interval)

        thread = threading.Thread(target=poll_loop, name="lab-poll", daemon=True)
        if capture is not None:
            capture.start(run_dir / "victim.pcap")
        if self.world.probe is not None:
            self.world.probe.start(run_dir / "probe.jsonl")
        thread.start()
        try:
            self.world.sleep(self.spec.pre_attack_seconds)
            t_start = self.world.clock()
            outcome = self.world.attacker.run(attack.script, args, timeout=attack.duration + 120.0)
            t_end = self.world.clock()
            self.world.sleep(self.spec.post_attack_seconds)
        finally:
            stop_polling.set()
            thread.join(timeout=10)
            if self.world.probe is not None:
                self.world.probe.stop()
            if capture is not None:
                capture.stop()
        (run_dir / "attack.log").write_text(outcome.output, encoding="utf-8", newline="\n")
        versions = {
            line.split("=", 1)[1].split(" ", 1)[0]: line.split("=", 1)[1]
            for line in outcome.output.splitlines()
            if line.startswith("TOOL_VERSION=")
        }
        window: dict[str, Json] = {
            "mac": self.attacker.mac,
            "start": t_start,
            "end": t_end,
            "label": attack.id,
            "tool": attack.script,
            "argv": list(outcome.argv),
            "offered_rate_pps": attack.offered_rate_pps,
            "run": run_dir.name,
        }
        if self.attacker.mac is not None:
            (run_dir / "ground_truth.jsonl").write_text(
                json.dumps(window) + "\n", encoding="utf-8", newline="\n"
            )
        wanted = victim_filter(attack, self.attacker.ip, self.params)
        write_manifest(
            run_dir,
            self._manifest(
                "run",
                {
                    "attack": attack.id,
                    "script": attack.script,
                    "rep": rep,
                    "index": index,
                    "campaign": self.spec.name,
                    "seed": self.spec.seed,
                    "t_start": t_start,
                    "t_end": t_end,
                    "target": str(target),
                    "side": attack.side,
                    "attacker_ip": self.attacker.ip,
                    "attacker_mac": self.attacker.mac,
                    "offered_rate_pps": attack.offered_rate_pps,
                    "victim_filter": wanted,
                    "argv": list(outcome.argv),
                    "returncode": outcome.returncode,
                },
                versions,
            ),
        )

    def _manifest(
        self, kind: Literal["run", "campaign"], extra: dict[str, Json], versions: dict[str, str] | None = None
    ) -> Manifest:
        sha, dirty = git_state(REPO_ROOT)
        ruleset = self.start_manifest.get("ruleset_sha256")
        hashes = self.provenance.hashes
        return Manifest(
            kind=kind,
            env_tag=self.env_tag,
            tool=TOOL,
            phase=self.spec.phase,
            git_sha=sha,
            git_dirty=dirty,
            config_sha256=self.provenance.config_sha256,
            hashes=type(hashes)(
                thresholds=hashes.thresholds,
                thresholds_frozen=hashes.thresholds_frozen,
                policy_table=hashes.policy_table,
                models=hashes.models,
                ruleset=ruleset if isinstance(ruleset, str) else None,
            ),
            pipeline_engine=_text(self.start_manifest.get("pipeline_engine"))
            or self.provenance.pipeline_engine,
            enforcement_mode=_text(self.start_manifest.get("enforcement_mode"))
            or self.provenance.enforcement_mode,
            guard_modes=_modes(self.start_manifest.get("guards")) or dict(self.provenance.guard_modes),
            tool_versions={**self.tool_versions, **(versions or {})},
            extra=extra,
        )


def _text(value: Json) -> str | None:
    return value if isinstance(value, str) else None


def _modes(value: Json) -> dict[str, str]:
    return {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}


# --------------------------------------------------------------------- CLI


@dataclass(slots=True)
class _Printer:
    """`--dry-run`: prints commands, runs nothing, reads nothing."""

    attacker: SshAttacker

    def run(self, script: str, args: Sequence[str], timeout: float) -> AttackOutcome:
        argv = self.attacker.command(script, args)
        print("  would run: " + shlex.join(argv))
        return AttackOutcome(tuple(argv), 0, "")


def dry_run(
    spec: CampaignSpec, targets: LabTargets, attacker: SshAttacker, params: Mapping[str, str]
) -> list[str]:
    """The plan, one line per run, as printed. Raises `LabError` for a missing `--param`."""
    printer = _Printer(attacker)
    lines: list[str] = []
    for index, (attack, rep) in enumerate(run_order(spec), start=1):
        _target, target_args = targets.resolve(attack.target)
        args = [*target_args, "--duration", f"{attack.duration:g}", *expand_args(attack.args, params)]
        line = f"[{index:03d}] {attack.id} rep {rep} ({attack.side} side, {attack.duration:g}s)"
        print(line)
        lines.append(line)
        printer.run(attack.script, args, 0)
    return lines


def lab_params(targets: LabTargets, given: Mapping[str, str]) -> dict[str, str]:
    """The placeholders every campaign may use, from the config, overridden by `--param`."""
    victim, _flags = targets.resolve("victim")
    return {
        "pi_ip": str(targets.pi_ip),
        "victim_ip": str(victim),
        "victim_net": str(targets.victim_network),
        "protected_net": str(targets.protected),
        **given,
    }


def read_start_manifest(path: Path) -> dict[str, Json]:
    """`pirewall-start`'s manifest (it records the env tag). Raises `LabError`."""
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LabError(
            f"{path}: no pirewall-start manifest; start pirewall first (it records the env tag)"
        ) from exc
    except (OSError, ValueError) as exc:
        raise LabError(f"{path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise LabError(f"{path}: not a pirewall-start manifest")
    document = cast(dict[str, Json], raw)
    if not isinstance(document.get("env"), str):
        raise LabError(f"{path}: not a pirewall-start manifest (no env tag)")
    return document


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("campaign", type=Path)
    parser.add_argument("--attacker", required=True, help="user@host of the attacker (SSH, key auth)")
    parser.add_argument(
        "--attacker-lab-dir", default="lab", help="where lab/ was copied on the attacker host"
    )
    parser.add_argument("--attacker-ip", help="the attacker's LAN IP (ground truth)")
    parser.add_argument("--attacker-mac", help="the attacker's LAN MAC (ground truth)")
    parser.add_argument("--legit-client", help="user@host running lab/benign/background.py --profile probe")
    parser.add_argument("--legit-kind", choices=("wired", "wifi"), default="wifi")
    parser.add_argument("--legit-lab-dir", default="lab")
    parser.add_argument("--config", type=Path, default=REPO_ROOT / "config" / "local_config.toml")
    parser.add_argument("--start-manifest", type=Path, default=DEFAULT_START_MANIFEST)
    parser.add_argument("--socket", default="/run/pirewall/core.sock")
    parser.add_argument(
        "--param",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="fill a {name} placeholder in the campaign's args (repeatable)",
    )
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "lab" / "runs")
    parser.add_argument("--dry-run", action="store_true", help="print the order and commands; touch nothing")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """0 when the campaign completed, 2 on a refusal."""
    args = build_parser().parse_args(argv)
    try:
        spec = load_campaign(args.campaign)
        from pirewall.config.loader import load_config

        config = load_config(args.config)
        targets = LabTargets(
            config.network.pirewall_lan_ip, config.lab.victim_network, config.network.protected_network
        )
        attacker = SshAttacker(args.attacker, args.attacker_lab_dir)
        params = lab_params(targets, parse_params(args.param))
        if args.dry_run:
            print(f"campaign {spec.name} ({spec.phase}), seed {spec.seed}")
            dry_run(spec, targets, attacker, params)
            return 0
        if not args.attacker_ip or not args.attacker_mac:
            raise LabError("--attacker-ip and --attacker-mac are required: they are the ground truth")
        start = read_start_manifest(args.start_manifest)
        env_tag = require_env_tag(str(start["env"]))
        probe = None
        if args.legit_client:
            probe = RemoteProbe(
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    args.legit_client,
                    "python3",
                    f"{args.legit_lab_dir}/benign/background.py",
                    "--profile",
                    "probe",
                    "--client-kind",
                    args.legit_kind,
                    "--stdout",
                ]
            )
        world = World(
            attacker=attacker,
            core=ReadOnlyCore(args.socket),
            capture=lambda side: VictimCapture(side, args.config),
            probe=probe,
        )
        campaign = Campaign(
            spec,
            world,
            targets,
            Identity(args.attacker_ip, args.attacker_mac.lower()),
            env_tag,
            project_provenance(args.config),
            start_manifest=start,
            params=params,
        )
        directory = campaign.run(args.out)
    except LabError as exc:
        print(f"run_campaign: {exc}", file=sys.stderr)
        return 2
    print(
        f"campaign sealed: {directory}\n"
        f"next: lab/score_run.py {directory}/*/ then lab/aggregate.py {directory}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

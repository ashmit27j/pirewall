"""`lab/run_campaign.py` against fakes (phase 18): order, cooldown, eval refusal, placeholders."""

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

import pytest

from lab.common import LabError, Provenance
from lab.manifest import Hashes, Json, read_manifest
from lab.run_campaign import (
    AttackOutcome,
    Campaign,
    Identity,
    LabTargets,
    Side,
    SshAttacker,
    World,
    dry_run,
    expand_args,
    lab_params,
    load_campaign,
    parse_params,
    run_order,
)
from lab.verify_manifest import verify_tree

_REPO = Path(__file__).resolve().parents[2]
CAMPAIGN = """
name = "t"
phase = "{phase}"
seed = {seed}
pre_attack_seconds = 1
post_attack_seconds = 1
cooldown_poll_seconds = 2
cooldown_quiet_polls = 3
cooldown_timeout_seconds = 60

[[attack]]
id = "syn"
script = "syn_flood.sh"
runs = 5
target = "victim"
side = "forward"
duration = 3
offered_rate_pps = 1500
args = ["--rate", "1500"]
victim_filter = {{ proto = "tcp", dport = 80 }}

[[attack]]
id = "spoof"
script = "spoof_neighbour.sh"
runs = 3
target = "pi"
side = "input"
duration = 3
args = ["--spoof-ip", "{{neighbour_ip}}"]
victim_filter = {{ src = "{{neighbour_ip}}" }}
"""
TARGETS = LabTargets(IPv4Address("192.0.2.2"), IPv4Network("10.250.0.0/30"), IPv4Network("192.0.2.0/24"))


def _campaign(tmp_path: Path, phase: str = "dev", seed: int = 7) -> Path:
    path = tmp_path / f"c-{phase}-{seed}.toml"
    path.write_text(CAMPAIGN.format(phase=phase, seed=seed), encoding="utf-8")
    return path


@dataclass(slots=True)
class FakeCore:
    """Live rules/offenders for the first `busy_reads` reads, then empty."""

    busy_reads: int = 0
    reads: int = 0

    def rules(self) -> list[dict[str, Json]]:
        self.reads += 1
        if self.reads <= self.busy_reads:
            return [{"action": "block", "status": "active", "mac": "02:00:00:00:a0:01"}]
        return [{"action": "monitor", "status": "active"}]

    def events(self) -> list[dict[str, Json]]:
        return []

    def offenders(self) -> list[dict[str, Json]]:
        return []

    def bindings(self) -> int:
        return 0

    def guard_modes(self) -> dict[str, Json]:
        return {}

    def engine(self) -> dict[str, Json]:
        return {"frames_seen": 0}


@dataclass(slots=True)
class FakeAttacker:
    calls: list[tuple[str, tuple[str, ...]]] = field(default_factory=list[tuple[str, tuple[str, ...]]])

    def run(self, script: str, args: Sequence[str], timeout: float) -> AttackOutcome:
        self.calls.append((script, tuple(args)))
        return AttackOutcome(("ssh", script, *args), 0, "TOOL_VERSION=hping3 hping3 3.0.0\nARGV=...\n")


@dataclass(slots=True)
class FakeClock:
    now: float = 1_800_000_000.0
    sleeps: list[float] = field(default_factory=list[float])

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _world(core: FakeCore, attacker: FakeAttacker, clock: FakeClock) -> World:
    def no_capture(side: Side) -> None:
        del side

    return World(
        attacker=attacker,
        core=core,
        capture=no_capture,
        clock=clock.time,
        sleep=clock.sleep,
        poll_interval=0.01,
        log=lambda line: None,
    )


def _provenance(frozen: bool | None, thresholds_path: str | None) -> Provenance:
    return Provenance(
        config_sha256="c" * 64,
        hashes=Hashes(thresholds="t" * 64, thresholds_frozen=frozen, policy_table="p" * 64),
        thresholds_path=thresholds_path,
    )


def test_the_run_order_is_a_deterministic_function_of_the_seed(tmp_path: Path) -> None:
    first = [(a.id, rep) for a, rep in run_order(load_campaign(_campaign(tmp_path, seed=7)))]
    again = [(a.id, rep) for a, rep in run_order(load_campaign(_campaign(tmp_path, seed=7)))]
    other = [(a.id, rep) for a, rep in run_order(load_campaign(_campaign(tmp_path, seed=8)))]
    assert first == again != other
    assert sorted(first) == sorted([("syn", r) for r in range(1, 6)] + [("spoof", r) for r in range(1, 4)])


def test_dry_run_prints_every_run_and_needs_every_placeholder(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    spec = load_campaign(_campaign(tmp_path))
    with pytest.raises(LabError, match="neighbour_ip"):
        dry_run(spec, TARGETS, SshAttacker("kali@lab"), lab_params(TARGETS, {}))
    params = lab_params(TARGETS, parse_params(["neighbour_ip=192.0.2.21"]))
    lines = dry_run(spec, TARGETS, SshAttacker("kali@lab"), params)
    assert len(lines) == 8
    printed = capsys.readouterr().out
    assert "--spoof-ip 192.0.2.21" in printed and "--target 10.250.0.2" in printed


def test_placeholders_and_params() -> None:
    assert expand_args(["{victim_net}", "x{pi_ip}"], lab_params(TARGETS, {})) == [
        "10.250.0.0/30",
        "x192.0.2.2",
    ]
    with pytest.raises(LabError):
        parse_params(["Bad=1"])


def test_cooldown_waits_until_the_sets_are_empty_for_the_quiet_polls(tmp_path: Path) -> None:
    spec = load_campaign(_campaign(tmp_path))
    core, clock = FakeCore(busy_reads=4), FakeClock()
    campaign = Campaign(
        spec,
        _world(core, FakeAttacker(), clock),
        TARGETS,
        Identity("192.0.2.100", None),
        "mock",
        _provenance(False, None),
    )
    waited = campaign.cooldown()
    # 4 busy reads, then 3 quiet ones in a row; a 2 s sleep between polls that are not the last.
    assert core.reads == 7
    assert waited == pytest.approx(6 * 2.0)


def test_cooldown_gives_up_and_never_forces_the_sets(tmp_path: Path) -> None:
    spec = load_campaign(_campaign(tmp_path))
    campaign = Campaign(
        spec,
        _world(FakeCore(busy_reads=10_000), FakeAttacker(), FakeClock()),
        TARGETS,
        Identity(None, None),
        "mock",
        _provenance(False, None),
    )
    with pytest.raises(LabError, match="never kill-switch"):
        campaign.cooldown()


def test_an_eval_campaign_refuses_unfrozen_thresholds(tmp_path: Path) -> None:
    spec = load_campaign(_campaign(tmp_path, phase="eval"))
    attacker = FakeAttacker()
    campaign = Campaign(
        spec,
        _world(FakeCore(), attacker, FakeClock()),
        TARGETS,
        Identity(None, None),
        "mock",
        _provenance(False, str(_REPO / "config" / "d1_thresholds.toml")),
        params={"neighbour_ip": "192.0.2.21"},
    )
    with pytest.raises(LabError, match="frozen = false"):
        campaign.run(tmp_path / "runs")
    assert attacker.calls == [] and not (tmp_path / "runs").exists()


def test_a_dev_campaign_runs_every_run_and_seals_it(tmp_path: Path) -> None:
    spec = load_campaign(_campaign(tmp_path))
    attacker = FakeAttacker()
    campaign = Campaign(
        spec,
        _world(FakeCore(), attacker, FakeClock()),
        TARGETS,
        Identity("192.0.2.100", "02:00:00:00:a0:01"),
        "mock",
        _provenance(False, None),
        params=lab_params(TARGETS, {"neighbour_ip": "192.0.2.21"}),
    )
    directory = campaign.run(tmp_path / "runs")
    assert len(attacker.calls) == 8
    assert verify_tree(directory).ok
    runs = sorted(path for path in directory.iterdir() if path.is_dir())
    assert len(runs) == 8
    spoof = next(run for run in runs if "spoof" in run.name)
    extra = read_manifest(spoof)["extra"]
    assert isinstance(extra, dict)
    assert extra["victim_filter"] == {"src": "192.0.2.21"}
    syn = next(run for run in runs if "syn" in run.name)
    syn_extra = read_manifest(syn)["extra"]
    assert isinstance(syn_extra, dict)
    assert syn_extra["victim_filter"] == {"src": "192.0.2.100", "proto": "tcp", "dport": 80}
    truth = json.loads((syn / "ground_truth.jsonl").read_text(encoding="utf-8"))
    assert truth["mac"] == "02:00:00:00:a0:01" and truth["label"] == "syn"
    assert read_manifest(syn)["tool_versions"] == {"hping3": "hping3 hping3 3.0.0"}


def test_the_shipped_campaigns_load_and_expand(tmp_path: Path) -> None:
    params = lab_params(
        TARGETS,
        parse_params(
            ["neighbour_ip=192.0.2.21", "attacker_iface=eth0", "wordlist=/usr/share/wordlists/lab.txt"]
        ),
    )
    for name, phase in (("dev", "dev"), ("eval", "eval")):
        spec = load_campaign(_REPO / "lab" / "campaigns" / f"{name}.toml")
        assert spec.phase == phase
        assert {a.runs for a in spec.attacks if "flood" in a.id or "scan" in a.id or a.id == "masscan"} == {5}
        assert all(
            a.runs == 3
            for a in spec.attacks
            if "flood" not in a.id and "scan" not in a.id and a.id != "masscan"
        )
        for attack in spec.attacks:
            expand_args(attack.args, params)

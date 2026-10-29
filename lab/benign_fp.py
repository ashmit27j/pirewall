"""Offline G5: what would pirewall have done to clean benign traffic? (PLAN_v3 §2 G5, critique_safety_eval.md)

    uv run python lab/benign_fp.py FLOWS_DIR [FLOWS_DIR ...] --out DIR \\
        [--config config/local_config.toml] [--thresholds config/d1_thresholds.toml] \\
        [--exclude-mac MAC ...] [--capture-manifest DIR ...] [--ground-truth FILE ...] \\
        [--pcaps DIR] [--no-meters] [--leases FILE] [--pi-mac MAC] \\
        [--lightgbm MODEL] [--isolation-forest MODEL] [--min-device-hours 24]

**Inputs.** `scripts/dataset/pcap_to_flows.py` output directories
(`flows.csv` + `manifest.json`), all with **one** env tag (D7: run once per
tag, so `pi-live` and `pi-scripted` are always reported separately). The
pcaps each manifest names are replayed through the kernel-meter simulator;
`--pcaps DIR` finds them by file name when they were copied elsewhere, and
their SHA-256 must match the manifest.

**Clean data.** Rows labelled anything but `benign` / `benign:<profile>`
are dropped, as are rows from lab MACs (`--exclude-mac`, and the
`extra.lab_macs` of every `--capture-manifest`) and rows inside a
`--ground-truth` attack window of that window's MAC (windows labelled
`benign` / `benign:<profile>`, from `lab/benign/background.py`, exclude
nothing). Kernel evidence from those MACs or windows is dropped the same
way. In the clean totals and the verdict, a MAC with any attack window
is a lab device for the whole span: its offender entries and escalation
memory outlive the window, and those decisions are not benign FPs.

**What runs, all through the project's own code:**

* D1: connection starts (`start_from_features`) into `D1State`, evaluated
  once per poll interval with `evaluate_device` / `evaluate_destination` /
  `evaluate_global`, i.e. the `measure_*` functions core runs, against the
  thresholds file given.
* Tier K: `lab.meter_sim.MeterSimulator` (rates and bursts parsed from the
  rendered static template) read by the real `KernelPoller` every
  `d1.kernel_poll_interval_seconds` of capture time.
* D2/D3 (optional): Isolation Forest / LightGBM over the rows' features
  when model artifacts are given. Unlike core, no protocol-domain guard is
  applied, so this can only over-count MONITORs.
* Every device's bundle goes through `pirewall.policy.PolicyEngine` for
  ASSISTED and ACTIVE (SHADOW reads the ACTIVE column and only records), in
  two guard scenarios: the configured guard modes, and the same with the
  forward guard enforcing (the question G5 answers).

Every decision the policy returns is counted as if the validator accepted
it (an upper bound: the live validator also refuses duplicates).

**Report** (`DIR/fp.json`, sealed by `DIR/manifest.json`): device-hours
(a device is active in an hour if it opened >= 1 flow in it); per scenario
and mode, enforce actions (RATE_LIMIT + BLOCK) and MONITORs per
device-hour, with the rule-of-three bound 3/T at zero and the exact Poisson
95% interval otherwise; per-MAC breakdowns; meter trips, static drops and
fail-opens. And one line:

    forward guard may enforce: yes|no — <reason>

"yes" needs all of: env tag `pi-live`, the meters simulated, at least
`--min-device-hours` clean device-hours, and, with the forward guard
enforcing, no forward meter trip, no forward backstop hit and no enforce
action against any clean device. This script never changes a guard.
"""

import argparse
import csv
import json
import math
import sys
from collections import deque
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # `python lab/benign_fp.py`

from lab.common import REPO_ROOT, LabError, check_output_location
from lab.manifest import Manifest, ManifestError, read_manifest, sha256_file, write_manifest
from lab.meter_sim import MeterSimulator, SimKernelReader, TemplateSpec, Trip
from lab.stats import rate_interval
from pirewall.capture.pcapio import PcapReader
from pirewall.config.loader import load_config
from pirewall.config.models import PirewallConfig
from pirewall.core.bindings import parse_leases
from pirewall.core.enums import EnforcementMode, FirewallAction, GuardMode, GuardName
from pirewall.core.exceptions import PirewallError
from pirewall.core.models.evidence import AnomalyEvidence
from pirewall.core.models.evidence_v2 import ClassifierEvidence, D1Evidence, KernelGuardEvidence
from pirewall.core.models.identity import RuleTarget
from pirewall.core.nft_names import OFFENDER_GUARD, OffenderCode
from pirewall.detection_v2.d1 import ConnectionStart, D1State, start_from_features, unicast_mac
from pirewall.detection_v2.kernel import KernelPoller
from pirewall.detection_v2.thresholds import load_thresholds
from pirewall.policy.engine import EvidenceBundle, PolicyEngine
from pirewall.policy.table import load_policy_table

TOOL: Final = "lab/benign_fp.py"
MODES: Final = (EnforcementMode.ASSISTED, EnforcementMode.ACTIVE)
_START_COLUMNS: Final = ("packet_count", "payload_byte_count", "backward_packet_count", "duration_seconds")
_ENFORCE: Final = frozenset({FirewallAction.RATE_LIMIT, FirewallAction.BLOCK})
_FORWARD_BACKSTOP: Final = "c_bk_newconn"
_US: Final = 1_000_000
ML_MEMORY: Final = timedelta(seconds=60)
"""How long core keeps a device's ML evidence for its bundles (`pipeline_v2._ML_MEMORY`)."""
ML_PER_DEVICE: Final = 32
type Evidence = KernelGuardEvidence | D1Evidence | AnomalyEvidence | ClassifierEvidence


def _is_benign(label: str | None) -> bool:
    return label is None or label == "benign" or label.startswith("benign:")


@dataclass(frozen=True, slots=True)
class Window:
    """A lab window to leave out: `mac`'s traffic within [start, end] (Unix seconds)."""

    mac: str
    start: float
    end: float

    def covers(self, mac: str, at: float) -> bool:
        """Whether this window excludes `mac` at `at`."""
        return mac == self.mac and self.start <= at <= self.end


@dataclass(slots=True)
class Exclusions:
    """Lab MACs (always out) and lab windows (out within their span)."""

    macs: set[str] = field(default_factory=set[str])
    windows: list[Window] = field(default_factory=list[Window])

    @property
    def lab_macs(self) -> set[str]:
        """Every MAC that is never counted as a clean device: listed lab MACs and attack-window MACs."""
        return self.macs | {window.mac for window in self.windows}

    def excluded(self, mac: str | None, at: float) -> bool:
        """Whether evidence or a row from `mac` at `at` is lab traffic."""
        if mac is None:
            return False
        return mac in self.macs or any(window.covers(mac, at) for window in self.windows)


@dataclass(slots=True)
class Inputs:
    """Everything read from the flow directories."""

    env_tag: str
    manifests: list[tuple[Path, str]]
    pcaps: list[tuple[Path, str]]
    starts: list[ConnectionStart]
    device_hours: set[tuple[str, int]]
    ml: list[tuple[float, str, AnomalyEvidence | ClassifierEvidence]]
    rows: int = 0
    rows_excluded: int = 0
    first_at: float | None = None
    last_at: float | None = None


@dataclass(slots=True)
class Tally:
    """One (scenario, mode)'s decisions, per MAC."""

    monitor: dict[str, int] = field(default_factory=dict[str, int])
    rate_limit: dict[str, int] = field(default_factory=dict[str, int])
    block: dict[str, int] = field(default_factory=dict[str, int])

    def add(self, mac: str, action: FirewallAction) -> None:
        """Count one decision."""
        bucket = {
            FirewallAction.MONITOR: self.monitor,
            FirewallAction.RATE_LIMIT: self.rate_limit,
            FirewallAction.BLOCK: self.block,
        }.get(action)
        if bucket is not None:
            bucket[mac] = bucket.get(mac, 0) + 1

    def enforce(self, mac: str) -> int:
        """RATE_LIMIT + BLOCK decisions against `mac`."""
        return self.rate_limit.get(mac, 0) + self.block.get(mac, 0)


@dataclass(slots=True)
class Scenario:
    """One guard-mode scenario: its own simulator, poller and policy engines."""

    name: str
    modes: dict[GuardName, GuardMode]
    simulator: MeterSimulator | None
    reader: SimKernelReader | None
    poller: KernelPoller | None
    engines: dict[EnforcementMode, PolicyEngine]
    tallies: dict[EnforcementMode, Tally]
    kernel: dict[str, tuple[KernelGuardEvidence, ...]] = field(
        default_factory=dict[str, tuple[KernelGuardEvidence, ...]]
    )
    kernel_evidence: dict[str, int] = field(default_factory=dict[str, int])


# ------------------------------------------------------------------ inputs


def _exclusions(args: argparse.Namespace) -> Exclusions:
    found = Exclusions(macs={str(mac).lower() for mac in args.exclude_mac})
    for directory in args.capture_manifest:
        try:
            manifest = read_manifest(Path(directory))
        except ManifestError as exc:
            raise LabError(str(exc)) from exc
        extra = manifest.get("extra")
        lab_macs = extra.get("lab_macs") if isinstance(extra, dict) else None
        if isinstance(lab_macs, list):
            found.macs.update(str(mac).lower() for mac in lab_macs)
    for path in args.ground_truth:
        for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                label = entry.get("label")
                if isinstance(label, str) and _is_benign(label):
                    continue  # scripted benign ground truth: those devices are the clean data
                found.windows.append(
                    Window(str(entry["mac"]).lower(), float(entry["start"]), float(entry["end"]))
                )
            except (ValueError, KeyError, TypeError) as exc:
                raise LabError(f"{path}:{number}: expected {{mac, start, end}}: {exc}") from exc
    return found


def _find_pcap(recorded: Path, sha256: str, pcap_dir: Path | None) -> Path:
    candidates = [recorded] + ([pcap_dir / recorded.name] if pcap_dir is not None else [])
    for candidate in candidates:
        if candidate.is_file():
            if sha256_file(candidate) != sha256:
                raise LabError(f"{candidate}: SHA-256 differs from the flows manifest; not the same capture")
            return candidate
    raise LabError(f"pcap {recorded.name} not found (pass --pcaps DIR, or --no-meters to skip the meters)")


class _MlScorer:
    """Optional D2/D3 over flow rows, batched; evidence only for rows the models flag."""

    def __init__(self, config: PirewallConfig, lightgbm: Path | None, isolation_forest: Path | None) -> None:
        from pirewall.ml.inference.loader import load_isolation_forest_model, load_lightgbm_model

        self._config = config
        self.lightgbm = load_lightgbm_model(lightgbm) if lightgbm is not None else None
        self.forest = load_isolation_forest_model(isolation_forest) if isolation_forest is not None else None
        self._pending: list[tuple[float, str, str, tuple[float, ...]]] = []
        self.out: list[tuple[float, str, AnomalyEvidence | ClassifierEvidence]] = []

    @property
    def active(self) -> bool:
        return self.lightgbm is not None or self.forest is not None

    def add(self, at: float, mac: str, flow_id: str, values: tuple[float, ...]) -> None:
        self._pending.append((at, mac, flow_id, values))
        if len(self._pending) >= 512:
            self.flush()

    def flush(self) -> None:
        from pirewall.core.models.feature_vector import FeatureVector
        from pirewall.detection.known_attack import classify
        from pirewall.features.schema import FEATURE_NAMES, SCHEMA_VERSION
        from pirewall.ml.inference.isolation_forest_predictor import anomaly_score_batch
        from pirewall.ml.labels import is_attack_label

        batch, self._pending = self._pending, []
        if not batch:
            return
        vectors = [
            FeatureVector(
                flow_id=flow_id,
                schema_version=SCHEMA_VERSION,
                feature_names=FEATURE_NAMES,
                values=values,
                computed_at=datetime.fromtimestamp(at, UTC),
            )
            for at, _mac, flow_id, values in batch
        ]
        if self.forest is not None:
            threshold = self._config.detection.anomaly_score_threshold
            for (at, mac, flow_id, _values), score in zip(
                batch, anomaly_score_batch(self.forest, vectors), strict=True
            ):
                if score < threshold:
                    self.out.append(
                        (
                            at,
                            mac,
                            AnomalyEvidence(
                                flow_id=flow_id,
                                anomaly_score=score,
                                threshold=threshold,
                                is_anomaly=True,
                                model_version=self.forest.metadata.model_version,
                                feature_schema_version=self.forest.metadata.feature_schema_version,
                                generated_at=datetime.fromtimestamp(at, UTC),
                            ),
                        )
                    )
        if self.lightgbm is not None:
            operating = self._config.detection.known_attack_confidence_threshold
            for (at, mac, flow_id, _values), vector in zip(batch, vectors, strict=True):
                known = classify(self.lightgbm, vector, datetime.fromtimestamp(at, UTC))
                benign = sum(
                    p for label, p in known.class_probabilities.items() if not is_attack_label(label)
                )
                probability = min(max(1.0 - benign, 0.0), 1.0)
                if probability < operating:
                    continue
                attack = is_attack_label(known.predicted_class)
                self.out.append(
                    (
                        at,
                        mac,
                        ClassifierEvidence(
                            id=f"ml:{flow_id}",
                            flow_id=flow_id,
                            mac=mac,
                            attack_probability=probability,
                            operating_threshold=operating,
                            is_attack=True,
                            family=known.predicted_class if attack else None,
                            family_probability=known.confidence if attack else None,
                            model_version=known.model_version,
                            feature_schema_version=known.feature_schema_version,
                            generated_at=datetime.fromtimestamp(at, UTC),
                        ),
                    )
                )


def read_inputs(
    directories: Sequence[Path],
    exclusions: Exclusions,
    protected: IPv4Network,
    scorer: _MlScorer | None,
    pcap_dir: Path | None,
    want_pcaps: bool,
) -> Inputs:
    """Read every flows directory; refuse mixed env tags (D7)."""
    tags: set[str] = set()
    manifests: list[tuple[Path, str]] = []
    pcaps: list[tuple[Path, str]] = []
    starts: list[ConnectionStart] = []
    hours: set[tuple[str, int]] = set()
    rows = excluded = 0
    first: float | None = None
    last: float | None = None
    from pirewall.features.schema import FEATURE_NAMES

    for directory in directories:
        manifest_path, flows_path = directory / "manifest.json", directory / "flows.csv"
        if not manifest_path.is_file() or not flows_path.is_file():
            raise LabError(f"{directory}: needs flows.csv and manifest.json from pcap_to_flows (CSV output)")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        tags.add(str(manifest.get("env_tag")))
        manifests.append((directory, sha256_file(manifest_path)))
        if want_pcaps:
            for item in manifest.get("inputs", []):
                pcaps.append(
                    (_find_pcap(Path(item["path"]), str(item["sha256"]), pcap_dir), str(item["sha256"]))
                )
        with flows_path.open(newline="", encoding="utf-8") as stream:
            for number, raw in enumerate(csv.DictReader(stream)):
                rows += 1
                mac = unicast_mac(raw.get("source_mac") or None)
                at = int(raw["first_seen_us"]) / _US
                if not _is_benign(raw.get("label")) or exclusions.excluded(mac, at):
                    excluded += 1
                    continue
                source = IPv4Address(raw["source_ip"])
                if mac is None or source not in protected:
                    continue  # not a LAN device opening a flow: no device-hour, no D1 identity
                first = at if first is None else min(first, at)
                last = at if last is None else max(last, at)
                hours.add((mac, math.floor(at / 3600)))
                if scorer is not None and scorer.active:
                    scorer.add(
                        at,
                        mac,
                        f"{directory.name}:{number}",
                        tuple(float(raw[name]) for name in FEATURE_NAMES),
                    )
                port = raw.get("destination_port")
                start = start_from_features(
                    is_start=raw.get("protocol") == "tcp"
                    and raw.get("connection_start") in ("True", "true", "1"),
                    source_mac=mac,
                    source_ip=source,
                    destination_ip=IPv4Address(raw["destination_ip"]),
                    destination_port=int(float(port)) if port else None,
                    first_seen=datetime.fromtimestamp(at, UTC),
                    features={name: float(raw[name]) for name in _START_COLUMNS},
                )
                if start is not None:
                    starts.append(start)
    if len(tags) != 1:
        raise LabError(f"inputs mix env tags {sorted(tags)}; run once per tag (ADDENDUM_4.md D7)")
    if scorer is not None:
        scorer.flush()
    starts.sort(key=lambda item: (item.at, item.mac, str(item.destination_ip), item.destination_port or 0))
    ml = sorted(scorer.out if scorer is not None else [], key=lambda item: (item[0], item[1]))
    return Inputs(tags.pop(), manifests, pcaps, starts, hours, ml, rows, excluded, first, last)


def _frames(pcaps: Sequence[tuple[Path, str]]) -> Iterator[tuple[float, bytes]]:
    """Every frame of every pcap, files in order of their first timestamp (hourly rotation order)."""

    def first_ts(path: Path) -> int:
        for record in PcapReader(path):
            return record.ts_us
        return 0

    for path in sorted((path for path, _ in pcaps), key=lambda path: (first_ts(path), path.name)):
        for record in PcapReader(path):
            yield record.ts_us / _US, record.data


# --------------------------------------------------------------- timeline


@dataclass(slots=True)
class Aggregates:
    """Detector output that names no device: reported, never acted on (policy table `[d1]`)."""

    by_detector: dict[str, int] = field(default_factory=dict[str, int])
    untargetable: int = 0
    d1_by_detector: dict[str, int] = field(default_factory=dict[str, int])


class Evaluator:
    """Drives D1, the simulated kernel and the policy engines along the capture's own clock."""

    def __init__(
        self,
        config: PirewallConfig,
        inputs: Inputs,
        scenarios: list[Scenario],
        exclusions: Exclusions,
    ) -> None:
        thresholds = load_thresholds(_resolve(config.d1.thresholds_path))
        self._config = config
        self._inputs = inputs
        self._scenarios = scenarios
        self._exclusions = exclusions
        self._d1 = D1State(config.d1, thresholds, extra_brute_force_ports=(config.portal.listen_port,))
        self._interval = config.d1.kernel_poll_interval_seconds
        self._start_index = 0
        self._ml_index = 0
        self._ml: dict[str, deque[AnomalyEvidence | ClassifierEvidence]] = {}
        self._seen_aggregate: set[str] = set()
        self.aggregates = Aggregates()
        self.polls = 0

    def run(self, frames: Iterator[tuple[float, bytes]]) -> None:
        """Feed every frame; poll at every interval boundary that has something to look at."""
        next_poll: float | None = None
        last_activity: float | None = None
        for at, data in frames:
            if next_poll is None:
                next_poll = self._boundary(at)
            while next_poll <= at:
                self._tick(next_poll)
                next_poll += self._interval
                if not self._busy() and next_poll < self._boundary(at):
                    next_poll = self._boundary(at)  # idle gap: nothing can change until this frame
            for scenario in self._scenarios:
                if scenario.simulator is not None:
                    scenario.simulator.feed(data, at)
            last_activity = at
        # Drain: the remaining starts and ML, then until every offender has expired.
        horizon = max(
            [value for value in (last_activity, self._last_input()) if value is not None], default=None
        )
        if horizon is None:
            return
        offender_tail = max(
            (
                s.simulator.spec.sets["offenders"].timeout_seconds or 0.0
                for s in self._scenarios
                if s.simulator
            ),
            default=0.0,
        )
        poll = next_poll if next_poll is not None else self._boundary(self._first_input() or horizon)
        end = horizon + offender_tail + 2 * self._interval
        while poll <= end:
            self._tick(poll)
            poll += self._interval
            if not self._busy() and poll <= horizon:
                poll = max(poll, self._boundary(self._next_input_at() or horizon))

    def _boundary(self, at: float) -> float:
        return math.ceil(at / self._interval) * self._interval

    def _first_input(self) -> float | None:
        values = [item.at.timestamp() for item in self._inputs.starts[:1]] + [
            item[0] for item in self._inputs.ml[:1]
        ]
        return min(values, default=None)

    def _last_input(self) -> float | None:
        values = [item.at.timestamp() for item in self._inputs.starts[-1:]] + [
            item[0] for item in self._inputs.ml[-1:]
        ]
        return max(values, default=None)

    def _next_input_at(self) -> float | None:
        values: list[float] = []
        if self._start_index < len(self._inputs.starts):
            values.append(self._inputs.starts[self._start_index].at.timestamp())
        if self._ml_index < len(self._inputs.ml):
            values.append(self._inputs.ml[self._ml_index][0])
        return min(values, default=None)

    def _busy(self) -> bool:
        """Whether a poll can change anything without new frames: live kernel evidence is still decaying."""
        return any(scenario.kernel for scenario in self._scenarios)

    def _tick(self, at: float) -> None:
        self.polls += 1
        now = datetime.fromtimestamp(at, UTC)
        touched: set[str] = set()
        destinations: set[IPv4Address] = set()
        starts = self._inputs.starts
        while self._start_index < len(starts) and starts[self._start_index].at.timestamp() <= at:
            start = starts[self._start_index]
            self._d1.observe(start)
            touched.add(start.mac)
            destinations.add(start.destination_ip)
            self._start_index += 1
        ml = self._inputs.ml
        while self._ml_index < len(ml) and ml[self._ml_index][0] <= at:
            _at, mac, item = ml[self._ml_index]
            self._ml.setdefault(mac, deque(maxlen=ML_PER_DEVICE)).append(item)
            touched.add(mac)
            self._ml_index += 1
        d1_cache: dict[str, list[D1Evidence]] = {}
        for scenario in self._scenarios:
            scenario_touched = set(touched)
            if scenario.poller is not None and scenario.reader is not None:
                scenario.reader.now = at
                result = scenario.poller.poll(now)
                current: dict[str, list[KernelGuardEvidence]] = {}
                for item in result.evidence:
                    if self._exclusions.excluded(str(item.mac), at):
                        continue
                    current.setdefault(str(item.mac), []).append(item)
                scenario.kernel = {mac: tuple(items) for mac, items in current.items()}
                scenario_touched.update(current)
            for mac in sorted(scenario_touched):
                if mac not in d1_cache:
                    d1_cache[mac] = self._d1.evaluate_device(mac, now)
                    for item in d1_cache[mac]:
                        name = item.detector.value
                        self.aggregates.d1_by_detector[name] = self.aggregates.d1_by_detector.get(name, 0) + 1
                self._decide(scenario, mac, d1_cache[mac], now)
        for destination in sorted(destinations):
            self._aggregate(self._d1.evaluate_destination(destination, now))
        self._aggregate([item for item in self._d1.evaluate_global(now) if item.mac is None])

    def _decide(self, scenario: Scenario, mac: str, d1: list[D1Evidence], now: datetime) -> None:
        kernel = scenario.kernel.get(mac, ())
        if kernel:
            scenario.kernel_evidence[mac] = scenario.kernel_evidence.get(mac, 0) + len(kernel)
        ml = self._recent_ml(mac, now)
        items: tuple[Evidence, ...] = (*kernel, *d1, *ml)
        if not items:
            return
        ip = self._ip_for(scenario, mac)
        if ip is None:
            self.aggregates.untargetable += 1
            return
        bundle = EvidenceBundle(RuleTarget(ip=ip, mac=mac), items)
        had_d1 = bool(d1)
        for mode, engine in scenario.engines.items():
            for decision in engine.decide(bundle, mode, now):
                scenario.tallies[mode].add(mac, decision.action)
                engine.record_enforced(decision, had_d1)

    def _recent_ml(self, mac: str, now: datetime) -> tuple[AnomalyEvidence | ClassifierEvidence, ...]:
        """ML evidence for `mac` from the last `ML_MEMORY`, as core keeps it (`pipeline_v2._recent_ml`)."""
        recent = self._ml.get(mac)
        if not recent:
            return ()
        while recent and recent[0].generated_at < now - ML_MEMORY:
            recent.popleft()
        return tuple(recent)

    def _ip_for(self, scenario: Scenario, mac: str) -> IPv4Address | None:
        if scenario.simulator is not None:
            for ip, bound in scenario.simulator.bindings.items():
                if bound == mac:
                    return ip
        return self._d1.last_ip(mac)

    def _aggregate(self, items: Sequence[D1Evidence]) -> None:
        for item in items:
            if item.id in self._seen_aggregate:
                continue
            self._seen_aggregate.add(item.id)
            name = item.detector.value
            self.aggregates.by_detector[name] = self.aggregates.by_detector.get(name, 0) + 1


def _resolve(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


# ----------------------------------------------------------------- report


def _scenarios(
    config: PirewallConfig,
    spec: TemplateSpec | None,
    bindings: dict[IPv4Address, str] | None,
    pi_mac: str | None,
) -> list[Scenario]:
    table = load_policy_table(_resolve(config.policy.table_path))
    infrastructure = {
        config.network.pirewall_lan_ip,
        config.network.upstream_gateway,
        config.admin.admin_pc_ip,
    }
    admin_mac = config.admin.admin_pc_mac

    def protected(target: RuleTarget) -> bool:
        return target.ip in infrastructure or (target.mac is not None and target.mac == admin_mac)

    configured: dict[GuardName, GuardMode] = (
        dict(spec.guard_modes)
        if spec is not None
        else {
            GuardName.RAW: config.guards.raw_mode,
            GuardName.INPUT: config.guards.input_mode,
            GuardName.FORWARD: config.guards.forward_mode,
        }
    )
    variants = [("configured", configured)]
    if configured[GuardName.FORWARD] is not GuardMode.ENFORCE:
        variants.append(("forward-enforce", {**configured, GuardName.FORWARD: GuardMode.ENFORCE}))
    out: list[Scenario] = []
    for name, modes in variants:
        simulator = reader = poller = None
        if spec is not None:
            simulator = MeterSimulator(
                spec,
                pi_ip=config.network.pirewall_lan_ip,
                protected=config.network.protected_network,
                guard_modes=modes,
                bindings=bindings,
                pi_mac=pi_mac,
            )
            reader = SimKernelReader(simulator)
            poller = KernelPoller(
                reader,
                sustained_polls=config.policy.sustained_polls,
                set_fill_warning_ratio=config.d1.set_fill_warning_ratio,
            )
        out.append(
            Scenario(
                name=name,
                modes=modes,
                simulator=simulator,
                reader=reader,
                poller=poller,
                engines={mode: PolicyEngine(table, config.policy, is_protected=protected) for mode in MODES},
                tallies={mode: Tally() for mode in MODES},
            )
        )
    return out


def _trips_json(
    trips: Mapping[tuple[str, OffenderCode], Trip], exclusions: Exclusions
) -> list[dict[str, object]]:
    return [
        {
            "mac": trip.mac,
            "code": trip.code.name,
            "guard": OFFENDER_GUARD[trip.code].value,
            "hits": trip.hits,
            "first_at": trip.first_at,
            "last_at": trip.last_at,
            "lab": exclusions.excluded(trip.mac, trip.first_at),
        }
        for trip in sorted(trips.values(), key=lambda item: (item.mac, item.code))
    ]


def build_report(
    inputs: Inputs,
    scenarios: list[Scenario],
    evaluator: Evaluator,
    exclusions: Exclusions,
    meters: bool,
    min_device_hours: float,
) -> dict[str, object]:
    """The `fp.json` document, including the forward-guard verdict."""
    device_hours = float(len(inputs.device_hours))
    clean_macs = sorted({mac for mac, _hour in inputs.device_hours})
    per_scenario: dict[str, object] = {}
    for scenario in scenarios:
        modes: dict[str, object] = {}
        for mode, tally in scenario.tallies.items():
            macs = sorted(set(tally.monitor) | set(tally.rate_limit) | set(tally.block))
            clean = [mac for mac in macs if mac not in exclusions.lab_macs]
            enforce = sum(tally.enforce(mac) for mac in clean)
            monitor = sum(tally.monitor.get(mac, 0) for mac in clean)
            modes[mode.value] = {
                "enforce_actions": rate_interval(enforce, device_hours).as_json(),
                "monitors": rate_interval(monitor, device_hours).as_json(),
                "g5_zero_enforce": enforce == 0,
                "g5_monitor_per_device_hour_le_1": device_hours > 0 and monitor / device_hours <= 1.0,
                "by_mac": {
                    mac: {
                        "monitor": tally.monitor.get(mac, 0),
                        "rate_limit": tally.rate_limit.get(mac, 0),
                        "block": tally.block.get(mac, 0),
                    }
                    for mac in macs
                },
            }
        simulator = scenario.simulator
        per_scenario[scenario.name] = {
            "guard_modes": {guard.value: mode.value for guard, mode in sorted(scenario.modes.items())},
            "modes": modes,
            "shadow": "SHADOW computes the ACTIVE column and records it SHADOWED; see 'active'",
            "kernel_evidence_by_mac": dict(sorted(scenario.kernel_evidence.items())),
            "meter_trips": _trips_json(dict(simulator.trips), exclusions) if simulator else None,
            "backstop_hits": dict(sorted(simulator.counters.backstop_hits.items())) if simulator else None,
            "static_drops": dict(sorted(simulator.counters.static_drops.items())) if simulator else None,
            "static_drops_by_mac": (
                {
                    mac: dict(sorted(v.items()))
                    for mac, v in sorted(simulator.counters.static_drops_by_mac.items())
                }
                if simulator
                else None
            ),
            "failopen": dict(sorted(simulator.counters.failopen.items())) if simulator else None,
            "offenders_full": simulator.counters.offenders_full if simulator else None,
            "frames": simulator.counters.frames if simulator else None,
            "pi_mac": simulator.pi_mac if simulator else None,
        }
    verdict, reason = forward_verdict(inputs, scenarios, exclusions, meters, device_hours, min_device_hours)
    return {
        "tool": TOOL,
        "env_tag": inputs.env_tag,
        "inputs": [{"directory": str(path), "manifest_sha256": sha} for path, sha in inputs.manifests],
        "pcaps": [{"path": str(path), "sha256": sha} for path, sha in inputs.pcaps],
        "rows": {"total": inputs.rows, "excluded_lab_or_labelled": inputs.rows_excluded},
        "span": {"first": inputs.first_at, "last": inputs.last_at},
        "device_hours": device_hours,
        "devices": clean_macs,
        "excluded_macs": sorted(exclusions.macs),
        "attack_window_macs": sorted(exclusions.lab_macs - exclusions.macs),
        "excluded_windows": len(exclusions.windows),
        "polls": evaluator.polls,
        "d1_evidence_by_detector": dict(sorted(evaluator.aggregates.d1_by_detector.items())),
        "aggregate_evidence_by_detector": dict(sorted(evaluator.aggregates.by_detector.items())),
        "untargetable_bundles": evaluator.aggregates.untargetable,
        "ml": {"evidence": len(inputs.ml)},
        "meters_simulated": meters,
        "scenarios": per_scenario,
        "verdict": {"forward_guard_may_enforce": verdict, "reason": reason},
    }


def forward_verdict(
    inputs: Inputs,
    scenarios: list[Scenario],
    exclusions: Exclusions,
    meters: bool,
    device_hours: float,
    min_device_hours: float,
) -> tuple[bool, str]:
    """G5's answer for the forward guard, with the first reason it fails."""
    if inputs.env_tag != "pi-live":
        return (
            False,
            f"env tag is {inputs.env_tag}; only pi-live benign data can clear the forward guard (G5)",
        )
    if not meters:
        return False, "the kernel meters were not simulated (--no-meters)"
    if device_hours < min_device_hours:
        return (
            False,
            f"only {device_hours:g} clean device-hours (< {min_device_hours:g}); the bound 3/T is too weak",
        )
    scenario = next((item for item in scenarios if item.modes[GuardName.FORWARD] is GuardMode.ENFORCE), None)
    if scenario is None or scenario.simulator is None:
        return False, "no forward-enforce scenario was simulated"
    forward = [
        trip
        for trip in scenario.simulator.trips.values()
        if OFFENDER_GUARD[trip.code] is GuardName.FORWARD and not exclusions.excluded(trip.mac, trip.first_at)
    ]
    if forward:
        macs = sorted({trip.mac for trip in forward})
        return False, f"forward meters tripped on clean devices {macs} ({sum(t.hits for t in forward)} hits)"
    backstop = scenario.simulator.counters.backstop_hits.get(_FORWARD_BACKSTOP, 0)
    if backstop:
        return False, f"the forward backstop {_FORWARD_BACKSTOP} hit {backstop} times"
    active = scenario.tallies[EnforcementMode.ACTIVE]
    enforce = {
        mac: active.enforce(mac) for mac in active.rate_limit | active.block if mac not in exclusions.lab_macs
    }
    if any(enforce.values()):
        return False, f"enforce actions against clean devices with the forward guard enforcing: {enforce}"
    return True, (
        f"zero forward meter trips and zero enforce actions over {device_hours:g} clean pi-live device-hours "
        f"(rule of three: < {3.0 / device_hours:.4g} per device-hour)"
    )


# --------------------------------------------------------------------- CLI


def _bindings(path: Path | None, protected: IPv4Network) -> dict[IPv4Address, str] | None:
    if path is None:
        return None
    parsed = parse_leases(path.read_text(encoding="utf-8", errors="replace"), protected)
    return {binding.ip: str(binding.mac) for binding in parsed.bindings}


def evaluate(args: argparse.Namespace) -> dict[str, object]:
    """Run the whole evaluation; returns the report (also written under `args.out`)."""
    config = load_config(args.config)
    if args.thresholds is not None:
        config = config.model_copy(
            update={"d1": config.d1.model_copy(update={"thresholds_path": str(args.thresholds)})}
        )
    out = check_output_location(args.out)
    exclusions = _exclusions(args)
    protected = config.network.protected_network
    scorer = (
        _MlScorer(config, args.lightgbm, args.isolation_forest)
        if (args.lightgbm or args.isolation_forest)
        else None
    )
    meters = not args.no_meters
    inputs = read_inputs(args.inputs, exclusions, protected, scorer, args.pcaps, meters)
    spec = TemplateSpec.from_config(config) if meters else None
    pi_mac = unicast_mac(args.pi_mac) if args.pi_mac else None
    scenarios = _scenarios(config, spec, _bindings(args.leases, protected), pi_mac)
    evaluator = Evaluator(config, inputs, scenarios, exclusions)
    evaluator.run(_frames(inputs.pcaps) if meters else iter(()))
    report = build_report(inputs, scenarios, evaluator, exclusions, meters, args.min_device_hours)
    out.mkdir(parents=True, exist_ok=False)
    (out / "fp.json").write_text(
        json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8", newline="\n"
    )
    thresholds_path = _resolve(config.d1.thresholds_path)
    write_manifest(
        out,
        Manifest(
            kind="evaluator",
            env_tag=inputs.env_tag,
            tool=TOOL,
            config_sha256=None,
            extra={
                "inputs": [f"{path.name}:{sha}" for path, sha in inputs.manifests],
                "thresholds_sha256": sha256_file(thresholds_path),
                "policy_table_sha256": sha256_file(_resolve(config.policy.table_path)),
                "forward_guard_may_enforce": bool(report["verdict"]["forward_guard_may_enforce"]),  # type: ignore[index]
            },
        ),
    )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("inputs", nargs="+", type=Path, help="pcap_to_flows output directories (one env tag)")
    parser.add_argument(
        "--out", type=Path, required=True, help="new output directory (lab/runs/... or outside the repo)"
    )
    parser.add_argument("--config", type=Path, default=REPO_ROOT / "config" / "default_config.toml")
    parser.add_argument(
        "--thresholds", type=Path, help="D1 thresholds file (default: the config's d1.thresholds_path)"
    )
    parser.add_argument("--exclude-mac", action="append", default=[], help="lab/attacker MAC to leave out")
    parser.add_argument(
        "--capture-manifest", action="append", default=[], help="capture directory with lab_macs"
    )
    parser.add_argument("--ground-truth", action="append", default=[], help="ground_truth.jsonl lab windows")
    parser.add_argument("--pcaps", type=Path, help="directory holding the pcaps the manifests name")
    parser.add_argument(
        "--no-meters", action="store_true", help="skip the kernel-meter simulator (verdict: no)"
    )
    parser.add_argument("--leases", type=Path, help="dnsmasq lease file for bound4/macbind (default: learnt)")
    parser.add_argument("--pi-mac", help="the Pi's LAN MAC (default: learnt from its own frames)")
    parser.add_argument("--lightgbm", type=Path, help="D3 model artifact (optional)")
    parser.add_argument("--isolation-forest", type=Path, help="D2 model artifact (optional)")
    parser.add_argument(
        "--min-device-hours",
        type=float,
        default=24.0,
        help="clean device-hours needed before the forward guard can be cleared (default 24)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Exit 0 with a report (whatever the verdict), 2 on a refusal."""
    args = build_parser().parse_args(argv)
    try:
        report = evaluate(args)
    except (LabError, ManifestError, PirewallError, OSError, ValueError) as exc:
        print(f"benign_fp: {exc}", file=sys.stderr)
        return 2
    verdict = report["verdict"]
    assert isinstance(verdict, dict)
    answer = "yes" if verdict["forward_guard_may_enforce"] else "no"
    print(
        f"env tag {report['env_tag']}, {report['device_hours']:g} clean device-hours "
        f"-> {args.out / 'fp.json'}"
    )
    print(f"forward guard may enforce: {answer} — {verdict['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

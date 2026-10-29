"""Python half of `scripts/deployment/pirewall-start` v2 (phase 16, PLAN_v3 §6).

The bash script owns ordering, services and the `--dry-run` contract; this
module owns everything that needs the validated config or the v2 kernel
API. Each subcommand does one step of the bring-up, so the dry run prints
the real sequence and each step stays testable on its own:

======================  ======================================================
`preflight`             The v2 refusals (exit 2, each with a fix) and reports.
`render`                Render every template, with the guard verdicts the
                        tables should *load* with (raw always observe: it is
                        raised only once bindings are seeded).
`seed`                  Bindings (lease file + `[[antispoof.static]]`) and the
                        allowlist pairs into the kernel sets, through
                        `FirewallManager`. Prints `SEEDED=1|0`.
`guards`                Set the three guard verdicts through
                        `FirewallManager.set_guard_mode`; raw enforces only if
                        seeded (D2).
`manifest`              The run manifest (git SHA, hashes, versions, modes,
                        env tag, ruleset hash).
`panic`                 Delete the v2 tables: through core's RPC when core
                        answers (so its state matches), else directly.
`mock-config`           A self-contained `--data-mode mock` run directory:
                        config, throwaway TLS, a generated admin password.
`lab-env`/`lab-ruleset` Shell variables and the rendered `pirewall_lab` table
                        for `--lab-victim`.
`crashloop-alert`       Run by `pirewall-crashloop-alert.service` (core's
                        `OnFailure=`): a CRITICAL to syslog and, if enabled,
                        to Wazuh. The guards keep running in the kernel.
======================  ======================================================

**Single writer.** Every kernel write here goes through `FirewallManager`,
the same class core uses, so each set keeps exactly one writer *type* (D1).
`pirewall-start` runs these before core starts, and core reseeds and
reconciles on its own start. Like `pirewall.runtime.core`, this module only
*constructs* a backend and hands it to the manager; it never calls one.

**Probes are overridable** through `PIREWALL_PREFLIGHT_*` environment
variables (documented on `SystemProbe`), so every refusal is testable
without the real system state it describes.

Spec §21 still holds: nothing here changes network configuration. The
kernel writes are the reviewed v2 tables' sets and verdict chains only.
"""

import argparse
import hashlib
import importlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import syslog
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from pydantic import ValidationError

from pirewall.config.loader import load_config
from pirewall.config.models import PirewallConfig
from pirewall.core import nft_names
from pirewall.core.bindings import LeaseBindingTable, static_bindings
from pirewall.core.enums import (
    EnforcementMode,
    EnvTag,
    EventSeverity,
    GuardMode,
    GuardName,
    PipelineEngine,
    SecurityEventType,
)
from pirewall.core.exceptions import ConfigurationError, FirewallError, IntegrationError, RpcError
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.core.passwords import hash_password
from pirewall.detection_v2.thresholds import load_thresholds
from pirewall.firewall.allowlist_store import AllowlistStore
from pirewall.firewall.backend.nftables import NftablesBackend
from pirewall.firewall.backend.nftables_sets import NftablesSetBackend
from pirewall.firewall.guards import effective_raw_mode
from pirewall.firewall.manager import FirewallManager
from pirewall.integration.wazuh import SyslogWazuhTransport, WazuhForwarder, WazuhTransport
from pirewall.ipc.client import UnixSocketRpcClient
from pirewall.ml.artifacts.metadata import metadata_path_for
from pirewall.runtime.core import IMPLEMENTED_ENGINES
from pirewall.runtime.lease_sync import LeaseSync
from scripts.deployment.migrate_config import MigrationError, migrate_text
from scripts.deployment.render_templates import missing_tokens, render_all

REPO_ROOT = Path(__file__).resolve().parents[2]
LAB_TEMPLATE = REPO_ROOT / "deploy" / "lab" / "pirewall_lab.nft.template"
MANIFEST_SCHEMA = "pirewall-run-manifest/1"
ACTOR = "pirewall-start"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2

DataMode = Literal["live", "scripted", "mock"]
_ENV_FOR_DATA_MODE: Mapping[str, EnvTag] = {
    "live": EnvTag.PI_LIVE,
    "scripted": EnvTag.PI_SCRIPTED,
    "mock": EnvTag.MOCK,
}
_NFT_FLUSH_RULESET = "flush ruleset"


# --------------------------------------------------------------------- probes


class SystemProbe:
    """Reads the system facts preflight decides on. Each one can be overridden for tests.

    =========================================  ===================================================
    `PIREWALL_PREFLIGHT_NFTABLES_ENABLED`      `enabled`/`disabled`, instead of `systemctl is-enabled`
    `PIREWALL_PREFLIGHT_NFTABLES_CONF`         path read instead of `/etc/nftables.conf`
    `PIREWALL_PREFLIGHT_PROC_ROOT`             directory read instead of `/proc`
    `PIREWALL_PREFLIGHT_CHRONY`                `synced`/`unsynced`/`missing`, instead of `chronyc`
    `PIREWALL_PREFLIGHT_TRANSPORT`             `libnftables`/`subprocess`, instead of importing it
    =========================================  ===================================================
    """

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._env = os.environ if environ is None else environ

    def nftables_service_enabled(self) -> bool | None:
        """Whether `nftables.service` is enabled; None when that cannot be asked (no systemd)."""
        override = self._env.get("PIREWALL_PREFLIGHT_NFTABLES_ENABLED")
        if override is not None:
            return override.strip() == "enabled"
        if shutil.which("systemctl") is None:
            return None
        result = subprocess.run(
            ["systemctl", "is-enabled", "nftables.service"], capture_output=True, text=True, check=False
        )
        return result.stdout.strip() == "enabled"

    def nftables_conf(self) -> tuple[Path, str | None]:
        """The `nftables.service` config file and its text (None when unreadable or absent)."""
        path = Path(self._env.get("PIREWALL_PREFLIGHT_NFTABLES_CONF", "/etc/nftables.conf"))
        try:
            return path, path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return path, None

    def _proc(self) -> Path:
        return Path(self._env.get("PIREWALL_PREFLIGHT_PROC_ROOT", "/proc"))

    def ipv6_disabled(self, interface: str) -> bool | None:
        """`net.ipv6.conf.<interface>.disable_ipv6 == 1`; True with no IPv6 at all; None if no interface."""
        ipv6 = self._proc() / "sys" / "net" / "ipv6" / "conf"
        if not ipv6.is_dir():
            return True
        flag = ipv6 / interface / "disable_ipv6"
        try:
            return flag.read_text(encoding="utf-8").strip() == "1"
        except OSError:
            return None

    def is_raspberry_pi(self) -> bool:
        """Whether the device-tree model names a Raspberry Pi (the only host a `pi-*` tag is true on)."""
        model = self._proc() / "device-tree" / "model"
        try:
            return "Raspberry Pi" in model.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False

    def chrony(self) -> Literal["synced", "unsynced", "missing"]:
        """chrony's sync state. Manifests carry timestamps; an unsynced clock makes them lie."""
        override = self._env.get("PIREWALL_PREFLIGHT_CHRONY")
        if override in {"synced", "unsynced", "missing"}:
            return override  # pyright: ignore[reportReturnType] -- narrowed by the membership test
        if shutil.which("chronyc") is None:
            return "missing"
        result = subprocess.run(["chronyc", "tracking"], capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            if line.strip().startswith("Leap status") and line.split(":", 1)[-1].strip() == "Normal":
                return "synced"
        return "unsynced"

    def nft_transport(self) -> str:
        """`libnftables` when `python3-nftables` imports from this interpreter, else `subprocess`."""
        override = self._env.get("PIREWALL_PREFLIGHT_TRANSPORT")
        if override is not None:
            return override
        try:
            importlib.import_module("nftables")
        except ImportError:
            return "subprocess"
        return "libnftables"

    def native(self) -> tuple[bool, bool]:
        """(`pirewall_native` imports, it was built with `HAS_PACKET_RING`)."""
        try:
            module = importlib.import_module("pirewall_native")
        except ImportError:
            return False, False
        return True, bool(getattr(module, "HAS_PACKET_RING", False))


# ------------------------------------------------------------------ preflight


@dataclass(frozen=True, slots=True)
class Finding:
    """One preflight result. `refuse` stops the bring-up with exit 2; `fix` says what to do."""

    level: Literal["ok", "warn", "refuse"]
    message: str
    fix: str = ""


@dataclass(frozen=True, slots=True)
class ModelCheck:
    """One model artifact: where it is, its hash on disk, and what its sidecar claims."""

    name: str
    path: Path
    present: bool
    sha256: str | None
    claimed_sha256: str | None
    sidecar_error: str | None = None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_models(config: PirewallConfig, repo_root: Path = REPO_ROOT) -> list[ModelCheck]:
    """Hash each configured model artifact and read the hash its sidecar claims, if any."""
    checks: list[ModelCheck] = []
    for name, raw in (
        ("lightgbm", config.ml.lightgbm_model_path),
        ("isolation_forest", config.ml.isolation_forest_model_path),
    ):
        path = Path(raw) if Path(raw).is_absolute() else repo_root / raw
        if not path.is_file():
            checks.append(ModelCheck(name, path, False, None, None))
            continue
        claimed: str | None = None
        error: str | None = None
        try:
            metadata = ModelMetadata.model_validate_json(metadata_path_for(path).read_text(encoding="utf-8"))
            claimed = metadata.artifact_sha256
        except (OSError, ValidationError) as exc:
            error = str(exc).splitlines()[0]
        checks.append(ModelCheck(name, path, True, sha256_file(path), claimed, error))
    return checks


def _d1_thresholds_finding(config: PirewallConfig, repo_root: Path) -> Finding:
    """`engine = "v2"` in ASSISTED/ACTIVE needs a valid D1 thresholds file (phase 17); SHADOW warns."""
    path = Path(config.d1.thresholds_path)
    if not path.is_absolute():
        path = repo_root / path
    try:
        thresholds = load_thresholds(path)
    except ConfigurationError as exc:
        if config.firewall.enforcement_mode is EnforcementMode.SHADOW:
            return Finding("warn", f"{exc}; SHADOW runs on the documented D1 floors")
        return Finding(
            "refuse",
            f"engine v2 in {config.firewall.enforcement_mode.value} mode needs the D1 thresholds: {exc}",
            "Write it with `uv run python -m scripts.train.fit_d1_thresholds --floors-only`, or fit it "
            "from benign pcap_to_flows output (RUNBOOK H20).",
        )
    state = "frozen" if thresholds.frozen else "not frozen"
    source = thresholds.provenance.get("source", "fitted")
    count = len(thresholds.thresholds)
    return Finding("ok", f"D1 thresholds {path.name}: {count} entries, {source}, {state}")


def requested_engine(config: PirewallConfig, engine: str | None) -> PipelineEngine:
    return PipelineEngine(engine) if engine is not None else config.pipeline.engine


def preflight(
    config: PirewallConfig,
    config_text: str,
    *,
    engine: str | None,
    data_mode: DataMode | None,
    probe: SystemProbe,
    repo_root: Path = REPO_ROOT,
) -> list[Finding]:
    """Every v2 preflight check, in order. Refusals carry the command that fixes them."""
    findings: list[Finding] = []
    chosen = requested_engine(config, engine)
    mock = data_mode == "mock"

    if chosen not in IMPLEMENTED_ENGINES:
        findings.append(
            Finding(
                "refuse",
                f"pipeline engine {chosen.value!r} is not implemented in this pirewall-core",
                "Run with --engine v1 or --engine v2.",
            )
        )
    else:
        findings.append(Finding("ok", f"pipeline engine {chosen.value}"))
    if chosen is PipelineEngine.V2:
        findings.append(_d1_thresholds_finding(config, repo_root))

    if not mock:
        try:
            changes = migrate_text(config_text).changes
        except MigrationError as exc:
            changes = [f"cannot be migrated: {exc}"]
        if changes:
            findings.append(
                Finding(
                    "refuse",
                    "config/local_config.toml needs migration to the v2 schema: " + "; ".join(changes),
                    "Back it up and migrate:  uv run python -m scripts.deployment.migrate_config --write",
                )
            )
        else:
            findings.append(Finding("ok", "config is on the v2 schema"))

    if not mock:
        missing_identity = [
            label
            for label, value in (
                ("admin.admin_pc_mac", config.admin.admin_pc_mac),
                ("network.admin_interface", config.network.admin_interface),
            )
            if value is None
        ]
        if missing_identity:
            findings.append(
                Finding(
                    "refuse",
                    f"the admin identity is incomplete: {', '.join(missing_identity)} unset. The base "
                    "ruleset pins admin access to interface + MAC + IP (ADDENDUM_4.md D3).",
                    "Set them with:  uv run python -m scripts.deployment.configure --admin-identity",
                )
            )
        else:
            findings.append(
                Finding("ok", f"admin pinned to {config.network.admin_interface} {config.admin.admin_pc_mac}")
            )

        enabled = probe.nftables_service_enabled()
        conf_path, conf_text = probe.nftables_conf()
        if enabled and conf_text is not None and _flushes_ruleset(conf_text):
            findings.append(
                Finding(
                    "refuse",
                    f"nftables.service is enabled and {conf_path} contains `flush ruleset`: the next time "
                    "it runs it deletes every pirewall table, silently (ADDENDUM_4.md D1).",
                    "Disable it:  sudo systemctl disable --now nftables.service",
                )
            )
        elif enabled is None:
            findings.append(Finding("warn", "could not ask systemd whether nftables.service is enabled"))
        else:
            findings.append(Finding("ok", "nftables.service cannot flush the ruleset under pirewall"))

        lan = config.network.lan_interface
        disabled = probe.ipv6_disabled(lan)
        if disabled is False:
            findings.append(
                Finding(
                    "refuse",
                    f"IPv6 is enabled on the LAN interface {lan}; v2 drops IPv6 on the LAN and the "
                    "adaptive pipeline is IPv4-only (A5, ADDENDUM_4.md D3).",
                    f"Disable it:  sudo sysctl -w net.ipv6.conf.{lan}.disable_ipv6=1  and persist it: "
                    f"echo 'net.ipv6.conf.{lan}.disable_ipv6 = 1' | "
                    "sudo tee /etc/sysctl.d/60-pirewall-ipv6.conf",
                )
            )
        elif disabled is None:
            findings.append(Finding("warn", f"cannot read net.ipv6.conf.{lan}.disable_ipv6 (is {lan} up?)"))
        else:
            findings.append(Finding("ok", f"IPv6 disabled on {lan}"))

    if data_mode in {"live", "scripted"} and not probe.is_raspberry_pi():
        tag = _ENV_FOR_DATA_MODE[data_mode or "live"].value
        findings.append(
            Finding(
                "refuse",
                f"--data-mode {data_mode} claims the {tag} env tag, but this is not a Raspberry Pi. Only "
                "real Pi runs may carry a pi-* tag (ADDENDUM_4.md D7).",
                "Run without --data-mode (env tag from the config, default sandbox), or use "
                "--data-mode mock.",
            )
        )

    findings.extend(_model_findings(config, chosen, repo_root))

    transport = probe.nft_transport()
    if not mock:
        if transport == "libnftables":
            findings.append(Finding("ok", "nft transport: libnftables (python3-nftables)"))
        else:
            findings.append(
                Finding(
                    "warn",
                    "nft transport: `nft -j -f -` subprocess fallback (python3-nftables is not importable "
                    "from this venv; set updates are slower)",
                    "Link it in:  sudo scripts/deployment/install_nftables_pth.sh",
                )
            )
    present, ring = probe.native()
    if present and ring:
        findings.append(Finding("ok", "pirewall_native present with HAS_PACKET_RING"))
    elif present:
        findings.append(Finding("warn", "pirewall_native present without the packet ring; live capture "
                                        "uses the Python path"))
    else:
        findings.append(
            Finding(
                "warn",
                "pirewall_native is not installed; capture uses the Python path, which drops packets "
                "under load",
                "Install it:  uv sync --extra native",
            )
        )
    if not mock:
        lease_file = Path(config.antispoof.lease_file)
        if os.access(lease_file, os.R_OK):
            findings.append(Finding("ok", f"lease file {lease_file} is readable"))
        else:
            findings.append(
                Finding(
                    "warn",
                    f"lease file {lease_file} is not readable: the binding seed will fail and the raw "
                    "guard stays in observe (ADDENDUM_4.md D2)",
                    "Check antispoof.lease_file (it follows network.lan_interface while unset) and that "
                    "the NetworkManager hotspot is up",
                )
            )
        state = probe.chrony()
        if state == "synced":
            findings.append(Finding("ok", "chrony is synchronised"))
        else:
            findings.append(
                Finding(
                    "warn",
                    f"chrony is {state}: manifest and event timestamps may be wrong",
                    "Check:  chronyc tracking",
                )
            )
    return findings


def _flushes_ruleset(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if " ".join(stripped.split()) == _NFT_FLUSH_RULESET:
            return True
    return False


def _model_findings(config: PirewallConfig, engine: PipelineEngine, repo_root: Path) -> list[Finding]:
    checks = check_models(config, repo_root)
    if engine is PipelineEngine.V2 and not any(check.present for check in checks):
        return [Finding("ok", "no model artifacts, and engine v2 runs without ML: hash check skipped")]
    findings: list[Finding] = []
    for check in checks:
        if not check.present:
            findings.append(Finding("warn", f"{check.name}: no artifact at {check.path}; running without it"))
        elif check.sidecar_error is not None:
            findings.append(
                Finding(
                    "refuse",
                    f"{check.name}: the metadata sidecar for {check.path} cannot be read: "
                    f"{check.sidecar_error}",
                    "Restore the artifact and its .metadata.json together, or retrain (docs/ML_PIPELINE.md).",
                )
            )
        elif check.claimed_sha256 is None:
            findings.append(
                Finding(
                    "warn",
                    f"{check.name}: its sidecar records no artifact_sha256 (trained before phase 16); "
                    f"cannot verify, recording sha256 {check.sha256} in the manifest",
                )
            )
        elif check.claimed_sha256 != check.sha256:
            findings.append(
                Finding(
                    "refuse",
                    f"{check.name}: {check.path} has sha256 {check.sha256}, but its sidecar says "
                    f"{check.claimed_sha256}. The artifact and its metadata do not belong together.",
                    "Restore the artifact and its .metadata.json together, or retrain (docs/ML_PIPELINE.md).",
                )
            )
        else:
            findings.append(Finding("ok", f"{check.name}: artifact matches its sidecar hash"))
    return findings


def print_findings(findings: Sequence[Finding]) -> bool:
    """Print findings the way the bash script prints its own; True when none refuses."""
    symbols = {"ok": "✓", "warn": "!", "refuse": "✗"}
    for finding in findings:
        print(f"    {symbols[finding.level]} {finding.message}")
        if finding.fix and finding.level != "ok":
            print(f"      {finding.fix}")
    return not any(finding.level == "refuse" for finding in findings)


# ----------------------------------------------------------- kernel steps


def guard_modes_from_args(config: PirewallConfig, args: argparse.Namespace) -> dict[GuardName, GuardMode]:
    """Config modes, then `--guards` for all three, then the per-guard flags (most specific wins)."""
    modes = {
        GuardName.RAW: config.guards.raw_mode,
        GuardName.INPUT: config.guards.input_mode,
        GuardName.FORWARD: config.guards.forward_mode,
    }
    everything: str | None = args.guards
    if everything is not None:
        modes = dict.fromkeys(GuardName, GuardMode(everything))
    for guard in GuardName:
        override: str | None = getattr(args, f"guard_{guard.value}")
        if override is not None:
            modes[guard] = GuardMode(override)
    return modes


def load_modes(requested: Mapping[GuardName, GuardMode]) -> dict[GuardName, GuardMode]:
    """The verdicts the templates load with: as requested, except raw, which waits for the seed (D2)."""
    modes = dict(requested)
    modes[GuardName.RAW] = GuardMode.OBSERVE
    return modes


def with_guard_modes(config: PirewallConfig, modes: Mapping[GuardName, GuardMode]) -> PirewallConfig:
    guards = config.guards.model_copy(
        update={
            "raw_mode": modes[GuardName.RAW],
            "input_mode": modes[GuardName.INPUT],
            "forward_mode": modes[GuardName.FORWARD],
        }
    )
    return config.model_copy(update={"guards": guards})


def build_manager(config: PirewallConfig) -> FirewallManager:
    """A `FirewallManager` on the real kernel sets: the one writer of every set it touches (D1).

    The v1 backend is required by the constructor but never used here: no
    rule is submitted and no portal client is authorised.
    """
    return FirewallManager(
        config,
        NftablesBackend(config.firewall.rate_limit_per_second),
        AllowlistStore(config.firewall.allowlist_store_path),
        set_backend=NftablesSetBackend(),
    )


def _print_event(event: SecurityEvent) -> None:
    print(f"    [{event.severity.value}] {event.reason}", file=sys.stderr)


def seed(config: PirewallConfig, manager: FirewallManager) -> bool:
    """Bindings, then the allowlist pairs. False when the binding seed failed (raw stays observe)."""
    table = LeaseBindingTable(static_bindings(config.antispoof.static))
    seeded = LeaseSync(config, table, manager, on_event=_print_event).seed()
    print(f"    bindings: {len(table.snapshot())} ({'seeded' if seeded else 'seed FAILED'})", file=sys.stderr)
    try:
        pairs = manager.sync_allowlist()
        print(f"    allow_bound: {pairs} allowlist MAC+IP pair(s)", file=sys.stderr)
    except FirewallError as exc:
        print(f"    allow_bound: writing the allowlist pairs failed: {exc}", file=sys.stderr)
    return seeded


def set_guards(
    manager: FirewallManager, requested: Mapping[GuardName, GuardMode], seeded: bool, now: datetime
) -> dict[GuardName, GuardMode]:
    """Set every verdict chain (one atomic batch each), raw enforcing only if seeded. Returns what was set."""
    applied = dict(requested)
    applied[GuardName.RAW] = effective_raw_mode(requested[GuardName.RAW], seeded)
    if applied[GuardName.RAW] is not requested[GuardName.RAW]:
        print(
            "    ! raw guard left in observe: the bindings were not seeded, and enforcing anti-spoof "
            "with an empty binding set would meter every client as unbound (ADDENDUM_4.md D2)",
            file=sys.stderr,
        )
    for guard in GuardName:
        _print_event(manager.set_guard_mode(guard, applied[guard], ACTOR, now))
    return applied


# ------------------------------------------------------------------ manifest


def _run_text(command: Sequence[str], cwd: Path | None = None) -> str | None:
    if shutil.which(command[0]) is None:
        return None
    result = subprocess.run(list(command), capture_output=True, text=True, check=False, cwd=cwd)
    return result.stdout.strip() if result.returncode == 0 else None


def build_manifest(
    config: PirewallConfig,
    config_path: Path,
    *,
    env_tag: EnvTag,
    data_mode: str | None,
    engine: PipelineEngine,
    guard_modes: Mapping[GuardName, GuardMode],
    guard_modes_source: str,
    ruleset_text: str | None,
    repo_root: Path = REPO_ROOT,
    now: datetime | None = None,
) -> dict[str, object]:
    """Everything a result needs to be traced back to (PLAN_v3 G7). Pure apart from reading files/git."""
    git_sha = _run_text(["git", "rev-parse", "HEAD"], cwd=repo_root)
    status = _run_text(["git", "status", "--porcelain"], cwd=repo_root)
    return {
        "schema": MANIFEST_SCHEMA,
        "created_at": (now or datetime.now(UTC)).isoformat(),
        "env": env_tag.value,
        "data_mode": data_mode,
        "git": {"sha": git_sha, "dirty": None if status is None else bool(status)},
        "config": {"path": str(config_path), "sha256": sha256_file(config_path)},
        "models": {
            check.name: {
                "path": str(check.path),
                "present": check.present,
                "sha256": check.sha256,
                "sidecar_sha256": check.claimed_sha256,
            }
            for check in check_models(config, repo_root)
        },
        "versions": {
            "nft": _run_text(["nft", "--version"]),
            "kernel": platform.release(),
            "python": platform.python_version(),
        },
        "guards": {guard.value: mode.value for guard, mode in guard_modes.items()},
        "guards_source": guard_modes_source,
        "enforcement_mode": config.firewall.enforcement_mode.value,
        "pipeline_engine": engine.value,
        "ruleset_sha256": None
        if ruleset_text is None
        else hashlib.sha256(ruleset_text.encode("utf-8")).hexdigest(),
    }


def write_manifest(manifest: Mapping[str, object], paths: Sequence[Path]) -> None:
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


# --------------------------------------------------------------------- panic


def panic(config: PirewallConfig, actor: str, *, direct: bool = False) -> int:
    """Delete the v2 tables. Through core when it answers, so its rules go REMOVED and mode SHADOW."""
    deleted: tuple[str, ...]
    restore: str
    route = "pirewall-core"
    try:
        if direct:
            raise RpcError("--direct given")
        result = UnixSocketRpcClient(config.api.rpc_socket_path, timeout_seconds=5.0).panic(actor)
        deleted, restore = result.deleted_tables, result.restore_command
    except RpcError as exc:
        route = "directly"
        if not direct:
            print(f"    pirewall-core did not answer ({exc}); deleting the tables directly", file=sys.stderr)
        try:
            result, _event = build_manager(config).panic(actor, datetime.now(UTC))
        except FirewallError as error:
            print(f"panic failed: {error}", file=sys.stderr)
            return EXIT_FAILED
        deleted, restore = result.deleted_tables, result.restore_command
    message = (
        f"pirewall PANIC by {actor} ({route}): deleted {', '.join(deleted) or 'nothing'}; "
        f"pirewall_base and pirewall_portal untouched. Restore with: {restore}"
    )
    syslog.openlog("pirewall-start", 0, syslog.LOG_AUTH)
    syslog.syslog(syslog.LOG_CRIT, message)
    print(message)
    return EXIT_OK


# ----------------------------------------------------------- crash-loop alert


def crashloop_message(unit: str) -> str:
    """The CRITICAL text: what is down, what keeps running, and how to recover."""
    return (
        f"pirewall CRITICAL: {unit} has failed and systemd stopped restarting it (crash loop). "
        "Detection and adaptive enforcement are DOWN. The static kernel guards and the "
        "fail-open base policy keep running. Inspect: journalctl -u "
        f"{unit} -n 200; recover: sudo systemctl reset-failed {unit} && sudo systemctl start {unit}"
    )


def crashloop_alert(
    config_path: Path,
    unit: str,
    transport_factory: Callable[[str, int], WazuhTransport] = SyslogWazuhTransport,
) -> int:
    """Raise core's crash loop to syslog (always) and Wazuh (when enabled). Exit 1 if Wazuh failed.

    Syslog goes first and needs no config: a config core cannot load may be
    exactly why it is crash-looping, and the alert must still go out.
    """
    message = crashloop_message(unit)
    syslog.openlog("pirewall-crashloop-alert", 0, syslog.LOG_DAEMON)
    syslog.syslog(syslog.LOG_CRIT, message)
    print(message, file=sys.stderr)
    try:
        config = load_config(config_path)
    except ConfigurationError as exc:
        print(f"    config unreadable ({exc}); syslog only", file=sys.stderr)
        return EXIT_OK
    integration = config.integration
    if not integration.wazuh_enabled or integration.wazuh_host is None or integration.wazuh_port is None:
        return EXIT_OK
    event = SecurityEvent(
        timestamp=datetime.now(UTC),
        severity=EventSeverity.CRITICAL,
        event_type=SecurityEventType.SYSTEM_WARNING,
        subsystem="systemd.crashloop",
        reason=message,
    )
    transport = transport_factory(integration.wazuh_host, integration.wazuh_port)
    try:
        WazuhForwarder(transport, enabled=True).forward(event)
    except IntegrationError as exc:
        syslog.syslog(syslog.LOG_ERR, f"crash-loop alert not forwarded to Wazuh: {exc}")
        print(f"    Wazuh forward failed: {exc}", file=sys.stderr)
        return EXIT_FAILED
    return EXIT_OK


# ---------------------------------------------------------------- mock mode


def to_toml(document: Mapping[str, object]) -> str:
    """Serialise a JSON-shaped config dump to TOML: tables, arrays of tables, scalars, scalar arrays.

    Only what `PirewallConfig.model_dump(mode="json")` produces. Strings are
    written as JSON strings, which are valid TOML basic strings. None values
    are omitted (an unset optional key).
    """
    lines: list[str] = []
    _emit_table(lines, [], document)
    return "\n".join(lines).strip() + "\n"


def _emit_table(lines: list[str], path: list[str], table: Mapping[str, object]) -> None:
    scalars: list[tuple[str, object]] = []
    tables: list[tuple[str, Mapping[str, object]]] = []
    arrays_of_tables: list[tuple[str, list[Mapping[str, object]]]] = []
    for key, value in table.items():
        if value is None:
            continue
        nested = _as_table(value)
        items = _as_list(value)
        item_tables = [_as_table(item) for item in items] if items else []
        if nested is not None:
            tables.append((key, nested))
        elif item_tables and all(item is not None for item in item_tables):
            arrays_of_tables.append((key, [item for item in item_tables if item is not None]))
        else:
            scalars.append((key, value))
    if path and (scalars or not (tables or arrays_of_tables)):
        lines.append(f"\n[{'.'.join(path)}]")
    for key, value in scalars:
        lines.append(f"{key} = {_toml_value(value)}")
    for key, items in arrays_of_tables:
        for item in items:
            lines.append(f"\n[[{'.'.join([*path, key])}]]")
            for item_key, item_value in item.items():
                if item_value is not None:
                    lines.append(f"{item_key} = {_toml_value(item_value)}")
    for key, value in tables:
        _emit_table(lines, [*path, key], value)


def _as_table(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    mapping = cast("Mapping[object, object]", value)
    return {str(key): item for key, item in mapping.items()}


def _as_list(value: object) -> list[object] | None:
    if not isinstance(value, list | tuple):
        return None
    return list(cast("Sequence[object]", value))


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    items = _as_list(value)
    if items is not None:
        return "[" + ", ".join(_toml_value(item) for item in items) + "]"
    raise ConfigurationError(f"cannot write {value!r} to TOML")


def mock_config(
    source: PirewallConfig,
    run_dir: Path,
    pcap: Path,
    api_port: int,
    password_hash: str,
    engine: str | None = None,
) -> PirewallConfig:
    """`source` rewritten to run entirely inside `run_dir`: replay, loopback, no portal, no forwarding.

    Nothing in the result points at a system path: sockets, logs, state and
    TLS all live under `run_dir`, so a mock run needs no root and leaves the
    host untouched. The env tag is `mock` (D7), never a `pi-*` tag.

    `engine` overrides `pipeline.engine` when `pirewall-start --engine` was
    given; `None` keeps the source config's engine.
    """
    data = source.model_dump(mode="json")
    if engine is not None:
        data["pipeline"]["engine"] = engine
    data["capture"].update(backend="replay", replay_path=str(pcap), replay_speed="max")
    data["api"].update(
        host="127.0.0.1",
        port=api_port,
        rpc_socket_path=str(run_dir / "core.sock"),
        tls_cert_path=str(run_dir / "tls" / "pirewall.crt"),
        tls_key_path=str(run_dir / "tls" / "pirewall.key"),
        log_dir=str(run_dir / "log-api"),
    )
    data["authentication"].update(admin_username="admin", admin_password_hash=password_hash)
    data["admin"].update(admin_pc_ip="127.0.0.1", allow_local_console=True)
    data["portal"].update(
        enabled=False,
        rpc_socket_path=str(run_dir / "portal.sock"),
        user_store_path=str(run_dir / "portal_users.json"),
        log_dir=str(run_dir / "log-portal"),
    )
    data["logging"].update(log_dir=str(run_dir / "log"))
    data["firewall"].update(allowlist_store_path=str(run_dir / "allowlist.json"))
    data["integration"].update(wazuh_enabled=False, netdata_enabled=False)
    data["antispoof"].update(lease_file=str(run_dir / "dnsmasq.leases"))
    data["lab"].update(env_tag=EnvTag.MOCK.value)
    return PirewallConfig.model_validate(data)


def make_throwaway_tls(directory: Path) -> None:
    """A self-signed loopback certificate for the mock API. Never used outside its run directory."""
    if shutil.which("openssl") is None:
        raise ConfigurationError("mock mode needs openssl to make a throwaway loopback certificate")
    directory.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "7",
            "-subj", "/CN=pirewall-mock",
            "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(directory / "pirewall.key"),
            "-out", str(directory / "pirewall.crt"),
        ],
        check=True,
        capture_output=True,
    )
    (directory / "pirewall.key").chmod(0o600)


def prepare_mock_run(
    source_path: Path, run_dir: Path, pcap: Path, api_port: int, engine: str | None = None
) -> dict[str, str]:
    """Write the mock config, password and TLS into `run_dir`. Returns shell variables for the script."""
    run_dir.mkdir(parents=True, exist_ok=True)
    run_dir.chmod(0o700)
    password = os.urandom(18).hex()
    password_file = run_dir / "admin-password"
    password_file.write_text(password + "\n", encoding="utf-8")
    password_file.chmod(0o600)
    (run_dir / "dnsmasq.leases").touch()
    make_throwaway_tls(run_dir / "tls")
    config = mock_config(
        load_config(source_path),
        run_dir,
        pcap.resolve(),
        api_port,
        hash_password(password),
        engine=engine,
    )
    config_path = run_dir / "mock_config.toml"
    config_path.write_text(
        "# Written by pirewall-start --data-mode mock. Throwaway; lives only in this run directory.\n"
        + to_toml(config.model_dump(mode="json")),
        encoding="utf-8",
    )
    load_config(config_path)  # the round trip must validate, or the run would fail later and obscurely
    return {
        "MOCK_CONFIG": str(config_path),
        "MOCK_CORE_SOCK": config.api.rpc_socket_path,
        "MOCK_API_PORT": str(api_port),
        "MOCK_PASSWORD_FILE": str(password_file),
    }


# ------------------------------------------------------------------- lab


def lab_env(config: PirewallConfig) -> dict[str, str]:
    """The lab victim's names and addresses (`[lab]`): host side first usable /30 address, victim second."""
    hosts = list(config.lab.victim_network.hosts())
    host_if = config.lab.victim_host_interface
    return {
        "LAB_NETNS": config.lab.victim_netns,
        "LAB_HOST_IF": host_if,
        "LAB_PEER_IF": (host_if[:14] + "p"),
        "LAB_HOST_IP": str(hosts[0]),
        "LAB_VICTIM_IP": str(hosts[1]),
        "LAB_PREFIX": str(config.lab.victim_network.prefixlen),
        "LAB_TABLE": nft_names.LAB_TABLE,
        "LAN_IF": config.network.lan_interface,
    }


def render_lab_ruleset(config: PirewallConfig, template: Path = LAB_TEMPLATE) -> str:
    """`deploy/lab/pirewall_lab.nft.template` with this config's values. Refuses on any unknown token."""
    env = lab_env(config)
    mapping: dict[str, str | None] = {
        "LAN_INTERFACE": config.network.lan_interface,
        "LAB_INTERFACE": env["LAB_HOST_IF"],
        "PROTECTED_NETWORK": str(config.network.protected_network),
        "LAB_VICTIM_IP": env["LAB_VICTIM_IP"],
        "LAB_FORWARD_MARK": f"0x{nft_names.LAB_FORWARD_MARK:08x}",
    }
    text = template.read_text(encoding="utf-8")
    missing = missing_tokens(text, mapping)
    if missing:
        raise ConfigurationError(f"missing lab template values: {', '.join(missing)}")
    for name, value in mapping.items():
        text = text.replace("${" + name + "}", value or "")
    return text


# ------------------------------------------------------------------- CLI


def _shell(values: Mapping[str, str]) -> str:
    return "".join(f"{key}={shlex.quote(value)}\n" for key, value in values.items())


def _add_guard_args(parser: argparse.ArgumentParser) -> None:
    modes = [mode.value for mode in GuardMode]
    parser.add_argument("--guards", choices=modes, default=None)
    for guard in GuardName:
        parser.add_argument(
            f"--guard-{guard.value}", dest=f"guard_{guard.value}", choices=modes, default=None
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pirewall-start-helper", description=(__doc__ or "").splitlines()[0]
    )
    parser.add_argument("--config", type=Path, default=Path("config/local_config.toml"))
    sub = parser.add_subparsers(dest="command", required=True)

    pre = sub.add_parser("preflight", help="the v2 refusals and reports")
    pre.add_argument("--engine", choices=[engine.value for engine in PipelineEngine], default=None)
    pre.add_argument("--data-mode", choices=["live", "scripted", "mock"], default=None)

    render = sub.add_parser("render", help="render every template with the load-time guard verdicts")
    render.add_argument("--out", type=Path, default=REPO_ROOT / "deploy" / "rendered")
    _add_guard_args(render)

    sub.add_parser("seed", help="seed bindings and allowlist pairs; prints SEEDED=1|0")

    guards = sub.add_parser("guards", help="set the three guard verdicts through FirewallManager")
    guards.add_argument("--seeded", choices=["0", "1"], required=True)
    _add_guard_args(guards)

    manifest = sub.add_parser("manifest", help="write the run manifest")
    manifest.add_argument("--out", type=Path, action="append", required=True)
    manifest.add_argument("--data-mode", choices=["live", "scripted", "mock"], default=None)
    manifest.add_argument("--engine", choices=[engine.value for engine in PipelineEngine], default=None)
    manifest.add_argument("--no-kernel", action="store_true", help="mock: record requested modes, no nft")
    _add_guard_args(manifest)

    panic_parser = sub.add_parser("panic", help="delete the v2 tables")
    panic_parser.add_argument("--actor", default=ACTOR)
    panic_parser.add_argument("--direct", action="store_true", help="skip core, delete the tables directly")

    mock = sub.add_parser("mock-config", help="prepare a --data-mode mock run directory")
    mock.add_argument("--run-dir", type=Path, required=True)
    mock.add_argument("--pcap", type=Path, required=True)
    mock.add_argument("--api-port", type=int, default=18443)
    mock.add_argument(
        "--engine",
        choices=[engine.value for engine in PipelineEngine],
        default=None,
        help="override pipeline.engine",
    )

    sub.add_parser("lab-env", help="shell variables for --lab-victim")
    lab = sub.add_parser("lab-ruleset", help="render the pirewall_lab table")
    lab.add_argument("--out", type=Path, required=True)

    alert = sub.add_parser("crashloop-alert", help="core's OnFailure= hook: CRITICAL to syslog and Wazuh")
    alert.add_argument("--unit", default="pirewall-core.service")
    return parser


def _env_tag(config: PirewallConfig, data_mode: str | None) -> EnvTag:
    return config.lab.env_tag if data_mode is None else _ENV_FOR_DATA_MODE[data_mode]


def _dispatch(args: argparse.Namespace, config_path: Path) -> int:
    command: str = args.command
    if command == "mock-config":
        print(
            _shell(prepare_mock_run(config_path, args.run_dir, args.pcap, args.api_port, args.engine)),
            end="",
        )
        return EXIT_OK
    if command == "crashloop-alert":
        return crashloop_alert(config_path, args.unit)
    config = load_config(config_path)
    if command == "preflight":
        text = config_path.read_text(encoding="utf-8")
        ok = print_findings(
            preflight(config, text, engine=args.engine, data_mode=args.data_mode, probe=SystemProbe())
        )
        return EXIT_OK if ok else EXIT_REFUSED
    if command == "render":
        requested = guard_modes_from_args(config, args)
        written = render_all(with_guard_modes(config, load_modes(requested)), REPO_ROOT, args.out)
        for path in written:
            print(f"    rendered {path.name}")
        return EXIT_OK
    if command == "seed":
        print(f"SEEDED={1 if seed(config, build_manager(config)) else 0}")
        return EXIT_OK
    if command == "guards":
        requested = guard_modes_from_args(config, args)
        applied = set_guards(build_manager(config), requested, args.seeded == "1", datetime.now(UTC))
        print(" ".join(f"{guard.value}={mode.value}" for guard, mode in applied.items()))
        return EXIT_OK
    if command == "manifest":
        return _write_manifest_command(config, config_path, args)
    if command == "panic":
        return panic(config, args.actor, direct=args.direct)
    if command == "lab-env":
        print(_shell(lab_env(config)), end="")
        return EXIT_OK
    if command == "lab-ruleset":
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(render_lab_ruleset(config), encoding="utf-8")
        return EXIT_OK
    raise AssertionError(f"unhandled command {command}")


def _write_manifest_command(config: PirewallConfig, config_path: Path, args: argparse.Namespace) -> int:
    requested = guard_modes_from_args(config, args)
    modes: Mapping[GuardName, GuardMode] = requested
    source = "requested"
    ruleset: str | None = None
    if not args.no_kernel:
        try:
            read = build_manager(config).guard_modes(datetime.now(UTC))
            modes = {GuardName.RAW: read.raw, GuardName.INPUT: read.input, GuardName.FORWARD: read.forward}
            source = "kernel"
        except FirewallError as exc:
            print(f"    ! could not read the guard modes back ({exc}); recording the requested ones",
                  file=sys.stderr)
        ruleset = _run_text(["nft", "list", "ruleset"])
    manifest = build_manifest(
        config,
        config_path,
        env_tag=_env_tag(config, args.data_mode),
        data_mode=args.data_mode,
        engine=requested_engine(config, args.engine),
        guard_modes=modes,
        guard_modes_source=source,
        ruleset_text=ruleset,
    )
    write_manifest(manifest, args.out)
    for path in args.out:
        print(f"    manifest {path} (env={manifest['env']})")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _dispatch(args, args.config)
    except ConfigurationError as exc:
        print(f"pirewall-start: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except FirewallError as exc:
        print(f"pirewall-start: nft refused: {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())

"""`scripts/deployment/startup.py`: the Python half of `pirewall-start` v2 (phase 16).

Preflight refusals are simulated through `SystemProbe`'s environment
overrides and fixture files (a fake `/proc` tree, a fake nftables.conf), so
each refusal is exercised without the system state it describes.
"""

import argparse
import hashlib
import json
import tomllib
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts.deployment import startup
from scripts.deployment.render_templates import render_all

from pirewall.config.loader import load_config
from pirewall.config.models import PirewallConfig
from pirewall.core import nft_names
from pirewall.core.enums import EnvTag, GuardMode, GuardName, PipelineEngine
from pirewall.core.exceptions import IntegrationError
from pirewall.firewall.backend.fake import FakeFirewallBackend
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from pirewall.firewall.manager import FirewallManager
from tests.helpers.config import make_config

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
_REPO = Path(startup.__file__).resolve().parents[2]


def _config(tmp_path: Path, **overrides: Mapping[str, object]) -> PirewallConfig:
    sections: dict[str, dict[str, object]] = {
        "network": {"admin_interface": "eth0"},
        "admin": {"admin_pc_mac": "02:00:00:00:00:50"},
        "ml": {
            "lightgbm_model_path": str(tmp_path / "missing-lgbm.txt"),
            "isolation_forest_model_path": str(tmp_path / "missing-if.joblib"),
        },
        "antispoof": {"lease_file": str(tmp_path / "leases")},
        "firewall": {"allowlist_store_path": str(tmp_path / "allowlist.json")},
    }
    for section, values in overrides.items():
        sections[section] = {**sections.get(section, {}), **values}
    return make_config(**sections)


def _text(config: PirewallConfig) -> str:
    return startup.to_toml(config.model_dump(mode="json"))


@pytest.fixture
def proc(tmp_path: Path) -> Path:
    """A fake /proc: IPv6 disabled on the test LAN (eth1), no device-tree model."""
    root = tmp_path / "proc"
    flag = root / "sys" / "net" / "ipv6" / "conf" / "eth1" / "disable_ipv6"
    flag.parent.mkdir(parents=True)
    flag.write_text("1\n")
    return root


def _probe(proc: Path, **overrides: str) -> startup.SystemProbe:
    environ = {
        "PIREWALL_PREFLIGHT_PROC_ROOT": str(proc),
        "PIREWALL_PREFLIGHT_NFTABLES_ENABLED": "disabled",
        "PIREWALL_PREFLIGHT_NFTABLES_CONF": str(proc / "no-such-nftables.conf"),
        "PIREWALL_PREFLIGHT_CHRONY": "synced",
        "PIREWALL_PREFLIGHT_TRANSPORT": "libnftables",
    }
    environ.update(overrides)
    return startup.SystemProbe(environ)


def _refusals(findings: list[startup.Finding]) -> list[str]:
    return [finding.message for finding in findings if finding.level == "refuse"]


def _preflight(
    config: PirewallConfig,
    probe: startup.SystemProbe,
    *,
    text: str | None = None,
    engine: str | None = None,
    data_mode: startup.DataMode | None = None,
) -> list[startup.Finding]:
    return startup.preflight(
        config, text if text is not None else _text(config), engine=engine, data_mode=data_mode, probe=probe
    )


# ------------------------------------------------------------------ preflight


def test_a_complete_v2_setup_passes(tmp_path: Path, proc: Path) -> None:
    findings = _preflight(_config(tmp_path), _probe(proc))

    assert _refusals(findings) == []
    assert any("IPv6 disabled on eth1" in finding.message for finding in findings)


def test_an_enabled_nftables_service_that_flushes_the_ruleset_is_refused(tmp_path: Path, proc: Path) -> None:
    conf = tmp_path / "nftables.conf"
    conf.write_text("#!/usr/sbin/nft -f\n\nflush   ruleset\n\ntable inet filter {}\n")
    probe = _probe(
        proc, PIREWALL_PREFLIGHT_NFTABLES_ENABLED="enabled", PIREWALL_PREFLIGHT_NFTABLES_CONF=str(conf)
    )

    refusals = _refusals(_preflight(_config(tmp_path), probe))

    assert len(refusals) == 1
    assert "flush ruleset" in refusals[0]


@pytest.mark.parametrize(
    ("enabled", "conf_text"),
    [
        ("disabled", "flush ruleset\n"),
        ("enabled", "# flush ruleset   (commented out)\ntable inet filter {}\n"),
        ("enabled", "table inet filter {}\n"),
    ],
)
def test_nftables_service_is_fine_when_disabled_or_not_flushing(
    tmp_path: Path, proc: Path, enabled: str, conf_text: str
) -> None:
    conf = tmp_path / "nftables.conf"
    conf.write_text(conf_text)
    probe = _probe(
        proc, PIREWALL_PREFLIGHT_NFTABLES_ENABLED=enabled, PIREWALL_PREFLIGHT_NFTABLES_CONF=str(conf)
    )

    assert _refusals(_preflight(_config(tmp_path), probe)) == []


def test_ipv6_on_the_lan_is_refused(tmp_path: Path, proc: Path) -> None:
    (proc / "sys" / "net" / "ipv6" / "conf" / "eth1" / "disable_ipv6").write_text("0\n")

    refusals = _refusals(_preflight(_config(tmp_path), _probe(proc)))

    assert len(refusals) == 1
    assert "IPv6 is enabled on the LAN interface eth1" in refusals[0]


def test_a_host_without_ipv6_at_all_passes(tmp_path: Path) -> None:
    empty_proc = tmp_path / "bare-proc"
    empty_proc.mkdir()

    assert _refusals(_preflight(_config(tmp_path), _probe(empty_proc))) == []


def test_a_config_that_needs_migration_is_refused(tmp_path: Path, proc: Path) -> None:
    config = _config(tmp_path)
    document = config.model_dump(mode="json")
    del document["guards"]
    del document["lab"]

    refusals = _refusals(_preflight(config, _probe(proc), text=startup.to_toml(document)))

    assert len(refusals) == 1
    assert "needs migration" in refusals[0] and "[guards]" in refusals[0]


@pytest.mark.parametrize(
    ("section", "field"),
    [("admin", "admin_pc_mac"), ("network", "admin_interface")],
)
def test_a_missing_admin_identity_is_refused(tmp_path: Path, proc: Path, section: str, field: str) -> None:
    config = _config(tmp_path, **{section: {field: None}})

    refusals = _refusals(_preflight(config, _probe(proc)))

    assert len(refusals) == 1
    assert f"{section}.{field}" in refusals[0]


def _artifact(tmp_path: Path, claimed: str | None) -> Path:
    model = tmp_path / "lightgbm_model.txt"
    model.write_bytes(b"tree\n")
    sidecar = json.loads(
        (_REPO / "pirewall/ml/artifacts/lightgbm_model.txt.metadata.json").read_text(encoding="utf-8")
    )
    if claimed is None:
        sidecar.pop("artifact_sha256", None)
    else:
        sidecar["artifact_sha256"] = claimed
    (tmp_path / "lightgbm_model.txt.metadata.json").write_text(json.dumps(sidecar), encoding="utf-8")
    return model


def test_a_model_that_does_not_match_its_sidecar_hash_is_refused(tmp_path: Path, proc: Path) -> None:
    model = _artifact(tmp_path, "0" * 64)
    config = _config(tmp_path, ml={"lightgbm_model_path": str(model)})

    refusals = _refusals(_preflight(config, _probe(proc)))

    assert len(refusals) == 1
    assert "do not belong together" in refusals[0]


def test_a_matching_hash_passes_and_a_missing_one_only_warns(tmp_path: Path, proc: Path) -> None:
    real = hashlib.sha256(b"tree\n").hexdigest()
    config = _config(tmp_path, ml={"lightgbm_model_path": str(_artifact(tmp_path, real))})
    findings = _preflight(config, _probe(proc))
    assert _refusals(findings) == []
    assert any("matches its sidecar" in finding.message for finding in findings)

    _artifact(tmp_path, None)
    findings = _preflight(config, _probe(proc))
    assert _refusals(findings) == []
    assert any("records no artifact_sha256" in f.message and f.level == "warn" for f in findings)


def test_engine_v2_runs_on_the_shipped_thresholds(tmp_path: Path, proc: Path) -> None:
    findings = _preflight(_config(tmp_path), _probe(proc), engine=PipelineEngine.V2.value)

    assert _refusals(findings) == []
    assert any("D1 thresholds d1_thresholds.toml" in finding.message for finding in findings)


def test_engine_v2_in_assisted_without_thresholds_is_refused(tmp_path: Path, proc: Path) -> None:
    config = _config(
        tmp_path,
        firewall={"enforcement_mode": "assisted"},
        d1={"thresholds_path": str(tmp_path / "missing.toml")},
    )

    refusals = _refusals(_preflight(config, _probe(proc), engine=PipelineEngine.V2.value))

    assert len(refusals) == 1
    assert "D1 thresholds" in refusals[0]


def test_engine_v2_in_shadow_without_thresholds_only_warns(tmp_path: Path, proc: Path) -> None:
    config = _config(tmp_path, d1={"thresholds_path": str(tmp_path / "missing.toml")})

    findings = _preflight(config, _probe(proc), engine=PipelineEngine.V2.value)

    assert _refusals(findings) == []
    assert any(finding.level == "warn" and "D1 floors" in finding.message for finding in findings)


@pytest.mark.parametrize("data_mode", ["live", "scripted"])
def test_a_pi_tag_is_refused_off_a_pi(tmp_path: Path, proc: Path, data_mode: startup.DataMode) -> None:
    refusals = _refusals(_preflight(_config(tmp_path), _probe(proc), data_mode=data_mode))

    assert len(refusals) == 1
    assert f"pi-{data_mode}" in refusals[0]


def test_a_pi_tag_is_allowed_on_a_pi(tmp_path: Path, proc: Path) -> None:
    model = proc / "device-tree" / "model"
    model.parent.mkdir(parents=True)
    model.write_text("Raspberry Pi 4 Model B Rev 1.5\x00")

    assert _refusals(_preflight(_config(tmp_path), _probe(proc), data_mode="live")) == []


def test_mock_mode_skips_every_host_check(tmp_path: Path, proc: Path) -> None:
    (proc / "sys" / "net" / "ipv6" / "conf" / "eth1" / "disable_ipv6").write_text("0\n")
    config = _config(tmp_path, admin={"admin_pc_mac": None})

    findings = _preflight(
        config, _probe(proc, PIREWALL_PREFLIGHT_NFTABLES_ENABLED="enabled"), data_mode="mock"
    )

    assert _refusals(findings) == []


def test_the_reports_say_which_transport_and_engine(tmp_path: Path, proc: Path) -> None:
    findings = _preflight(_config(tmp_path), _probe(proc, PIREWALL_PREFLIGHT_TRANSPORT="subprocess"))

    fallback = [f for f in findings if "subprocess fallback" in f.message]
    assert fallback and fallback[0].level == "warn"
    assert "install_nftables_pth.sh" in fallback[0].fix


def test_an_unreadable_lease_file_is_a_warning_not_a_refusal(tmp_path: Path, proc: Path) -> None:
    """The seed would fail and raw would stay observe: worth saying, not worth refusing (D2)."""
    missing = _preflight(_config(tmp_path), _probe(proc))
    (tmp_path / "leases").write_text("", encoding="utf-8")
    present = _preflight(_config(tmp_path), _probe(proc))

    assert [f.level for f in missing if "lease file" in f.message] == ["warn"]
    assert [f.level for f in present if "lease file" in f.message] == ["ok"]
    assert _refusals(missing) == []


# ------------------------------------------------------ guard modes / render


def _args(**values: str | None) -> argparse.Namespace:
    defaults: dict[str, str | None] = {
        "guards": None,
        "guard_raw": None,
        "guard_input": None,
        "guard_forward": None,
    }
    defaults.update(values)
    return argparse.Namespace(**defaults)


def test_guard_flags_override_the_config_most_specific_last(tmp_path: Path) -> None:
    config = _config(tmp_path)

    assert startup.guard_modes_from_args(config, _args()) == {
        GuardName.RAW: GuardMode.ENFORCE,
        GuardName.INPUT: GuardMode.ENFORCE,
        GuardName.FORWARD: GuardMode.OBSERVE,
    }
    assert startup.guard_modes_from_args(config, _args(guards="observe", guard_input="enforce")) == {
        GuardName.RAW: GuardMode.OBSERVE,
        GuardName.INPUT: GuardMode.ENFORCE,
        GuardName.FORWARD: GuardMode.OBSERVE,
    }


def test_the_tables_load_with_raw_in_observe_whatever_was_asked(tmp_path: Path) -> None:
    """D2: the raw guard is raised to enforce only after the seed, never at load."""
    config = _config(tmp_path)
    load = startup.load_modes(dict.fromkeys(GuardName, GuardMode.ENFORCE))
    out = tmp_path / "rendered"

    render_all(startup.with_guard_modes(config, load), _REPO, out)

    static = (out / "pirewall_static.nft").read_text(encoding="utf-8")
    assert "counter name c_verdict_raw \n" in static or "counter name c_verdict_raw\n" in static
    assert "counter name c_verdict_input drop" in static
    assert "counter name c_verdict_forward drop" in static


# ----------------------------------------------------------- kernel steps


def _manager(config: PirewallConfig) -> tuple[FirewallManager, FakeSetBackend]:
    sets = FakeSetBackend(
        lambda: NOW, guard_modes=startup.load_modes(dict.fromkeys(GuardName, GuardMode.ENFORCE))
    )
    return FirewallManager(config, FakeFirewallBackend(), set_backend=sets), sets


def test_an_unseeded_raw_guard_is_left_in_observe(tmp_path: Path) -> None:
    manager, sets = _manager(_config(tmp_path))

    applied = startup.set_guards(manager, dict.fromkeys(GuardName, GuardMode.ENFORCE), False, NOW)

    assert applied[GuardName.RAW] is GuardMode.OBSERVE
    assert sets.guard_mode(GuardName.RAW) is GuardMode.OBSERVE
    assert sets.guard_mode(GuardName.INPUT) is GuardMode.ENFORCE


def test_a_seeded_raw_guard_enforces(tmp_path: Path) -> None:
    config = _config(tmp_path)
    (tmp_path / "leases").write_text("")
    manager, sets = _manager(config)

    seeded = startup.seed(config, manager)
    startup.set_guards(manager, dict.fromkeys(GuardName, GuardMode.ENFORCE), seeded, NOW)

    assert seeded
    assert sets.guard_mode(GuardName.RAW) is GuardMode.ENFORCE


def test_a_missing_lease_file_fails_the_seed(tmp_path: Path) -> None:
    config = _config(tmp_path)
    manager, _sets = _manager(config)

    assert not startup.seed(config, manager)


# ------------------------------------------------------------------- mock


def test_to_toml_round_trips_a_full_config(tmp_path: Path) -> None:
    config = _config(
        tmp_path,
        antispoof={
            "static": [{"ip": "192.168.1.30", "mac": "02:00:00:00:00:30", "reason": 'a "quoted" one'}]
        },
        firewall={
            "allowlist": [
                {
                    "target": "192.168.1.50/32",
                    "reason": "admin",
                    "created_by": "t",
                    "created_at": NOW.isoformat(),
                }
            ]
        },
    )

    reloaded = PirewallConfig.model_validate(tomllib.loads(_text(config)))

    assert reloaded == config


def test_the_mock_config_lives_entirely_in_its_run_directory(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    pcap = tmp_path / "x.pcap"

    mock = startup.mock_config(_config(tmp_path), run_dir, pcap, 18443, "hash")

    assert mock.capture.backend == "replay"
    assert mock.capture.replay_path == str(pcap)
    assert mock.lab.env_tag is EnvTag.MOCK
    assert mock.api.host == "127.0.0.1"
    assert not mock.portal.enabled
    assert not mock.integration.wazuh_enabled
    assert mock.admin.allow_local_console
    for path in (
        mock.api.rpc_socket_path,
        mock.api.tls_cert_path,
        mock.api.log_dir,
        mock.logging.log_dir,
        mock.firewall.allowlist_store_path,
        mock.antispoof.lease_file,
        mock.portal.user_store_path,
    ):
        assert Path(path).is_relative_to(run_dir), path


# -------------------------------------------------------------------- lab


def test_the_lab_ruleset_marks_only_lan_to_victim_traffic(tmp_path: Path) -> None:
    config = _config(tmp_path, lab={"victim_network": "10.250.0.4/30"})

    text = startup.render_lab_ruleset(config)
    env = startup.lab_env(config)

    assert env["LAB_HOST_IP"] == "10.250.0.5"
    assert env["LAB_VICTIM_IP"] == "10.250.0.6"
    mark = f"0x{nft_names.LAB_FORWARD_MARK:08x}"
    assert (
        f'iifname "eth1" oifname "lab0" ip saddr 192.168.1.0/24 ip daddr 10.250.0.6 meta mark set {mark}'
        in text
    )
    assert "${" not in text
    assert "delete table" not in text


def test_the_base_template_accepts_exactly_the_lab_mark() -> None:
    """The lab table cannot override base's policy drop; base accepts its mark instead."""
    base = (_REPO / "deploy/firewall/base.nft.template").read_text(encoding="utf-8")

    assert f"meta mark 0x{nft_names.LAB_FORWARD_MARK:08x} accept" in base


# --------------------------------------------------------------- manifest


def test_the_manifest_records_what_a_result_needs(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config_path = tmp_path / "config.toml"
    config_path.write_text(_text(config), encoding="utf-8")
    load_config(config_path)

    manifest = startup.build_manifest(
        config,
        config_path,
        env_tag=EnvTag.SANDBOX,
        data_mode=None,
        engine=PipelineEngine.V1,
        guard_modes={GuardName.RAW: GuardMode.OBSERVE, GuardName.INPUT: GuardMode.ENFORCE},
        guard_modes_source="kernel",
        ruleset_text="table inet x {}\n",
        repo_root=_REPO,
        now=NOW,
    )

    assert manifest["env"] == "sandbox"
    assert manifest["config"] == {"path": str(config_path), "sha256": startup.sha256_file(config_path)}
    assert manifest["guards"] == {"raw": "observe", "input": "enforce"}
    assert manifest["ruleset_sha256"] == hashlib.sha256(b"table inet x {}\n").hexdigest()
    assert manifest["pipeline_engine"] == "v1"
    assert set(manifest) >= {"git", "models", "versions", "enforcement_mode", "created_at"}
    out = tmp_path / "a" / "manifest.json"
    startup.write_manifest(manifest, [out])
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == startup.MANIFEST_SCHEMA


def test_mock_never_writes_a_pi_tag(tmp_path: Path) -> None:
    config = _config(tmp_path, lab={"env_tag": "pi-live"})

    assert startup._env_tag(config, "mock") is EnvTag.MOCK  # pyright: ignore[reportPrivateUsage]
    assert startup._env_tag(config, None) is EnvTag.PI_LIVE  # pyright: ignore[reportPrivateUsage]


class _RecordingTransport:
    def __init__(self, host: str, port: int, *, fail: bool = False) -> None:
        self.target = (host, port)
        self.fail = fail
        self.sent: list[str] = []

    def send(self, message: str) -> None:
        if self.fail:
            raise IntegrationError("collector down")
        self.sent.append(message)


def _alert(tmp_path: Path, *, wazuh: bool, fail: bool = False) -> tuple[int, list[_RecordingTransport]]:
    integration: dict[str, object] = {"wazuh_enabled": wazuh, "wazuh_host": "192.168.1.50", "wazuh_port": 514}
    path = tmp_path / "local_config.toml"
    path.write_text(_text(_config(tmp_path, integration=integration)), encoding="utf-8")
    made: list[_RecordingTransport] = []

    def factory(host: str, port: int) -> _RecordingTransport:
        made.append(_RecordingTransport(host, port, fail=fail))
        return made[-1]

    return startup.crashloop_alert(path, "pirewall-core.service", factory), made


def test_the_crashloop_alert_forwards_a_critical_to_wazuh(tmp_path: Path) -> None:
    code, made = _alert(tmp_path, wazuh=True)

    assert code == startup.EXIT_OK
    assert made[0].target == ("192.168.1.50", 514)
    sent = json.loads(made[0].sent[0])
    assert sent["severity"] == "critical"
    assert "static kernel guards" in sent["reason"]


def test_the_crashloop_alert_is_syslog_only_when_wazuh_is_off(tmp_path: Path) -> None:
    code, made = _alert(tmp_path, wazuh=False)

    assert (code, made) == (startup.EXIT_OK, [])


def test_a_failed_wazuh_send_fails_the_alert_unit(tmp_path: Path) -> None:
    code, _made = _alert(tmp_path, wazuh=True, fail=True)

    assert code == startup.EXIT_FAILED


def test_the_crashloop_alert_survives_an_unloadable_config(tmp_path: Path) -> None:
    """A broken config may be why core is crash-looping; syslog still gets the alert."""
    path = tmp_path / "broken.toml"
    path.write_text("not = [valid\n", encoding="utf-8")

    assert startup.crashloop_alert(path, "pirewall-core.service") == startup.EXIT_OK

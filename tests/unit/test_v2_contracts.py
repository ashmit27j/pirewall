"""Phase-11 v2 contracts: model round-trips, MAC identity rules, and names pinned to the nft templates."""

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import BaseModel, TypeAdapter, ValidationError

from pirewall.core import nft_names
from pirewall.core.enums import (
    BindingSource,
    D1Detector,
    FirewallAction,
    GuardMode,
    GuardName,
    ThreatLevel,
)
from pirewall.core.models.common import MacAddress, UnicastMacAddress
from pirewall.core.models.evidence import AnomalyEvidence
from pirewall.core.models.evidence_v2 import (
    ClassifierEvidence,
    D1Evidence,
    EvidenceV2,
    KernelGuardEvidence,
    evidence_id,
)
from pirewall.core.models.identity import Binding, BindingChange, RuleTarget
from pirewall.core.models.policy import THREAT_LEVEL_BY_ACTION, PolicyDecision
from pirewall.core.nft_names import OFFENDER_GUARD, OffenderCode
from pirewall.flow.connection_start import ConnectionStartTracker
from pirewall.ipc.protocol_v2 import EngineStats, GuardModes, OffenderEntry, PanicResult

REPO_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
DEVICE_MAC = "02:11:22:33:44:55"  # locally administered: what a phone's private address looks like

# --------------------------------------------------------------------- MAC addresses

_MAC: TypeAdapter[str] = TypeAdapter(MacAddress)
_UNICAST_MAC: TypeAdapter[str] = TypeAdapter(UnicastMacAddress)


@pytest.mark.parametrize(
    ("raw", "normalised"),
    [
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
        ("De:aD:bE:eF:00:01", "de:ad:be:ef:00:01"),
    ],
)
def test_mac_addresses_are_normalised_to_lowercase_colons(raw: str, normalised: str) -> None:
    assert _MAC.validate_python(raw) == normalised


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:ff:00",
        "aa:bb:cc:dd:ee:gg",
        "aa:bb-cc:dd:ee:ff",  # mixed separators
        "aabbccddeeff",
        "aabb.ccdd.eeff",
        "a:b:c:d:e:f",
        " aa:bb:cc:dd:ee:ff",
        "aa:bb:cc:dd:ee:ff\n",
        12345,
    ],
)
def test_malformed_macs_are_rejected(bad: object) -> None:
    with pytest.raises(ValidationError):
        _MAC.validate_python(bad)


@pytest.mark.parametrize(
    "group_or_null",
    [
        "ff:ff:ff:ff:ff:ff",  # broadcast
        "01:00:5e:00:00:fb",  # IPv4 multicast (mDNS)
        "33:33:00:00:00:01",  # IPv6 multicast
        "03:00:00:00:00:00",  # any address with the I/G bit set
        "00:00:00:00:00:00",
    ],
)
def test_multicast_broadcast_and_null_macs_cannot_identify_a_device(group_or_null: str) -> None:
    # Still a well-formed MAC for an observed frame field...
    assert _MAC.validate_python(group_or_null) == group_or_null
    # ...but never an identity: every model that names a device refuses it.
    with pytest.raises(ValidationError):
        _UNICAST_MAC.validate_python(group_or_null)
    with pytest.raises(ValidationError):
        RuleTarget(ip="192.168.100.20", mac=group_or_null)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        Binding(ip="192.168.100.20", mac=group_or_null, source=BindingSource.STATIC)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        KernelGuardEvidence(
            code=OffenderCode.SYN_PPS,
            mac=group_or_null,
            guard=GuardName.RAW,
            guard_mode=GuardMode.ENFORCE,
            sustained_polls=1,
            observed_at=NOW,
        )


def test_identity_macs_are_normalised_too() -> None:
    target = RuleTarget(ip="192.168.100.20", mac="02-AB-CD-EF-00-01")  # type: ignore[arg-type]
    assert target.mac == "02:ab:cd:ef:00:01"


def test_a_rule_target_without_a_mac_is_ip_only() -> None:
    assert RuleTarget(ip="192.168.100.20").mac is None  # type: ignore[arg-type]


# --------------------------------------------------------------------- round-trips


def _samples() -> list[BaseModel]:
    lease = Binding(
        ip="192.168.100.20",  # type: ignore[arg-type]
        mac=DEVICE_MAC,
        source=BindingSource.LEASE,
        expires_at=NOW + timedelta(hours=1),
    )
    static = Binding(ip="192.168.100.5", mac="b8:27:eb:00:00:05", source=BindingSource.STATIC)  # type: ignore[arg-type]
    return [
        RuleTarget(ip="192.168.100.20", mac=DEVICE_MAC),  # type: ignore[arg-type]
        lease,
        static,
        BindingChange(removed=(static,), added=(lease,)),
        KernelGuardEvidence(
            code=OffenderCode.CLOSED_PORT,
            mac=DEVICE_MAC,
            guard=GuardName.INPUT,
            guard_mode=GuardMode.OBSERVE,
            sustained_polls=3,
            observed_at=NOW,
        ),
        D1Evidence(
            detector=D1Detector.VERTICAL_SCAN,
            window_seconds=60,
            value=412.0,
            threshold=100.0,
            mac=DEVICE_MAC,
            observed_at=NOW,
        ),
        ClassifierEvidence(
            flow_id="flow-1",
            mac=DEVICE_MAC,
            attack_probability=0.91,
            operating_threshold=0.8,
            is_attack=True,
            family="scan",
            family_probability=0.7,
            model_version="3.0.0-test",
            feature_schema_version="3.0.0",
            generated_at=NOW,
        ),
        PolicyDecision(
            target=RuleTarget(ip="192.168.100.20", mac=DEVICE_MAC),  # type: ignore[arg-type]
            action=FirewallAction.BLOCK,
            ttl_seconds=600,
            reasons=("vertical scan: 412 ports in 60 s",),
            evidence_ids=("e1", "e2"),
            requires_approval=True,
            decided_at=NOW,
        ),
        GuardModes(raw=GuardMode.ENFORCE, input=GuardMode.ENFORCE, forward=GuardMode.OBSERVE, read_at=NOW),
        OffenderEntry(
            mac=DEVICE_MAC,
            code=OffenderCode.UDP_FWD,
            guard=GuardName.FORWARD,
            guard_mode=GuardMode.OBSERVE,
            sustained_polls=1,
            first_seen=NOW,
            last_seen=NOW,
        ),
        EngineStats(
            backend="native",
            has_packet_ring=True,
            frames_seen=10,
            kernel_drops=0,
            flows_shed=0,
            new_flow_signals_shed=0,
            panics_caught=0,
            read_at=NOW,
        ),
        PanicResult(
            deleted_tables=("inet pirewall_adaptive", "inet pirewall_static"),
            restore_command="sudo pirewall-start",
            actor="admin",
            performed_at=NOW,
        ),
    ]


@pytest.mark.parametrize("model", _samples(), ids=lambda model: type(model).__name__)
def test_contract_models_round_trip_through_json(model: BaseModel) -> None:
    cls = type(model)
    assert cls.model_validate(model.model_dump(mode="json")) == model
    assert cls.model_validate_json(model.model_dump_json()) == model


_AnyEvidence = KernelGuardEvidence | D1Evidence | AnomalyEvidence | ClassifierEvidence
_EVIDENCE: TypeAdapter[_AnyEvidence] = TypeAdapter(EvidenceV2)


def _anomaly() -> AnomalyEvidence:
    return AnomalyEvidence(
        flow_id="flow-9",
        anomaly_score=-0.2,
        threshold=0.0,
        is_anomaly=True,
        model_version="0.4.0",
        feature_schema_version="2.0.0",
        generated_at=NOW,
    )


@pytest.mark.parametrize(
    "evidence",
    [
        *(m for m in _samples() if isinstance(m, KernelGuardEvidence | D1Evidence | ClassifierEvidence)),
        _anomaly(),
    ],
    ids=lambda evidence: type(evidence).__name__,
)
def test_the_evidence_union_resolves_each_variant_to_its_own_type(evidence: BaseModel) -> None:
    parsed = _EVIDENCE.validate_python(evidence.model_dump(mode="json"))
    assert type(parsed) is type(evidence)
    assert parsed == evidence


def test_evidence_ids_name_the_reused_anomaly_evidence_by_its_flow() -> None:
    assert evidence_id(_anomaly()) == "anomaly:flow-9"
    d1 = D1Evidence(
        detector=D1Detector.BRUTE_FORCE, window_seconds=10, value=30, threshold=12, observed_at=NOW
    )
    assert evidence_id(d1) == d1.id


# --------------------------------------------------------------------- model invariants


def test_a_lease_binding_needs_an_expiry_and_a_static_one_must_not_have_one() -> None:
    with pytest.raises(ValidationError, match="expires_at"):
        Binding(ip="192.168.100.20", mac=DEVICE_MAC, source=BindingSource.LEASE)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="never expires"):
        Binding(
            ip="192.168.100.20",  # type: ignore[arg-type]
            mac=DEVICE_MAC,
            source=BindingSource.STATIC,
            expires_at=NOW,
        )


def test_kernel_evidence_must_name_the_guard_that_raises_its_code() -> None:
    with pytest.raises(ValidationError, match="raised by the raw guard"):
        KernelGuardEvidence(
            code=OffenderCode.SYN_PPS,
            mac=DEVICE_MAC,
            guard=GuardName.FORWARD,
            guard_mode=GuardMode.ENFORCE,
            sustained_polls=2,
            observed_at=NOW,
        )


def test_classifier_evidence_must_be_self_consistent() -> None:
    with pytest.raises(ValidationError, match="is_attack"):
        ClassifierEvidence(
            flow_id="f",
            attack_probability=0.2,
            operating_threshold=0.8,
            is_attack=True,
            model_version="m",
            feature_schema_version="3.0.0",
            generated_at=NOW,
        )
    with pytest.raises(ValidationError, match="family"):
        ClassifierEvidence(
            flow_id="f",
            attack_probability=0.9,
            operating_threshold=0.8,
            is_attack=True,
            family="scan",
            model_version="m",
            feature_schema_version="3.0.0",
            generated_at=NOW,
        )


def _decision(**overrides: object) -> PolicyDecision:
    fields: dict[str, object] = {
        "target": {"ip": "192.168.100.20", "mac": DEVICE_MAC},
        "action": "rate_limit",
        "ttl_seconds": 300,
        "reasons": ("syn flood sustained 3 polls",),
        "evidence_ids": ("k1",),
        "decided_at": NOW,
    }
    fields.update(overrides)
    return PolicyDecision.model_validate(fields)


@pytest.mark.parametrize(("action", "level"), list(THREAT_LEVEL_BY_ACTION.items()))
def test_policy_threat_level_is_derived_from_the_action(action: FirewallAction, level: ThreatLevel) -> None:
    enforcing = action in (FirewallAction.RATE_LIMIT, FirewallAction.BLOCK)
    decision = _decision(action=action, ttl_seconds=300 if enforcing else None)
    assert decision.threat_level is level


def test_policy_threat_level_cannot_contradict_the_action() -> None:
    with pytest.raises(ValidationError, match="threat_level"):
        _decision(threat_level="critical")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"ttl_seconds": None}, "need ttl_seconds"),
        ({"ttl_seconds": 3601}, "less than or equal to 3600"),
        ({"evidence_ids": ()}, "name the evidence"),
        ({"action": "monitor", "ttl_seconds": 60}, "only RATE_LIMIT and BLOCK"),
        ({"requires_approval": True}, "only BLOCK"),
        ({"reasons": ()}, "at least 1"),
    ],
)
def test_policy_decision_invariants(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        _decision(**overrides)


def test_the_connection_start_tracker_is_a_stub_until_phase_15() -> None:
    with pytest.raises(ValueError, match="positive"):
        ConnectionStartTracker(max_tracked=0)
    tracker = ConnectionStartTracker(max_tracked=10)
    with pytest.raises(NotImplementedError):
        _ = tracker.evictions


# --------------------------------------------------------------------- nft names vs templates

_TEMPLATE_DIRS = [REPO_ROOT / "docs" / "v2" / "v2", REPO_ROOT / "deploy" / "firewall"]
_TABLE = re.compile(r"^table (\w+) (\w+) \{")
_CHAIN = re.compile(r"^\s*chain (\w+) \{")
_SET = re.compile(r"^\s*set (\w+) \{(.*)\}")
_COUNTER = re.compile(r"^\s*counter (\w+) \{")


class _Declared:
    def __init__(self) -> None:
        self.chains: set[str] = set()
        self.sets: dict[str, str] = {}  # name -> declaration body
        self.counters: set[str] = set()


def _parse_template(path: Path) -> dict[tuple[str, str], _Declared]:
    """(family, table) -> what the template declares in it. Repeated `table` blocks merge."""
    tables: dict[tuple[str, str], _Declared] = {}
    current: _Declared | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            continue
        if (match := _TABLE.match(line)) is not None:
            current = tables.setdefault((match.group(1), match.group(2)), _Declared())
        elif line.startswith("}"):
            current = None
        elif current is not None:
            if (chain := _CHAIN.match(line)) is not None:
                current.chains.add(chain.group(1))
            elif (set_ := _SET.match(line)) is not None:
                current.sets[set_.group(1)] = set_.group(2)
            elif (counter := _COUNTER.match(line)) is not None:
                current.counters.add(counter.group(1))
    return tables


def _template_paths(stem: str) -> list[Path]:
    paths = [directory / f"{stem}.nft.template" for directory in _TEMPLATE_DIRS]
    present = [path for path in paths if path.exists()]
    assert present, f"no {stem}.nft.template found"
    return present


@pytest.mark.parametrize("path", _template_paths("pirewall_static"), ids=str)
def test_static_names_match_the_static_template(path: Path) -> None:
    tables = _parse_template(path)
    assert set(tables) == {("inet", nft_names.STATIC_TABLE), ("arp", nft_names.STATIC_ARP_TABLE)}

    static = tables[("inet", nft_names.STATIC_TABLE)]
    assert static.chains == nft_names.STATIC_CHAINS
    assert set(static.sets) == nft_names.STATIC_SETS
    assert static.counters == nft_names.STATIC_COUNTERS
    assert set(nft_names.GUARD_VERDICT_CHAINS.values()) <= static.chains

    arp = tables[("arp", nft_names.STATIC_ARP_TABLE)]
    assert arp.chains == nft_names.ARP_CHAINS
    assert set(arp.sets) == nft_names.ARP_SETS
    assert arp.counters == nft_names.ARP_COUNTERS


@pytest.mark.parametrize("path", _template_paths("pirewall_adaptive"), ids=str)
def test_adaptive_names_match_the_adaptive_template(path: Path) -> None:
    tables = _parse_template(path)
    assert set(tables) == {("inet", nft_names.ADAPTIVE_TABLE)}
    adaptive = tables[("inet", nft_names.ADAPTIVE_TABLE)]
    assert adaptive.chains == nft_names.ADAPTIVE_CHAINS
    assert set(adaptive.sets) == nft_names.ADAPTIVE_SETS
    assert adaptive.counters == nft_names.ADAPTIVE_COUNTERS


def test_panic_deletes_exactly_the_v2_tables() -> None:
    declared: set[tuple[str, str]] = set()
    for stem in ("pirewall_static", "pirewall_adaptive"):
        for path in _template_paths(stem):
            declared |= set(_parse_template(path))
    assert set(nft_names.PANIC_TABLES) == declared
    assert all(name not in {nft_names.BASE_TABLE, nft_names.PORTAL_TABLE} for _, name in declared)


@pytest.mark.parametrize("path", _template_paths("pirewall_static"), ids=str)
def test_kernel_written_sets_are_dynamic_and_manager_written_sets_are_not(path: Path) -> None:
    static = _parse_template(path)[("inet", nft_names.STATIC_TABLE)]
    kernel_written = nft_names.STATIC_METER_SETS | {nft_names.SET_OFFENDERS, nft_names.SET_UNBOUND_SEEN}
    for name in kernel_written:
        assert "dynamic" in static.sets[name], name
    for name in nft_names.STATIC_BINDING_SETS | {nft_names.SET_ALLOW_BOUND}:
        assert "dynamic" not in static.sets[name], name


_OFFENDER_RULE = re.compile(r"update @offenders \{ ether saddr \. (\d+) \} jump (guard_verdict_\w+)")


@pytest.mark.parametrize("path", _template_paths("pirewall_static"), ids=str)
def test_offender_codes_and_their_guards_match_the_template(path: Path) -> None:
    found: dict[OffenderCode, set[str]] = {}
    for code, chain in _OFFENDER_RULE.findall(path.read_text(encoding="utf-8")):
        found.setdefault(OffenderCode(int(code)), set()).add(chain)
    assert set(found) == set(OffenderCode)
    for code, chains in found.items():
        assert chains == {nft_names.GUARD_VERDICT_CHAINS[OFFENDER_GUARD[code]]}, code


@pytest.mark.parametrize("path", _template_paths("pirewall_static"), ids=str)
def test_each_guard_verdict_chain_counts_on_its_own_counter(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for guard, chain in nft_names.GUARD_VERDICT_CHAINS.items():
        body = re.search(rf"chain {chain} \{{\s*counter name (\w+)", text)
        assert body is not None, chain
        assert body.group(1) == nft_names.GUARD_VERDICT_COUNTERS[guard]

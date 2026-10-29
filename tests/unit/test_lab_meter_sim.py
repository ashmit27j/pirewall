"""`lab/meter_sim.py`: the static template's meters, simulated (phase 18, PLAN_FINAL §1.2).

Token-bucket semantics incl. burst, set-timeout expiry, fail-open when a
meter set is full, observe vs enforce, and that the numbers come from the
rendered template (never retyped).
"""

import dataclasses

import pytest

from lab.meter_sim import MeterSimulator, SetDecl, TemplateParseError, TemplateSpec
from pirewall.core.enums import GuardMode, GuardName
from pirewall.core.nft_names import OffenderCode
from tests.helpers.config import make_config
from tests.helpers.traffic import SYN, mac_of, tcp

PI = "192.168.1.2"
WAN = "203.0.113.9"
PI_MAC = ":".join(f"{b:02x}" for b in mac_of(PI))


def _spec(**guards: object) -> TemplateSpec:
    return TemplateSpec.from_config(make_config(guards=guards) if guards else make_config())


def _sim(spec: TemplateSpec, modes: dict[GuardName, GuardMode] | None = None) -> MeterSimulator:
    config = make_config()
    return MeterSimulator(
        spec,
        pi_ip=config.network.pirewall_lan_ip,
        protected=config.network.protected_network,
        guard_modes=modes,
        pi_mac=PI_MAC,
    )


def _syn_flood(sim: MeterSimulator, src: str, pps: float, seconds: float, start: float = 0.0) -> None:
    for i in range(int(pps * seconds)):
        sim.feed(tcp(src, WAN, 1024 + i % 60000, 80, SYN), start + i / pps)


def _mac(ip: str) -> str:
    return ":".join(f"{b:02x}" for b in mac_of(ip))


def test_rates_and_bursts_come_from_the_rendered_template() -> None:
    spec = _spec(syn={"rate": 123, "burst": 456})
    rule = spec.meters[OffenderCode.SYN_PPS]
    assert (rule.rate_per_second, rule.burst) == (123.0, 456)
    defaults = make_config().guards
    assert spec.meters[OffenderCode.ICMP_PPS].burst == defaults.icmp.burst
    assert spec.meters[OffenderCode.DHCP].rate_per_second == pytest.approx(defaults.dhcp_per_minute.rate / 60)


def test_a_template_without_meter_rules_is_refused() -> None:
    with pytest.raises(TemplateParseError):
        TemplateSpec.parse("table inet pirewall_static {}\n")


def test_a_three_second_flood_inside_the_burst_does_not_trip_the_meter() -> None:
    # SYN meter 200/s, burst 400: 3 s at 300 pps is 900 packets <= 400 + 3 * 200 tokens.
    sim = _sim(_spec())
    _syn_flood(sim, "192.168.1.66", 300.0, 3.0)
    assert (_mac("192.168.1.66"), OffenderCode.SYN_PPS) not in sim.trips


def test_a_flood_beyond_rate_plus_burst_trips_when_the_bucket_runs_dry() -> None:
    # 400 pps against 200/s + 400 burst: empty at 400 + 200 t = 400 t, so t = 2 s.
    sim = _sim(_spec())
    _syn_flood(sim, "192.168.1.66", 400.0, 3.0)
    trip = sim.trips[(_mac("192.168.1.66"), OffenderCode.SYN_PPS)]
    assert 1.95 <= trip.first_at <= 2.05
    assert trip.hits > 0
    assert (_mac("192.168.1.66"), int(OffenderCode.SYN_PPS)) in sim.offenders(3.0)


def test_an_enforcing_guard_drops_on_a_trip_and_an_observing_one_does_not() -> None:
    enforce = _sim(_spec(), dict.fromkeys(GuardName, GuardMode.ENFORCE))
    observe = _sim(_spec(), dict.fromkeys(GuardName, GuardMode.OBSERVE))
    for sim in (enforce, observe):
        _syn_flood(sim, "192.168.1.66", 1000.0, 1.0)
    assert enforce.counters.guard_drops.get(GuardName.RAW, 0) > 0
    assert observe.counters.guard_drops == {}
    assert observe.counters.verdict_hits.get(GuardName.RAW, 0) > 0


def test_a_meter_element_expires_its_set_timeout_after_creation() -> None:
    spec = _spec()
    rule = spec.meters[OffenderCode.SYN_PPS]
    timeout = spec.sets[rule.set_name].timeout_seconds
    assert timeout is not None
    sim = _sim(spec)
    sim.feed(tcp("192.168.1.66", WAN, 1024, 80, SYN), 0.0)
    assert sim.set_fill(rule.set_name, timeout - 0.01)[0] == 1
    sim.feed(tcp("192.168.1.66", WAN, 1025, 80, SYN), timeout / 2)  # `add` never refreshes the timeout
    assert sim.set_fill(rule.set_name, timeout + 0.01)[0] == 0


def test_a_full_meter_set_fails_open() -> None:
    spec = _spec()
    rule = spec.meters[OffenderCode.SYN_PPS]
    declared = spec.sets[rule.set_name]
    tiny = dataclasses.replace(spec, sets={**spec.sets, rule.set_name: SetDecl(declared.timeout_seconds, 2)})
    sim = _sim(tiny)
    for host in ("192.168.1.61", "192.168.1.62", "192.168.1.63"):
        _syn_flood(sim, host, 1000.0, 1.0)
    assert sim.counters.failopen.get(rule.set_name, 0) == 1000  # every packet of the third MAC
    assert (_mac("192.168.1.63"), OffenderCode.SYN_PPS) not in sim.trips
    assert (_mac("192.168.1.61"), OffenderCode.SYN_PPS) in sim.trips


def test_a_spoofed_source_is_a_static_drop_not_a_meter_trip() -> None:
    sim = _sim(_spec())
    sim.feed(tcp("192.168.1.30", WAN, 1000, 443, SYN), 0.0)  # binds .30 to its own MAC
    sim.feed(tcp("192.168.1.30", WAN, 1001, 443, SYN, src_mac=mac_of("192.168.1.66")), 0.1)
    assert sim.counters.static_drops == {"c_spoof": 1}
    assert sim.counters.static_drops_by_mac == {_mac("192.168.1.66"): {"c_spoof": 1}}

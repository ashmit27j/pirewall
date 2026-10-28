"""`scripts.deployment.configure`: offering `[[antispoof.static]]` candidates (phase 14b).

A static entry outranks the lease file, so one made for a DHCP client pins
it to an address it may not keep. The properties asserted here: leased and
group-MAC neighbours are never offered, nothing is added without a human
choosing it, and the file surgery leaves the rest of an existing config
alone and still validates.
"""

import dataclasses
import ipaddress
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from scripts.deployment import configure
from scripts.deployment.configure import StaticBinding
from scripts.deployment.discovery import DiscoveredNetwork

from pirewall.config.loader import load_config
from pirewall.core.exceptions import ConfigurationError

LAN = ipaddress.IPv4Network("192.168.100.0/24")
PI = ipaddress.IPv4Address("192.168.100.1")
NAS = (ipaddress.IPv4Address("192.168.100.20"), "02:AA:00:00:00:20")
PRINTER = (ipaddress.IPv4Address("192.168.100.21"), "02:aa:00:00:00:21")
PHONE = (ipaddress.IPv4Address("192.168.100.50"), "02:aa:00:00:00:50")

_DISCOVERED = DiscoveredNetwork(
    wan_interface="eth0",
    lan_interface="wlan0",
    upstream_gateway=ipaddress.IPv4Address("192.168.1.1"),
    pirewall_lan_ip=PI,
    protected_network=LAN,
)
_ANSWERS = configure.Answers(
    admin_pc_ip=ipaddress.IPv4Address("192.168.100.10"),
    admin_username="admin",
    admin_password_hash="scrypt$fake$hash",
)


def _written_config(tmp_path: Path) -> Path:
    path = tmp_path / "local_config.toml"
    configure.write_validated(path, configure.render_config(_DISCOVERED, _ANSWERS))
    return path


def _scripted_input(monkeypatch: pytest.MonkeyPatch, answers: list[str]) -> None:
    supplied: Iterator[str] = iter(answers)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(supplied))


def _candidates(
    neighbours: list[tuple[ipaddress.IPv4Address, str]],
    *,
    existing_ips: frozenset[ipaddress.IPv4Address] = frozenset(),
    existing_macs: frozenset[str] = frozenset(),
) -> list[tuple[ipaddress.IPv4Address, str]]:
    return configure.static_binding_candidates(
        neighbours,
        leased={PHONE[0]},
        protected_network=LAN,
        pirewall_lan_ip=PI,
        existing_ips=existing_ips,
        existing_macs=existing_macs,
    )


class TestCandidates:
    def test_only_unleased_unicast_lan_neighbours_are_offered_normalised(self) -> None:
        neighbours = [
            NAS,
            PRINTER,
            PHONE,  # leased: a DHCP client
            (PI, "02:aa:00:00:00:01"),  # the Pi itself
            (ipaddress.IPv4Address("10.0.0.5"), "02:aa:00:00:00:05"),  # off the LAN
            (ipaddress.IPv4Address("192.168.100.30"), "01:00:5e:00:00:01"),  # multicast
            (ipaddress.IPv4Address("192.168.100.31"), "00:00:00:00:00:00"),  # all-zero
        ]
        assert _candidates(neighbours) == [(NAS[0], "02:aa:00:00:00:20"), PRINTER]

    def test_a_mac_seen_at_two_addresses_is_not_offered(self) -> None:
        moved = (ipaddress.IPv4Address("192.168.100.22"), PRINTER[1])
        assert _candidates([PRINTER, moved, NAS]) == [(NAS[0], "02:aa:00:00:00:20")]

    def test_devices_already_bound_are_not_offered_again(self) -> None:
        assert _candidates([NAS, PRINTER], existing_ips=frozenset({NAS[0]})) == [PRINTER]
        assert _candidates([NAS, PRINTER], existing_macs=frozenset({"02-AA-00-00-00-21"})) == [
            (NAS[0], "02:aa:00:00:00:20")
        ]


class TestLeasedIps:
    def test_reads_current_leases_through_the_runtime_parser(self, tmp_path: Path) -> None:
        expiry = int((datetime.now(UTC) + timedelta(hours=1)).timestamp())
        leases = tmp_path / "dnsmasq-wlan0.leases"
        leases.write_text(
            f"{expiry} {PHONE[1]} {PHONE[0]} phone *\nnot a lease line\n", encoding="utf-8"
        )
        assert configure.read_leased_ips(leases, LAN) == {PHONE[0]}

    def test_an_unreadable_lease_file_is_none_not_empty(self, tmp_path: Path) -> None:
        """Empty would make every DHCP client look like a fixed-address device."""
        assert configure.read_leased_ips(tmp_path / "absent.leases", LAN) is None


class TestPrompt:
    def test_nothing_is_added_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scripted_input(monkeypatch, [""])
        assert configure.prompt_static_bindings([NAS], Path("x"), leases_readable=True) == ()

    def test_nothing_is_offered_when_the_lease_file_is_unreadable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _scripted_input(monkeypatch, [])  # any prompt would raise StopIteration
        assert configure.prompt_static_bindings([NAS], Path("x"), leases_readable=False) == ()

    def test_chosen_entries_get_a_reason_and_bad_picks_re_ask(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scripted_input(monkeypatch, ["9", "one", "2, 1", 'NAS "rack"', ""])
        chosen = configure.prompt_static_bindings([NAS, PRINTER], Path("x"), leases_readable=True)
        assert chosen == (
            StaticBinding(NAS[0], NAS[1], "NAS 'rack'"),
            StaticBinding(PRINTER[0], PRINTER[1], configure._DEFAULT_STATIC_REASON),  # pyright: ignore[reportPrivateUsage]
        )


class TestRendering:
    def test_a_generated_config_leaves_the_lease_file_to_follow_the_lan(self, tmp_path: Path) -> None:
        config = load_config(_written_config(tmp_path))
        assert config.antispoof.lease_file == "/var/lib/NetworkManager/dnsmasq-wlan0.leases"
        assert config.antispoof.static == ()
        assert "lease_file =" not in (tmp_path / "local_config.toml").read_text(encoding="utf-8")

    def test_confirmed_bindings_are_written_and_validate(self, tmp_path: Path) -> None:
        answers = configure.Answers(
            admin_pc_ip=_ANSWERS.admin_pc_ip,
            admin_username=_ANSWERS.admin_username,
            admin_password_hash=_ANSWERS.admin_password_hash,
            static_bindings=(StaticBinding(NAS[0], "02:aa:00:00:00:20", "NAS"),),
        )
        path = tmp_path / "local_config.toml"
        configure.write_validated(path, configure.render_config(_DISCOVERED, answers))
        (entry,) = load_config(path).antispoof.static
        assert (entry.ip, entry.mac, entry.reason) == (NAS[0], "02:aa:00:00:00:20", "NAS")


class TestAddStaticBindings:
    _BINDING = StaticBinding(PRINTER[0], PRINTER[1], "printer")

    def test_replaces_an_empty_inline_array_and_keeps_everything_else(self, tmp_path: Path) -> None:
        path = _written_config(tmp_path)
        original = path.read_text(encoding="utf-8")
        assert "static = []" in original
        edited = configure.add_static_bindings(original, [self._BINDING])
        configure.write_validated(path, edited)
        (entry,) = load_config(path).antispoof.static
        assert entry.ip == PRINTER[0]
        kept = [line for line in original.splitlines() if line.strip() != "static = []"]
        assert edited.splitlines()[: len(kept)] == kept

    def test_appends_to_existing_array_tables(self, tmp_path: Path) -> None:
        path = _written_config(tmp_path)
        first = configure.add_static_bindings(
            path.read_text(encoding="utf-8"), [StaticBinding(NAS[0], "02:aa:00:00:00:20", "NAS")]
        )
        configure.write_validated(path, configure.add_static_bindings(first, [self._BINDING]))
        assert [entry.ip for entry in load_config(path).antispoof.static] == [NAS[0], PRINTER[0]]

    def test_adds_the_section_to_a_config_that_has_none(self, tmp_path: Path) -> None:
        path = _written_config(tmp_path)
        text = path.read_text(encoding="utf-8")
        without = text[: text.index("[antispoof]")]
        configure.write_validated(path, configure.add_static_bindings(without, [self._BINDING]))
        assert [entry.ip for entry in load_config(path).antispoof.static] == [PRINTER[0]]

    def test_a_hand_written_inline_array_is_refused(self) -> None:
        text = '[antispoof]\nstatic = [{ ip = "192.168.100.9", mac = "02:aa:00:00:00:09", reason = "x" }]\n'
        with pytest.raises(ConfigurationError, match="by hand"):
            configure.add_static_bindings(text, [self._BINDING])

    def test_no_bindings_is_no_change(self) -> None:
        assert configure.add_static_bindings("[antispoof]\nstatic = []\n", []) == "[antispoof]\nstatic = []\n"


def test_the_static_bindings_mode_is_wired_into_the_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _written_config(tmp_path)
    def no_leases(_path: Path, _network: ipaddress.IPv4Network) -> set[ipaddress.IPv4Address]:
        return set()

    monkeypatch.setattr(configure, "read_leased_ips", no_leases)
    with_printer = dataclasses.replace(_DISCOVERED, neighbour_macs=(PRINTER,))
    monkeypatch.setattr(configure, "discover", lambda: with_printer)
    _scripted_input(monkeypatch, ["1", ""])
    assert configure.main(["--config", str(path), "--static-bindings"]) == configure.EXIT_OK
    assert [entry.ip for entry in load_config(path).antispoof.static] == [PRINTER[0]]

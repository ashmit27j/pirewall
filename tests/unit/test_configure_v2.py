"""`scripts.deployment.configure` v2 additions (phase 16): the admin MAC and interface, `[guards]`, `[lab]`.

The admin rule matches interface + MAC + IP (ADDENDUM_4.md D3), so the MAC
is offered from the neighbour table and confirmed by a human, never
defaulted. The rendered `[guards]` keeps the D2 defaults and `[lab]` never
carries a `pi-*` env tag (D7).
"""

import ipaddress
from collections.abc import Iterator
from pathlib import Path

import pytest
from scripts.deployment import configure, discovery
from scripts.deployment.discovery import DiscoveredNetwork

from pirewall.config.loader import load_config
from pirewall.core.enums import EnvTag, GuardMode
from pirewall.core.exceptions import ConfigurationError

ADMIN_IP = ipaddress.IPv4Address("192.168.1.50")
ADMIN_MAC = "02:00:00:00:00:50"

_DISCOVERED = DiscoveredNetwork(
    wan_interface="eth0",
    lan_interface="wlan0",
    upstream_gateway=ipaddress.IPv4Address("192.168.1.1"),
    pirewall_lan_ip=ipaddress.IPv4Address("192.168.100.1"),
    protected_network=ipaddress.IPv4Network("192.168.100.0/24"),
    interface_macs=(("eth0", "dc:a6:32:00:00:01"), ("wlan0", "dc:a6:32:00:00:02")),
    all_neighbours=(
        (ADMIN_IP, ADMIN_MAC, "eth0"),
        (ADMIN_IP, "01:00:5e:00:00:01", "eth0"),  # multicast: never an identity
        (ipaddress.IPv4Address("192.168.100.20"), "02:00:00:00:00:20", "wlan0"),
    ),
)


def _answers(**overrides: str | None) -> configure.Answers:
    values: dict[str, str | None] = {"admin_interface": "eth0", "admin_pc_mac": ADMIN_MAC}
    values.update(overrides)
    return configure.Answers(
        admin_pc_ip=ADMIN_IP,
        admin_username="admin",
        admin_password_hash="scrypt$fake$hash",
        admin_interface=values["admin_interface"],
        admin_pc_mac=values["admin_pc_mac"],
    )


def _scripted_input(monkeypatch: pytest.MonkeyPatch, answers: list[str]) -> None:
    supplied: Iterator[str] = iter(answers)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(supplied))


def _written(tmp_path: Path, answers: configure.Answers) -> Path:
    path = tmp_path / "local_config.toml"
    configure.write_validated(path, configure.render_config(_DISCOVERED, answers))
    return path


class TestRender:
    def test_admin_identity_guards_and_lab_are_written_and_load(self, tmp_path: Path) -> None:
        config = load_config(_written(tmp_path, _answers()))

        assert config.network.admin_interface == "eth0"
        assert config.admin.admin_pc_mac == ADMIN_MAC
        assert (config.guards.raw_mode, config.guards.input_mode, config.guards.forward_mode) == (
            GuardMode.ENFORCE,
            GuardMode.ENFORCE,
            GuardMode.OBSERVE,
        )
        assert config.lab.victim_netns == "labvictim"
        assert str(config.lab.victim_network) == "10.250.0.0/30"

    def test_the_env_tag_is_never_written(self, tmp_path: Path) -> None:
        """D7: pirewall-start sets it per --data-mode; a config file never pins a pi-* tag."""
        path = _written(tmp_path, _answers())

        assert "env_tag =" not in path.read_text(encoding="utf-8")
        assert load_config(path).lab.env_tag is EnvTag.SANDBOX

    def test_the_lan_mac_is_shown_for_confirmation(self, tmp_path: Path) -> None:
        text = _written(tmp_path, _answers()).read_text(encoding="utf-8")

        assert "LAN interface MAC, as detected: dc:a6:32:00:00:02" in text
        assert "dc:a6:32:00:00:02" in configure.describe(_DISCOVERED)

    def test_without_an_identity_the_config_still_loads_with_both_unset(self, tmp_path: Path) -> None:
        config = load_config(_written(tmp_path, _answers(admin_interface=None, admin_pc_mac=None)))

        assert config.network.admin_interface is None
        assert config.admin.admin_pc_mac is None


class TestAdminIdentity:
    def test_candidates_are_the_admin_ips_unicast_macs_only(self) -> None:
        assert configure.admin_identity_candidates(_DISCOVERED, ADMIN_IP) == [("eth0", ADMIN_MAC)]

    def test_a_candidate_is_confirmed_by_number(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scripted_input(monkeypatch, ["", "7", "1"])  # empty and out-of-range are re-asked

        assert configure.prompt_admin_identity(_DISCOVERED, ADMIN_IP) == ("eth0", ADMIN_MAC)

    def test_manual_entry_refuses_a_group_mac(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scripted_input(monkeypatch, ["m", "eth0", "ff:ff:ff:ff:ff:ff", "02:00:00:00:00:99"])

        assert configure.prompt_admin_identity(_DISCOVERED, ADMIN_IP) == ("eth0", "02:00:00:00:00:99")

    def test_an_unseen_admin_pc_goes_straight_to_manual_entry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scripted_input(monkeypatch, ["eth0", "02-00-00-00-00-77"])

        unseen = ipaddress.IPv4Address("192.168.1.77")
        assert configure.prompt_admin_identity(_DISCOVERED, unseen) == ("eth0", "02:00:00:00:00:77")


class TestSetAdminPc:
    def test_scripted_mac_and_interface_are_inserted_into_a_1x_config(self, tmp_path: Path) -> None:
        path = _written(tmp_path, _answers(admin_interface=None, admin_pc_mac=None))

        code = configure.run_set_admin_pc(path, "192.168.1.60", "02:00:00:00:00:60", "eth0")

        config = load_config(path)
        assert code == configure.EXIT_OK
        assert str(config.admin.admin_pc_ip) == "192.168.1.60"
        assert config.admin.admin_pc_mac == "02:00:00:00:00:60"
        assert config.network.admin_interface == "eth0"

    def test_scripted_without_a_mac_leaves_it_unchanged(self, tmp_path: Path) -> None:
        path = _written(tmp_path, _answers())

        configure.run_set_admin_pc(path, "192.168.1.60")

        assert load_config(path).admin.admin_pc_mac == ADMIN_MAC

    def test_set_scalar_replaces_an_existing_key_without_duplicating_it(self) -> None:
        text = '[admin]\nadmin_pc_ip = "1.2.3.4"\nadmin_pc_mac = "02:00:00:00:00:01"\n'

        updated = configure.set_scalar(text, "admin", "admin_pc_mac", "02:00:00:00:00:02")

        assert updated.count("admin_pc_mac") == 1
        assert '"02:00:00:00:00:02"' in updated

    def test_set_scalar_refuses_a_missing_section(self) -> None:
        with pytest.raises(ConfigurationError):
            configure.set_scalar("[network]\n", "admin", "admin_pc_mac", ADMIN_MAC)


class TestDiscoveryParsing:
    def test_interface_macs_skip_loopback_and_down_links(self) -> None:
        payload: list[dict[str, object]] = [
            {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "address": "00:00:00:00:00:00"},
            {"ifname": "eth0", "flags": ["UP"], "address": "DC:A6:32:00:00:01"},
            {"ifname": "wlan1", "flags": [], "address": "dc:a6:32:00:00:09"},
        ]

        assert discovery.parse_interface_macs(payload) == [("eth0", "dc:a6:32:00:00:01")]

    def test_all_neighbours_keep_the_device(self) -> None:
        payload: list[dict[str, object]] = [
            {"dst": "192.168.1.50", "dev": "eth0", "lladdr": "02:00:00:00:00:50", "state": ["REACHABLE"]},
            {"dst": "192.168.1.51", "dev": "eth0", "state": ["FAILED"]},
            {"dst": "fe80::1", "dev": "eth0", "lladdr": "02:00:00:00:00:51", "state": ["STALE"]},
        ]

        assert discovery.parse_all_neighbours(payload) == [(ADMIN_IP, ADMIN_MAC, "eth0")]

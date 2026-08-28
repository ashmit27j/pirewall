"""`scripts.deployment.configure` — generating and surgically editing `local_config.toml`.

Two properties matter most and are asserted directly:

* **The generated config is one both entry points accept.** No `CHANGE_ME`
  survives, and it validates as a real `PirewallConfig` — the whole point
  of generating it rather than asking an operator to fill a template.
* **`--set-admin-pc` is a targeted edit, not a regenerate.** An operator's
  hand-tuned thresholds and comments have to survive changing which machine
  administers the firewall.

The interactive prompts are covered by driving `prompt_admin_pc_ip` with
scripted input, because "the Admin PC is chosen, never guessed" is the
single most important behaviour in this script.
"""

import ipaddress
from collections.abc import Iterator
from pathlib import Path

import pytest
from scripts.deployment import configure
from scripts.deployment.discovery import DiscoveredNetwork

from pirewall.config.loader import load_config
from pirewall.core.exceptions import ConfigurationError

_DISCOVERED = DiscoveredNetwork(
    wan_interface="eth0",
    lan_interface="wlan0",
    upstream_gateway=ipaddress.IPv4Address("192.168.1.1"),
    pirewall_lan_ip=ipaddress.IPv4Address("192.168.100.1"),
    protected_network=ipaddress.IPv4Network("192.168.100.0/24"),
    admin_pc_candidates=(
        ipaddress.IPv4Address("192.168.100.10"),
        ipaddress.IPv4Address("192.168.100.11"),
    ),
)

_ANSWERS = configure.Answers(
    admin_pc_ip=ipaddress.IPv4Address("192.168.100.10"),
    admin_username="admin",
    admin_password_hash="scrypt$fake$hash",
)


def _scripted_input(monkeypatch: pytest.MonkeyPatch, answers: list[str]) -> None:
    """Feed `input()` a fixed sequence, so a prompt loop that never terminates fails loudly."""
    supplied: Iterator[str] = iter(answers)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(supplied))


def _written_config(tmp_path: Path) -> Path:
    path = tmp_path / "local_config.toml"
    configure.write_validated(path, configure.render_config(_DISCOVERED, _ANSWERS))
    return path


class TestRenderConfig:
    def test_the_generated_config_is_valid_and_needs_no_further_editing(
        self, tmp_path: Path
    ) -> None:
        config = load_config(_written_config(tmp_path))
        assert config.network.wan_interface == "eth0"
        assert config.network.lan_interface == "wlan0"
        assert config.capture.interface == "wlan0"  # capture faces the LAN, not the uplink
        assert str(config.network.upstream_gateway) == "192.168.1.1"
        assert str(config.network.pirewall_lan_ip) == "192.168.100.1"
        assert str(config.network.protected_network) == "192.168.100.0/24"
        assert str(config.admin.admin_pc_ip) == "192.168.100.10"

    def test_no_placeholder_survives_into_the_output(self, tmp_path: Path) -> None:
        """A generated config that still says CHANGE_ME would defeat the point."""
        assert "CHANGE_ME" not in _written_config(tmp_path).read_text(encoding="utf-8")

    def test_safe_defaults_are_preserved(self, tmp_path: Path) -> None:
        """Auto-configuration must not quietly relax A1/A6 (CLAUDE.md)."""
        config = load_config(_written_config(tmp_path))
        assert config.firewall.enforcement_mode.value == "shadow"
        assert config.failure.mode.value == "fail_open"
        assert config.security.restrict_to_admin_pc is True

    def test_the_api_binds_to_the_lan_address_so_the_admin_pc_can_reach_it(
        self, tmp_path: Path
    ) -> None:
        assert load_config(_written_config(tmp_path)).api.host == "192.168.100.1"

    def test_the_admin_pc_gets_an_allowlist_entry(self, tmp_path: Path) -> None:
        """ADDENDUM.md A2, as a second layer behind spec §24's safety validation."""
        allowlist = load_config(_written_config(tmp_path)).firewall.allowlist
        assert [str(entry.target) for entry in allowlist] == ["192.168.100.10/32"]

    def test_integration_hosts_default_to_the_admin_pc_but_stay_disabled(
        self, tmp_path: Path
    ) -> None:
        integration = load_config(_written_config(tmp_path)).integration
        assert integration.wazuh_host == "192.168.100.10"
        assert integration.netdata_host == "192.168.100.10"
        assert integration.wazuh_enabled is False
        assert integration.netdata_enabled is False


class TestWriteValidated:
    def test_an_invalid_config_is_never_written(self, tmp_path: Path) -> None:
        """A bug here must not leave a deployment with a config core will refuse on restart."""
        path = tmp_path / "local_config.toml"
        with pytest.raises(ConfigurationError):
            configure.write_validated(path, "[network]\nwan_interface = 'eth0'\n")
        assert not path.exists()
        assert list(tmp_path.iterdir()) == []  # no staging file left behind

    def test_an_existing_config_survives_a_failed_write(self, tmp_path: Path) -> None:
        path = _written_config(tmp_path)
        original = path.read_text(encoding="utf-8")
        with pytest.raises(ConfigurationError):
            configure.write_validated(path, "not = [valid toml\n")
        assert path.read_text(encoding="utf-8") == original


class TestPromptAdminPcIp:
    def test_a_candidate_can_be_chosen_by_number(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scripted_input(monkeypatch, ["2"])
        assert configure.prompt_admin_pc_ip(_DISCOVERED) == ipaddress.IPv4Address("192.168.100.11")

    def test_an_address_can_be_typed_even_if_it_was_never_seen(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A machine that is switched off right now is a perfectly valid Admin PC."""
        _scripted_input(monkeypatch, ["192.168.100.55"])
        assert configure.prompt_admin_pc_ip(_DISCOVERED) == ipaddress.IPv4Address("192.168.100.55")

    def test_it_never_defaults_to_a_candidate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Pressing enter must re-ask: "recently seen" is not evidence of "may administer"."""
        _scripted_input(monkeypatch, ["", "1"])
        assert configure.prompt_admin_pc_ip(_DISCOVERED) == ipaddress.IPv4Address("192.168.100.10")

    def test_an_out_of_range_selection_re_asks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scripted_input(monkeypatch, ["9", "1"])
        assert configure.prompt_admin_pc_ip(_DISCOVERED) == ipaddress.IPv4Address("192.168.100.10")

    def test_an_invalid_address_re_asks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scripted_input(monkeypatch, ["not-an-ip", "192.168.100.10"])
        assert configure.prompt_admin_pc_ip(_DISCOVERED) == ipaddress.IPv4Address("192.168.100.10")

    def test_an_address_outside_the_lan_requires_confirmation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Usually a typo — but an Admin PC over a VPN is legitimate, so it is confirmable."""
        _scripted_input(monkeypatch, ["10.9.9.9", "no", "192.168.100.10"])
        assert configure.prompt_admin_pc_ip(_DISCOVERED) == ipaddress.IPv4Address("192.168.100.10")

        _scripted_input(monkeypatch, ["10.9.9.9", "yes"])
        assert configure.prompt_admin_pc_ip(_DISCOVERED) == ipaddress.IPv4Address("10.9.9.9")


class TestSetAdminPc:
    def test_changes_the_admin_pc_and_every_value_that_follows_it(self, tmp_path: Path) -> None:
        path = _written_config(tmp_path)

        assert configure.run_set_admin_pc(path, "192.168.100.77") == configure.EXIT_OK

        config = load_config(path)
        assert str(config.admin.admin_pc_ip) == "192.168.100.77"
        # The A2 allowlist entry has to follow, or it would keep exempting a
        # machine that is no longer the Admin PC.
        assert [str(e.target) for e in config.firewall.allowlist] == ["192.168.100.77/32"]
        assert config.integration.wazuh_host == "192.168.100.77"
        assert config.integration.netdata_host == "192.168.100.77"

    def test_it_is_a_targeted_edit_not_a_regenerate(self, tmp_path: Path) -> None:
        """An operator's hand-tuned thresholds and comments must survive the change."""
        path = _written_config(tmp_path)
        text = path.read_text(encoding="utf-8").replace(
            "max_active_rules = 500", "max_active_rules = 12  # tuned by hand"
        )
        path.write_text(text, encoding="utf-8")

        configure.run_set_admin_pc(path, "192.168.100.77")

        updated = path.read_text(encoding="utf-8")
        assert "max_active_rules = 12  # tuned by hand" in updated
        assert load_config(path).firewall.max_active_rules == 12
        assert "# ADDENDUM.md A1" in updated  # comments survived

    def test_an_integration_host_pointed_elsewhere_is_left_alone(self, tmp_path: Path) -> None:
        """An operator who aimed Wazuh at a dedicated box meant it."""
        path = _written_config(tmp_path)
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                'wazuh_host = "192.168.100.10"', 'wazuh_host = "192.168.100.200"'
            ),
            encoding="utf-8",
        )

        configure.run_set_admin_pc(path, "192.168.100.77")

        config = load_config(path)
        assert config.integration.wazuh_host == "192.168.100.200"  # untouched
        assert config.integration.netdata_host == "192.168.100.77"  # followed

    def test_an_invalid_address_is_rejected_without_touching_the_file(
        self, tmp_path: Path
    ) -> None:
        path = _written_config(tmp_path)
        original = path.read_text(encoding="utf-8")
        assert configure.main(["--config", str(path), "--set-admin-pc", "--admin-pc-ip", "nope"]) == (
            configure.EXIT_FAILURE
        )
        assert path.read_text(encoding="utf-8") == original

    def test_a_missing_config_is_reported_rather_than_created(self, tmp_path: Path) -> None:
        missing = tmp_path / "absent.toml"
        exit_code = configure.main(
            ["--config", str(missing), "--set-admin-pc", "--admin-pc-ip", "192.168.100.77"]
        )
        assert exit_code == configure.EXIT_FAILURE
        assert not missing.exists()


class TestReplaceScalar:
    def test_edits_only_the_named_key_in_the_named_section(self) -> None:
        text = '[a]\nhost = "one"\n\n[b]\nhost = "two"\n'
        assert configure.replace_scalar(text, "b", "host", "three") == (
            '[a]\nhost = "one"\n\n[b]\nhost = "three"\n'
        )

    def test_a_missing_key_is_an_error_not_a_silent_append(self) -> None:
        """Appending a duplicate key would make the file's meaning depend on parse order."""
        with pytest.raises(ConfigurationError):
            configure.replace_scalar('[a]\nhost = "one"\n', "a", "port", "8443")

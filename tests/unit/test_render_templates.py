"""`scripts.deployment.render_templates` — config-driven `${TOKEN}` substitution (Phase 8)."""

from pathlib import Path

import pytest
from scripts.deployment.render_templates import render_all, render_template, substitution_mapping

from tests.helpers.config import make_config


def test_substitution_mapping_covers_every_template_token() -> None:
    config = make_config()
    mapping = substitution_mapping(config)

    assert mapping["WAN_INTERFACE"] == "eth0"
    assert mapping["LAN_INTERFACE"] == "eth1"
    assert mapping["PROTECTED_NETWORK"] == "192.168.1.0/24"
    assert mapping["UPSTREAM_GATEWAY"] == "192.168.1.1"
    assert mapping["ADMIN_PC_IP"] == "192.168.1.50"
    assert mapping["API_PORT"] == "8443"


def test_render_template_substitutes_every_token() -> None:
    config = make_config()
    text = "wan=${WAN_INTERFACE} lan=${LAN_INTERFACE} net=${PROTECTED_NETWORK} admin=${ADMIN_PC_IP}"

    rendered = render_template(text, config)

    assert rendered == "wan=eth0 lan=eth1 net=192.168.1.0/24 admin=192.168.1.50"
    assert "$" not in rendered


def test_render_template_raises_on_unknown_token() -> None:
    config = make_config()
    with pytest.raises(KeyError):
        render_template("${NOT_A_REAL_TOKEN}", config)


def test_render_all_renders_every_real_template_without_leftover_placeholders(tmp_path: Path) -> None:
    """Exercises the actual checked-in `deploy/network/`/`deploy/firewall/` templates end to end."""
    config = make_config()
    repo_root = Path(__file__).resolve().parent.parent.parent
    output_dir = tmp_path / "rendered"

    written = render_all(config, repo_root=repo_root, output_dir=output_dir)

    assert written, "expected at least one *.template file to be rendered"
    for path in written:
        assert path.exists()
        assert not path.name.endswith(".template")
        text = path.read_text(encoding="utf-8")
        assert "${" not in text, f"{path} still contains an unrendered placeholder"

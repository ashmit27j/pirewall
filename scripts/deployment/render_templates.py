"""CLI: render `deploy/network/` and `deploy/firewall/` `${TOKEN}` templates from real config.

Spec §21 / `CLAUDE.md`: never auto-modify network configuration. This
script only ever *writes rendered files to `deploy/rendered/`* — it never
touches `/etc`, never invokes `nft`, `sysctl`, `dhcpcd`, or any other
system-mutating command, and never runs on import. A human reviews every
rendered file before applying it by hand (see `deploy/network/README.md`).

Run on a development machine or the Pi itself, pointed at your real (not
the checked-in placeholder) config:

    uv run python -m scripts.deployment.render_templates --config config/local_config.toml

v2 (phase 13): the mapping also carries every variable the two v2 kernel
tables need (`deploy/firewall/pirewall_static.nft.template`,
`pirewall_adaptive.nft.template`): interfaces, the Admin PC's MAC, the
infrastructure list, every `[guards]` meter and set size, and the three
guard verdicts. The `[guards]` → variable map is frozen in
docs/V2_CONTRACTS.md §8.

**Rendering refuses rather than guessing.** A config value that is unset
(`network.admin_interface`, `admin.admin_pc_mac` on a 1.x config) is
*missing*, not empty, and any template that references a missing or
unknown `${TOKEN}` fails the whole run with every offending name listed.
Nothing is written in that case, so no half-rendered ruleset can be loaded
by hand. Substitution matches `${NAME}` only (like the sandbox renderer,
`docs/v2/v2/render.py`); a bare `$word` in a template is left alone.
"""

import argparse
import re
import sys
from pathlib import Path

from pirewall.config.loader import load_config
from pirewall.config.models import GuardsConfig, MeterSetting, PirewallConfig
from pirewall.core.enums import GuardMode
from pirewall.core.exceptions import ConfigurationError

_TEMPLATE_DIRS = ("deploy/network", "deploy/firewall")
_TEMPLATE_SUFFIX = ".template"
_TOKEN = re.compile(r"\$\{([A-Z0-9_]+)\}")

# `[guards]` meter -> (rate variable, burst variable), V2_CONTRACTS.md §8.
_METER_VARIABLES: tuple[tuple[str, str, str], ...] = (
    ("dhcp_per_minute", "DHCP_PER_MINUTE", "DHCP_BURST"),
    ("unbound", "UNBOUND_PPS", "UNBOUND_BURST"),
    ("syn", "SYN_PPS", "SYN_BURST"),
    ("icmp", "ICMP_PPS", "ICMP_BURST"),
    ("udp_local", "UDP_LOCAL_PPS", "UDP_LOCAL_BURST"),
    ("local_pps", "LOCAL_PPS", "LOCAL_BURST"),
    ("dns", "DNS_QPS", "DNS_BURST"),
    ("closed_port", "CLOSED_PPS", "CLOSED_BURST"),
    ("newconn", "NEWCONN_PPS", "NEWCONN_BURST"),
    ("newconn_dst", "NEWCONN_DST_PPS", "NEWCONN_DST_BURST"),
    ("udp_fwd", "UDP_FWD_PPS", "UDP_FWD_BURST"),
    ("global_unbound", "GLOBAL_UNBOUND_PPS", "GLOBAL_UNBOUND_BURST"),
    ("global_syn", "GLOBAL_SYN_PPS", "GLOBAL_SYN_BURST"),
    ("global_icmp", "GLOBAL_ICMP_PPS", "GLOBAL_ICMP_BURST"),
    ("global_udp_local", "GLOBAL_UDP_LOCAL_PPS", "GLOBAL_UDP_LOCAL_BURST"),
    ("global_newconn", "GLOBAL_NEWCONN_PPS", "GLOBAL_NEWCONN_BURST"),
    ("ratelimit", "RATELIMIT_PPS", "RATELIMIT_BURST"),
)


def verdict(mode: GuardMode) -> str:
    """A guard verdict chain's statement: `drop` to enforce, nothing to observe (D2)."""
    return "drop" if mode is GuardMode.ENFORCE else ""


def infra4_elements(config: PirewallConfig) -> str:
    """The never-target infrastructure list for `infra4`: the Pi's LAN address, the gateway, the Admin PC.

    Sorted and de-duplicated so a reload renders byte-identical output.
    """
    addresses = sorted(
        {config.network.pirewall_lan_ip, config.network.upstream_gateway, config.admin.admin_pc_ip}
    )
    return ", ".join(str(address) for address in addresses)


def _guard_values(guards: GuardsConfig) -> dict[str, str]:
    values: dict[str, str] = {}
    for field, rate_variable, burst_variable in _METER_VARIABLES:
        meter = getattr(guards, field)
        assert isinstance(meter, MeterSetting)
        values[rate_variable] = str(meter.rate)
        values[burst_variable] = str(meter.burst)
    values.update(
        {
            "PORTAL_CONCURRENCY": str(guards.portal_concurrency),
            "BINDING_SIZE": str(guards.binding_set_size),
            "METER_SIZE": str(guards.meter_set_size),
            "PAIR_METER_SIZE": str(guards.pair_meter_set_size),
            "OFFENDER_SIZE": str(guards.offender_set_size),
            "ADAPTIVE_SIZE": str(guards.adaptive_set_size),
            "RAW_VERDICT": verdict(guards.raw_mode),
            "INPUT_VERDICT": verdict(guards.input_mode),
            "FORWARD_VERDICT": verdict(guards.forward_mode),
        }
    )
    return values


def substitution_mapping(config: PirewallConfig) -> dict[str, str | None]:
    """Build the `${TOKEN} -> value` mapping every template's placeholders use.

    A value of None means the config leaves it unset: a template that needs
    it cannot be rendered (`render_template` refuses). Kept in one place so
    every template's tokens resolve against the same config fields.
    """
    mac = config.admin.admin_pc_mac
    mapping: dict[str, str | None] = {
        "WAN_INTERFACE": config.network.wan_interface,
        "LAN_INTERFACE": config.network.lan_interface,
        "ADMIN_INTERFACE": config.network.admin_interface,
        "PROTECTED_NETWORK": str(config.network.protected_network),
        "LAN_BROADCAST": str(config.network.protected_network.broadcast_address),
        "UPSTREAM_GATEWAY": str(config.network.upstream_gateway),
        "ADMIN_PC_IP": str(config.admin.admin_pc_ip),
        "ADMIN_PC_MAC": None if mac is None else str(mac),
        "API_PORT": str(config.api.port),
        "PIREWALL_LAN_IP": str(config.network.pirewall_lan_ip),
        "PORTAL_PORT": str(config.portal.listen_port),
        "INFRA4_ELEMENTS": infra4_elements(config),
    }
    mapping.update(_guard_values(config.guards))
    return mapping


def missing_tokens(text: str, mapping: dict[str, str | None]) -> list[str]:
    """Tokens `text` references that `mapping` cannot fill (unknown, or unset in config), sorted."""
    return sorted({name for name in _TOKEN.findall(text) if mapping.get(name) is None})


def render_template(text: str, config: PirewallConfig) -> str:
    """Substitute every `${TOKEN}` in `text` using `substitution_mapping(config)`.

    Raises `ConfigurationError` naming every token that is unknown or unset,
    rather than leaving an unrendered `${...}` in output a human might apply
    by hand without noticing.
    """
    mapping = substitution_mapping(config)
    missing = missing_tokens(text, mapping)
    if missing:
        raise ConfigurationError(f"missing template values: {', '.join(missing)}")
    return _TOKEN.sub(lambda match: mapping[match.group(1)] or "", text)


def render_all(config: PirewallConfig, repo_root: Path, output_dir: Path) -> list[Path]:
    """Render every `*.template` file under `deploy/network/`/`deploy/firewall/` into `output_dir`.

    All-or-nothing: every template is rendered in memory first, and the
    first failure raises before any file is written. Returns the files
    written. Non-template files (READMEs) in those directories are left alone.
    """
    rendered: list[tuple[Path, str]] = []
    problems: list[str] = []
    for relative_dir in _TEMPLATE_DIRS:
        source_dir = repo_root / relative_dir
        if not source_dir.is_dir():
            continue
        for template_path in sorted(source_dir.glob(f"*{_TEMPLATE_SUFFIX}")):
            try:
                text = render_template(template_path.read_text(encoding="utf-8"), config)
            except ConfigurationError as exc:
                problems.append(f"{template_path.relative_to(repo_root).as_posix()}: {exc}")
                continue
            rendered.append((output_dir / template_path.name.removesuffix(_TEMPLATE_SUFFIX), text))
    if problems:
        raise ConfigurationError("refusing to render:\n" + "\n".join(f"  - {line}" for line in problems))

    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for output_path, text in rendered:
        output_path.write_text(text, encoding="utf-8")
        written.append(output_path)
    return written


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="Path to your real config TOML.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("deploy/rendered"),
        help="Where to write rendered files (default: deploy/rendered/). Never applied automatically.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        config = load_config(args.config)
        written = render_all(config, repo_root=Path.cwd(), output_dir=args.output_dir)
    except ConfigurationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not written:
        print("no *.template files found under deploy/network/ or deploy/firewall/", file=sys.stderr)
        return 1

    for path in written:
        print(f"rendered {path}")
    print("\nReview every file above before applying it by hand — nothing was auto-applied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

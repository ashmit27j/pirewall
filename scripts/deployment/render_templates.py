"""CLI: render `deploy/network/` and `deploy/firewall/` `${TOKEN}` templates from real config.

Spec §21 / `CLAUDE.md`: never auto-modify network configuration. This
script only ever *writes rendered files to `deploy/rendered/`* — it never
touches `/etc`, never invokes `nft`, `sysctl`, `dhcpcd`, or any other
system-mutating command, and never runs on import. A human reviews every
rendered file before applying it by hand (see `deploy/network/README.md`).

Run on a development machine or the Pi itself, pointed at your real (not
the checked-in placeholder) config:

    uv run python -m scripts.deployment.render_templates --config config/local_config.toml
"""

import argparse
import sys
from pathlib import Path
from string import Template

from pirewall.config.loader import load_config
from pirewall.config.models import PirewallConfig
from pirewall.core.exceptions import ConfigurationError

_TEMPLATE_DIRS = ("deploy/network", "deploy/firewall")
_TEMPLATE_SUFFIX = ".template"


def substitution_mapping(config: PirewallConfig) -> dict[str, str]:
    """Build the `${TOKEN} -> value` mapping every template's placeholders use.

    Kept in one place so every template's tokens (documented in
    `deploy/network/README.md`) are guaranteed to resolve against the same
    config fields this function reads.
    """
    return {
        "WAN_INTERFACE": config.network.wan_interface,
        "LAN_INTERFACE": config.network.lan_interface,
        "PROTECTED_NETWORK": str(config.network.protected_network),
        "UPSTREAM_GATEWAY": str(config.network.upstream_gateway),
        "ADMIN_PC_IP": str(config.admin.admin_pc_ip),
        "API_PORT": str(config.api.port),
    }


def render_template(text: str, config: PirewallConfig) -> str:
    """Substitute every `${TOKEN}` in `text` using `substitution_mapping(config)`.

    Raises `KeyError` (via `Template.substitute`'s strict mode) if a
    template references a token this function doesn't know how to fill —
    deliberately loud rather than leaving an unrendered `${...}` in output
    a human might apply by hand without noticing.
    """
    return Template(text).substitute(substitution_mapping(config))


def render_all(config: PirewallConfig, repo_root: Path, output_dir: Path) -> list[Path]:
    """Render every `*.template` file under `deploy/network/`/`deploy/firewall/` into `output_dir`.

    Returns the list of files written. Non-template files (READMEs) in
    those directories are left alone.
    """
    written: list[Path] = []
    output_dir.mkdir(parents=True, exist_ok=True)
    for relative_dir in _TEMPLATE_DIRS:
        source_dir = repo_root / relative_dir
        if not source_dir.is_dir():
            continue
        for template_path in sorted(source_dir.glob(f"*{_TEMPLATE_SUFFIX}")):
            rendered_text = render_template(template_path.read_text(encoding="utf-8"), config)
            output_path = output_dir / template_path.name.removesuffix(_TEMPLATE_SUFFIX)
            output_path.write_text(rendered_text, encoding="utf-8")
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
    except ConfigurationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    written = render_all(config, repo_root=Path.cwd(), output_dir=args.output_dir)
    if not written:
        print("no *.template files found under deploy/network/ or deploy/firewall/", file=sys.stderr)
        return 1

    for path in written:
        print(f"rendered {path}")
    print("\nReview every file above before applying it by hand — nothing was auto-applied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

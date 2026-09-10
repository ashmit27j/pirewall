"""`pirewall-portal` entry point — `python -m pirewall.portal` (ADDENDUM_3.md C1).

The **LAN-facing** process, and the least privileged of the three. It has no
capabilities, no raw socket, no nftables access, and — unlike pirewall-api —
no access to pirewall-core's privileged RPC socket either. It talks only to
`portal.rpc_socket_path`, whose dispatcher implements four operations and
knows nothing about rules, the allowlist, or the kill switch.

Startup, with everything checkable checked before anything is bound:

1. Load and validate `PirewallConfig`.
2. Refuse to start unless `portal.enabled` is set — the portal gates
   forwarding for the whole protected network, so it is never something a
   deployment gets by accident.
3. Refuse to bind a privileged port. The nat chain redirects 80 here, so a
   configuration asking this process to bind 80 itself is a mistake that
   would need `CAP_NET_BIND_SERVICE` this process deliberately lacks.
4. Configure logging into `<log_dir>/portal.log` — its own file, since it
   runs as its own user.
5. Build the RPC client, the app, and serve it.

**Plain HTTP, deliberately** (ADDENDUM_3.md C5). A self-signed certificate
on a captive portal breaks OS captive-portal detection and trains users to
click through certificate warnings; every mainstream implementation serves
the sign-in page over HTTP for this reason. Portal credentials therefore
cross the LAN in the clear, which is why they are low-value network-access
credentials distinct from the admin password, and why the setup guide says
so plainly.

**pirewall-core being down is not a startup failure**, for the same reason
it isn't for pirewall-api: the RPC client connects lazily per call and the
app turns an `RpcError` into a 503 that explains itself.

Exit codes: `0` clean shutdown, `1` fatal startup failure.
"""

import argparse
import logging
import sys
from pathlib import Path

import uvicorn

from pirewall.config.loader import load_config
from pirewall.config.models import PirewallConfig
from pirewall.core.exceptions import ConfigurationError
from pirewall.core.logging import configure_logging
from pirewall.ipc.client import UnixSocketRpcClient
from pirewall.portal.app import create_app

_COMPONENT = "portal"
_DEFAULT_CONFIG_PATHS = (Path("config/local_config.toml"), Path("config/default_config.toml"))

EXIT_OK = 0
EXIT_FAILURE = 1


def default_config_path() -> Path:
    """First existing entry in `_DEFAULT_CONFIG_PATHS`, or the last one as a reportable target."""
    for candidate in _DEFAULT_CONFIG_PATHS:
        if candidate.is_file():
            return candidate
    return _DEFAULT_CONFIG_PATHS[-1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pirewall-portal",
        description="pirewall LAN captive portal (sign-in page for protected-network clients).",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="path to a pirewall TOML config (default: config/local_config.toml)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate configuration and exit without binding anything",
    )
    return parser


def validate_runtime_prerequisites(config: PirewallConfig) -> None:
    """Refuse to start on a configuration this process cannot honestly serve.

    Raises `ConfigurationError` with a message naming the offending setting.
    """
    if not config.portal.enabled:
        raise ConfigurationError(
            "portal.enabled is false — set it to true in the config before starting "
            "pirewall-portal, or leave this service stopped"
        )
    if config.portal.listen_port < 1024:
        raise ConfigurationError(
            f"portal.listen_port is {config.portal.listen_port}: pirewall-portal runs without "
            "CAP_NET_BIND_SERVICE and cannot bind a privileged port. Port 80 reaches it via the "
            "nat redirect in deploy/firewall/portal.nft, not by binding it directly."
        )
    if config.portal.listen_host not in config.network.protected_network:
        raise ConfigurationError(
            f"portal.listen_host {config.portal.listen_host} is not inside the protected network "
            f"{config.network.protected_network} — the portal must be reachable by LAN clients "
            "and must not be exposed on the WAN or admin segments"
        )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config_path = args.config or default_config_path()

    try:
        config = load_config(config_path)
        validate_runtime_prerequisites(config)
    except ConfigurationError as exc:
        print(f"pirewall-portal: configuration error: {exc}", file=sys.stderr)
        return EXIT_FAILURE

    if args.check_config:
        print(
            f"pirewall-portal: configuration OK ({config_path}); would serve "
            f"http://{config.portal.listen_host}:{config.portal.listen_port} "
            f"via core socket {config.portal.rpc_socket_path}"
        )
        return EXIT_OK

    # Its own directory, not `logging.log_dir`: that one is shared by
    # pirewall-core and pirewall-api through the `pirewall-ipc` group, which
    # this process is deliberately not a member of (ADDENDUM_3.md C1).
    # Pointing it there would make it fail to open its log on every start and
    # silently fall back to stderr.
    portal_logging = config.logging.model_copy(update={"log_dir": config.portal.log_dir})
    configure_logging(portal_logging, _COMPONENT)
    logger = logging.getLogger(__name__)
    logger.info(
        "pirewall-portal starting with config %s (log: %s/%s.log)",
        config_path,
        config.portal.log_dir,
        _COMPONENT,
    )
    logger.info(
        "serving http://%s:%s for %s, core socket %s, sessions %ss",
        config.portal.listen_host,
        config.portal.listen_port,
        config.network.protected_network,
        config.portal.rpc_socket_path,
        config.portal.session_timeout_seconds,
    )

    # Longer than the 5s default. A login round-trip includes scrypt
    # verification, which is deliberately slow, executed under the single
    # lock pirewall-core serializes every RPC behind — so it contends with
    # the detection pipeline and with model loading at startup. At 5s that
    # was observed timing out *after* core had already authorized the
    # client, leaving the user told their password was wrong while their
    # address was forwarding. `PortalService.reconcile` now cleans up such
    # an orphan, but not tripping the timeout in the first place is better.
    rpc_client = UnixSocketRpcClient(
        config.portal.rpc_socket_path, timeout_seconds=config.portal.rpc_timeout_seconds
    )
    app = create_app(config, rpc_client)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=str(config.portal.listen_host),
            port=config.portal.listen_port,
            # Never trust forwarding headers: `client.host` decides who gets
            # authorized for forwarding, so it must be the real peer address.
            proxy_headers=False,
            server_header=False,
            date_header=False,
            log_config=None,
        )
    )
    server.run()
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())

"""`pirewall-api` entry point — `python -m pirewall.api` (ADDENDUM.md A4, spec §28, §29).

The **unprivileged** half of the process split. It has no raw socket, no
nftables access, and no capabilities at all (see
`deploy/systemd/pirewall-api.service`). Everything it reports or changes
goes through one `UnixSocketRpcClient` connected to pirewall-core's
`AF_UNIX` socket. That constraint is enforced mechanically, not by
convention: `tests/security/test_api_process_isolation.py` asserts that
nothing under `pirewall/api/` or `pirewall/web/` imports
`pirewall.capture`, `pirewall.firewall.manager`, or
`pirewall.firewall.backend` — directly *or* transitively — and this module
is inside that scanned tree.

Startup sequence, in order, with everything that can fail checked before
anything is bound:

1. Load and validate `PirewallConfig`.
2. Refuse to start on a placeholder credential or a missing/unreadable TLS
   certificate or key. Spec §29 requires HTTPS with authentication; a
   control panel that quietly came up on plain HTTP, or with
   `admin_password_hash = "CHANGE_ME"`, would be worse than one that
   refuses to start and says why.
3. Configure logging into `<log_dir>/api.log` — a *different* file from
   pirewall-core's, because the two run as different users.
4. Build the RPC client, the FastAPI app, and serve it over TLS.

**pirewall-core being down is not a startup failure.** A4's whole point is
that pirewall-api outlives a crash-looping core so it can report that fact;
the RPC client connects lazily per call, and `pirewall.api.app` turns an
`RpcError` into a 503 with a diagnosis rather than a traceback.

Exit codes: `0` clean shutdown, `1` fatal startup failure.
"""

import argparse
import logging
import ssl
import sys
from collections.abc import Callable
from pathlib import Path

import uvicorn

from pirewall.api.app import create_app
from pirewall.config.loader import load_config
from pirewall.config.models import PirewallConfig
from pirewall.core.exceptions import ConfigurationError
from pirewall.core.logging import configure_logging
from pirewall.ipc.client import UnixSocketRpcClient

_COMPONENT = "api"
_DEFAULT_CONFIG_PATHS = (Path("config/local_config.toml"), Path("config/default_config.toml"))

# Values `config/default_config.toml` ships as deliberate placeholders. Any
# of them surviving into a real deployment is an operator error worth
# failing loudly on, not a default worth honouring.
_PLACEHOLDER = "CHANGE_ME"

_TLS_VERSIONS = {
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

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
        prog="pirewall-api",
        description="pirewall HTTPS control panel and JSON API.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="path to a pirewall TOML config file (default: config/local_config.toml, "
        "falling back to config/default_config.toml)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate the configuration, credentials and TLS material, then exit",
    )
    return parser


def validate_runtime_prerequisites(config: PirewallConfig) -> None:
    """Raise `ConfigurationError` for anything that would make serving unsafe or impossible.

    `pirewall.config.models` cannot express these: it validates *shape*, and
    a placeholder string or a path pointing at a file that does not exist is
    a perfectly well-shaped `str`. Checking them here means the failure is a
    clear message at startup rather than a TLS handshake error, or — far
    worse — a control panel reachable with a credential nobody set.
    """
    problems: list[str] = []

    if _PLACEHOLDER in config.authentication.admin_username:
        problems.append("authentication.admin_username is still the CHANGE_ME placeholder")
    if _PLACEHOLDER in config.authentication.admin_password_hash:
        problems.append(
            "authentication.admin_password_hash is still the CHANGE_ME placeholder; generate one "
            'with: uv run python -c "from pirewall.api.auth import hash_password; import getpass; '
            'print(hash_password(getpass.getpass()))"'
        )

    for label, raw_path in (
        ("api.tls_cert_path", config.api.tls_cert_path),
        ("api.tls_key_path", config.api.tls_key_path),
    ):
        if _PLACEHOLDER in raw_path:
            problems.append(f"{label} is still the CHANGE_ME placeholder")
            continue
        path = Path(raw_path)
        if not path.is_file():
            problems.append(f"{label} points at {path}, which does not exist or is not a file")
        elif not _is_readable(path):
            problems.append(f"{label} points at {path}, which is not readable by this user")

    if config.security.min_tls_version not in _TLS_VERSIONS:
        supported = ", ".join(sorted(_TLS_VERSIONS))
        problems.append(
            f"security.min_tls_version={config.security.min_tls_version!r} is not supported "
            f"(supported: {supported})"
        )

    if problems:
        raise ConfigurationError(
            "pirewall-api cannot start:\n" + "\n".join(f"  - {problem}" for problem in problems)
        )


def _is_readable(path: Path) -> bool:
    try:
        with path.open("rb"):
            return True
    except OSError:
        return False


def make_ssl_context_factory(
    minimum_version: ssl.TLSVersion,
) -> Callable[[uvicorn.Config, Callable[[], ssl.SSLContext]], ssl.SSLContext]:
    """Build uvicorn's `ssl_context_factory`, pinning a minimum TLS version (spec §29).

    uvicorn's own `ssl_version=` sets the *protocol family*, not a floor, so
    it cannot express `security.min_tls_version` on its own. This wraps
    uvicorn's default context and raises the floor on the result, which is
    what the documented `ssl_context_factory` hook exists for.
    """

    def factory(
        _config: uvicorn.Config, default_factory: Callable[[], ssl.SSLContext]
    ) -> ssl.SSLContext:
        context = default_factory()
        context.minimum_version = minimum_version
        return context

    return factory


def build_server(config: PirewallConfig) -> uvicorn.Server:
    """Wire the RPC client, the FastAPI app, and TLS into a ready-to-run uvicorn server."""
    rpc_client = UnixSocketRpcClient(config.api.rpc_socket_path)
    app = create_app(config, rpc_client)
    server_config = uvicorn.Config(
        app=app,
        host=config.api.host,
        port=config.api.port,
        ssl_certfile=config.api.tls_cert_path,
        ssl_keyfile=config.api.tls_key_path,
        ssl_context_factory=make_ssl_context_factory(
            _TLS_VERSIONS[config.security.min_tls_version]
        ),
        # pirewall configures the root logger itself (`pirewall.core.logging`)
        # so pirewall-core and pirewall-api produce identically formatted
        # logs; letting uvicorn install its own dictConfig would replace that.
        log_config=None,
        access_log=True,
        # Trusting a forwarded client IP would defeat `require_admin_pc`:
        # anyone could set `X-Forwarded-For` to the Admin PC's address. The
        # Admin PC connects to the Pi directly, so there is no proxy to
        # trust and this stays off.
        proxy_headers=False,
        server_header=False,
        date_header=False,
    )
    return uvicorn.Server(server_config)


def main(argv: list[str] | None = None) -> int:
    """Run pirewall-api. Returns the process exit code."""
    args = build_parser().parse_args(argv)
    config_path = args.config if args.config is not None else default_config_path()

    try:
        config = load_config(config_path)
        validate_runtime_prerequisites(config)
    except ConfigurationError as exc:
        print(f"pirewall-api: {exc}", file=sys.stderr)
        return EXIT_FAILURE

    if args.check_config:
        print(f"pirewall-api: configuration at {config_path} is valid")
        return EXIT_OK

    log_path = configure_logging(config.logging, _COMPONENT)
    logger = logging.getLogger(__name__)
    logger.info("pirewall-api starting with config %s (log: %s)", config_path, log_path or "stderr")
    logger.info(
        "serving https://%s:%s (min TLS %s), admin PC %s, core socket %s",
        config.api.host,
        config.api.port,
        config.security.min_tls_version,
        config.admin.admin_pc_ip if config.security.restrict_to_admin_pc else "unrestricted",
        config.api.rpc_socket_path,
    )

    # uvicorn installs its own SIGTERM/SIGINT handlers and shuts the server
    # down cleanly, so pirewall-api needs none of its own.
    build_server(config).run()
    logger.info("pirewall-api stopped")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())

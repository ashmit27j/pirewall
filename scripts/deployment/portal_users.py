"""Manage the captive portal's LAN user accounts (ADDENDUM_3.md C3).

    python -m scripts.deployment.portal_users list
    python -m scripts.deployment.portal_users add <username> [--note TEXT]
    python -m scripts.deployment.portal_users passwd <username>
    python -m scripts.deployment.portal_users remove <username>
    python -m scripts.deployment.portal_users seed-demo --i-understand-these-are-insecure

Writes one JSON file and nothing else. It never starts a service, never
touches `/etc`, never invokes `nft` — the same discipline
`scripts/deployment/configure.py` holds to.

Run it as the user that owns the store (`pirewall-core`), or as root; the
file is mode 0600 and pirewall-core is its only writer at runtime. Changes
are picked up on the next pirewall-core restart, or immediately for
`add`/`remove` done through the control panel instead.

Passwords are never echoed and never stored in the clear: `add` and
`passwd` prompt twice via `getpass`, and only the scrypt hash is written.
"""

import argparse
import getpass
import sys
from datetime import UTC, datetime
from pathlib import Path

from pirewall.config.loader import load_config
from pirewall.core.exceptions import ConfigurationError, PirewallError
from pirewall.portal.store import PortalUserStore

_DEFAULT_CONFIG_PATHS = (Path("config/local_config.toml"), Path("config/default_config.toml"))

EXIT_OK = 0
EXIT_FAILURE = 1

# Fixed, published, obviously-fake credentials. These are documented in
# docs/SETUP.md on purpose, which is precisely why they must never be
# secrets: a generated password written into a git-tracked file would be a
# committed credential (CLAUDE.md), while these are non-secret by
# construction and exist only to be deleted.
DEMO_ACCOUNTS: tuple[tuple[str, str], tuple[str, str], tuple[str, str], tuple[str, str], tuple[str, str]] = (
    ("demo-alice", "pirewall-demo-1"),
    ("demo-bob", "pirewall-demo-2"),
    ("demo-carol", "pirewall-demo-3"),
    ("demo-dave", "pirewall-demo-4"),
    ("demo-erin", "pirewall-demo-5"),
)


def default_config_path() -> Path:
    for candidate in _DEFAULT_CONFIG_PATHS:
        if candidate.is_file():
            return candidate
    return _DEFAULT_CONFIG_PATHS[-1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portal_users",
        description="Manage pirewall captive-portal user accounts.",
    )
    parser.add_argument("--config", type=Path, default=None, help="path to a pirewall TOML config")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list accounts (never shows password material)")

    add = sub.add_parser("add", help="create an account, prompting for its password")
    add.add_argument("username")
    add.add_argument("--note", default="", help="free-text note, e.g. the device or person")

    passwd = sub.add_parser("passwd", help="change an account's password")
    passwd.add_argument("username")

    remove = sub.add_parser("remove", help="delete an account")
    remove.add_argument("username")

    seed = sub.add_parser("seed-demo", help="create the five documented demo accounts")
    seed.add_argument(
        "--i-understand-these-are-insecure",
        action="store_true",
        dest="acknowledged",
        help="required: these passwords are published in docs/SETUP.md",
    )
    return parser


def prompt_new_password(username: str) -> str:
    """Ask twice, never echo, never accept an empty value."""
    for _attempt in range(3):
        first = getpass.getpass(f"New password for {username!r}: ")
        if not first:
            print("Password must not be empty.", file=sys.stderr)
            continue
        if first != getpass.getpass("Repeat password: "):
            print("Passwords did not match.", file=sys.stderr)
            continue
        return first
    raise ConfigurationError("could not read a matching password after 3 attempts")


def _open_store(config_path: Path) -> PortalUserStore:
    config = load_config(config_path)
    return PortalUserStore(config.portal.user_store_path)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config_path = args.config or default_config_path()

    try:
        store = _open_store(config_path)
        return _run(args, store)
    except PirewallError as exc:
        print(f"portal_users: {exc}", file=sys.stderr)
        return EXIT_FAILURE


def _run(args: argparse.Namespace, store: PortalUserStore) -> int:
    now = datetime.now(UTC)

    if args.command == "list":
        users = store.list_users()
        if not users:
            print(f"No portal accounts in {store.path}.")
            return EXIT_OK
        print(f"{len(users)} portal account(s) in {store.path}:\n")
        print(f"{'USERNAME':<20} {'CREATED':<20} {'BY':<12} {'DEMO':<5} NOTE")
        for user in users:
            created_at = user.created_at.strftime("%Y-%m-%d %H:%M:%S")
            demo = "YES" if user.is_demo else "-"
            print(
                f"{user.username:<20} {created_at:<20} {user.created_by:<12} "
                f"{demo:<5} {user.note}"
            )
        if store.has_demo_accounts():
            print(
                "\nWARNING: demo accounts are present. Their passwords are published in "
                "docs/SETUP.md — remove them before production use.",
                file=sys.stderr,
            )
        return EXIT_OK

    if args.command == "add":
        password = prompt_new_password(args.username)
        store.add(args.username, password, now, created_by="cli", note=args.note)
        print(f"Created portal account {args.username!r} in {store.path}.")
        return EXIT_OK

    if args.command == "passwd":
        password = prompt_new_password(args.username)
        store.set_password(args.username, password)
        print(f"Password changed for {args.username!r}. Any active session for it has ended.")
        return EXIT_OK

    if args.command == "remove":
        if not store.remove(args.username):
            print(f"portal_users: no such account: {args.username!r}", file=sys.stderr)
            return EXIT_FAILURE
        print(f"Removed portal account {args.username!r}.")
        return EXIT_OK

    if args.command == "seed-demo":
        if not args.acknowledged:
            print(
                "portal_users: refusing to seed demo accounts without "
                "--i-understand-these-are-insecure.\n"
                "These five accounts use fixed passwords published in docs/SETUP.md. "
                "They exist to prove the portal works, and must be removed before "
                "this network carries real traffic.",
                file=sys.stderr,
            )
            return EXIT_FAILURE
        created: list[str] = []
        for username, password in DEMO_ACCOUNTS:
            if store.get(username) is not None:
                continue
            store.add(username, password, now, created_by="seed-demo", note="demo account", is_demo=True)
            created.append(username)
        if created:
            print(f"Created {len(created)} demo account(s): {', '.join(created)}")
        else:
            print("All demo accounts already exist; nothing to do.")
        print(
            "\nWARNING: these passwords are published in docs/SETUP.md. Remove these "
            "accounts before production use:\n"
            "  python -m scripts.deployment.portal_users remove <username>",
            file=sys.stderr,
        )
        return EXIT_OK

    raise ConfigurationError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())

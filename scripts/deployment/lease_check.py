"""CLI: is `antispoof.lease_file` the file a running dnsmasq is actually writing?

Portal sign-in is refused for a client with no IP<->MAC binding (phase 14),
and bindings come from this file. A path that is wrong, or that names a file
dnsmasq stopped writing after the LAN moved to another interface, does not
fail loudly. The file just never changes, and nobody can sign in.
`pirewall-start` runs this in preflight and refuses to bring the portal up
on anything but `ok`.

The check, in order:

* the file exists and this process can read it;
* some running `dnsmasq` was started with `--dhcp-leasefile` (or `-l`)
  naming **this** file, read from `/proc/<pid>/cmdline`. NetworkManager's
  shared mode starts one per shared interface, which is how a stale path
  shows up: the dnsmasq that is running writes a different file.

The file's contents are client-controlled. They go through the runtime's
own `parse_leases` and only counts are reported, never a hostname or
client-id.

Usage:

    uv run python -m scripts.deployment.lease_check                # human-readable, exit 1 on a problem
    uv run python -m scripts.deployment.lease_check --shell        # KEY=value lines for pirewall-start
    ... --config PATH                                              # default config/local_config.toml

Exit codes: 0 ok, 1 a problem with the lease file, 2 the config cannot be loaded.
With `--shell` the state is in `LEASE_STATE` and the exit code is 0 unless
the config cannot be loaded.
"""

import argparse
import os
import shlex
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Network
from pathlib import Path

from pirewall.config.loader import load_config
from pirewall.core.bindings import MAX_LEASE_FILE_BYTES, parse_leases
from pirewall.core.exceptions import ConfigurationError

DEFAULT_CONFIG_PATH = Path("config/local_config.toml")
_PROC = Path("/proc")
_DNSMASQ = "dnsmasq"
_LEASEFILE_LONG = "--dhcp-leasefile"
_LEASEFILE_SHORT = "-l"

EXIT_OK = 0
EXIT_PROBLEM = 1
EXIT_CONFIG = 2


class LeaseFileState(StrEnum):
    """The outcome of one lease-file check."""

    OK = "ok"
    MISSING = "missing"
    UNREADABLE = "unreadable"
    NO_DNSMASQ = "no_dnsmasq"
    OTHER_FILE = "other_file"


@dataclass(frozen=True, slots=True)
class LeaseFileCheck:
    """What `check_lease_file` found. `message` is safe to print: paths and counts only."""

    state: LeaseFileState
    path: str
    writers: tuple[str, ...]
    leases: int
    message: str


def dnsmasq_lease_files(cmdlines: Iterable[Sequence[str]]) -> tuple[str, ...]:
    """The lease files the given process command lines say a dnsmasq is writing, sorted, deduplicated.

    Only argv entries of processes whose executable is `dnsmasq` count.
    Accepts `--dhcp-leasefile=PATH`, `--dhcp-leasefile PATH`, `-l PATH` and
    `-lPATH`, the spellings dnsmasq itself accepts.
    """
    found: set[str] = set()
    for argv in cmdlines:
        if not argv or os.path.basename(argv[0]) != _DNSMASQ:
            continue
        arguments = list(argv[1:])
        for index, argument in enumerate(arguments):
            following = arguments[index + 1] if index + 1 < len(arguments) else ""
            if argument.startswith(f"{_LEASEFILE_LONG}="):
                found.add(argument.split("=", 1)[1])
            elif argument in (_LEASEFILE_LONG, _LEASEFILE_SHORT) and following:
                found.add(following)
            elif argument.startswith(_LEASEFILE_SHORT) and argument[1:2] != "-" and len(argument) > 2:
                found.add(argument[2:])
    return tuple(sorted(path for path in found if path))


def read_cmdlines(proc: Path = _PROC) -> list[list[str]]:
    """Every readable `/proc/<pid>/cmdline`, split on NUL. Processes that vanish mid-scan are skipped."""
    cmdlines: list[list[str]] = []
    try:
        entries = list(proc.iterdir())
    except OSError:
        return cmdlines
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        argv = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
        if argv:
            cmdlines.append(argv)
    return cmdlines


def _same_file(left: str, right: str) -> bool:
    return Path(left).resolve(strict=False) == Path(right).resolve(strict=False)


def check_lease_file(
    path: str, cmdlines: Iterable[Sequence[str]], protected_network: IPv4Network
) -> LeaseFileCheck:
    """Check that `path` exists, is readable, and is what a running dnsmasq writes."""
    writers = dnsmasq_lease_files(cmdlines)
    lease_path = Path(path)
    try:
        exists = lease_path.exists()
    except OSError as exc:
        # A parent directory this process cannot stat is not "missing": the
        # operator needs to know the path may exist but the check cannot see
        # it (e.g. /var/lib/NetworkManager is root-only for a non-root run).
        return LeaseFileCheck(
            LeaseFileState.UNREADABLE,
            path,
            writers,
            0,
            f"lease file {path} cannot be inspected ({exc.strerror or type(exc).__name__})",
        )
    if not exists:
        return LeaseFileCheck(
            LeaseFileState.MISSING,
            path,
            writers,
            0,
            f"lease file {path} does not exist" + _writers_hint(writers),
        )
    try:
        with lease_path.open("rb") as handle:
            raw = handle.read(MAX_LEASE_FILE_BYTES + 1)
    except OSError as exc:
        return LeaseFileCheck(
            LeaseFileState.UNREADABLE,
            path,
            writers,
            0,
            f"lease file {path} cannot be read ({exc.strerror or type(exc).__name__})",
        )
    leases = len(parse_leases(raw.decode("utf-8", errors="replace"), protected_network).bindings)
    if not writers:
        return LeaseFileCheck(
            LeaseFileState.NO_DNSMASQ,
            path,
            writers,
            leases,
            f"no running dnsmasq is writing {path}, so its leases are stale or never update "
            "(is the NetworkManager shared connection up?)",
        )
    if not any(_same_file(path, writer) for writer in writers):
        return LeaseFileCheck(
            LeaseFileState.OTHER_FILE,
            path,
            writers,
            leases,
            f"no running dnsmasq is writing {path}" + _writers_hint(writers),
        )
    return LeaseFileCheck(
        LeaseFileState.OK,
        path,
        writers,
        leases,
        f"lease file {path} is written by a running dnsmasq ({leases} current IPv4 lease(s))",
    )


def _writers_hint(writers: tuple[str, ...]) -> str:
    if not writers:
        return ""
    return "; the running dnsmasq writes " + ", ".join(writers)


def build_parser() -> argparse.ArgumentParser:
    """The CLI's argument parser."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0] if __doc__ else None)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--shell", action="store_true", help="print shell-quoted KEY=value lines")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the check against `--config`'s `antispoof.lease_file`."""
    arguments = build_parser().parse_args(argv)
    try:
        config = load_config(arguments.config)
    except ConfigurationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    result = check_lease_file(config.antispoof.lease_file, read_cmdlines(), config.network.protected_network)
    if arguments.shell:
        for key, value in (
            ("LEASE_STATE", result.state.value),
            ("LEASE_FILE", result.path),
            ("LEASE_COUNT", str(result.leases)),
            ("LEASE_MESSAGE", result.message),
        ):
            print(f"{key}={shlex.quote(value)}")
        return EXIT_OK
    print(result.message)
    return EXIT_OK if result.state is LeaseFileState.OK else EXIT_PROBLEM


if __name__ == "__main__":
    sys.exit(main())

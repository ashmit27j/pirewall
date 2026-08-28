"""CLI: build `config/local_config.toml` from the live network plus a few operator answers.

The split this implements, and why it is drawn where it is:

* **Detected, not asked** — everything that is an observable fact about the
  running machine: WAN/LAN interfaces, the LAN's CIDR, the Pi's own LAN
  address, the upstream gateway. These are exactly the values a human is
  most likely to mistype, and two of them
  (`network.pirewall_lan_ip`, `network.upstream_gateway`) are the addresses
  safety validation refuses to ever block (spec §24) — a typo there
  silently removes the protection that stops pirewall locking you out.
* **Asked, never guessed** — `admin.admin_pc_ip` and the admin password.
  The Admin PC is a *policy* decision ("which machine may administer this
  firewall"), not an observation. The neighbour table only knows which
  hosts have recently talked to the Pi, which is a different question, and
  guessing wrong either locks the operator out or hands administrative
  access to the wrong host. So detected neighbours are offered as a
  numbered list and a human chooses — including the option of typing an
  address that has not appeared on the network yet.

Spec §21 / `CLAUDE.md`: this **writes one config file and nothing else**.
It never brings up an interface, never touches `/etc`, never invokes `nft`
or `systemctl`. Network configuration itself stays a reviewed, manual step
(`deploy/network/`, `docs/SETUP.md`).

Nothing is written until the generated file has been parsed and validated
through the real `pirewall.config.loader`, so this cannot leave a
half-written or invalid config behind.

Usage:

    uv run python -m scripts.deployment.configure                 # full interactive setup
    uv run python -m scripts.deployment.configure --detect        # show detection, write nothing
    uv run python -m scripts.deployment.configure --set-admin-pc  # change only the Admin PC
    uv run python -m scripts.deployment.configure --set-password  # rotate only the admin password
"""

import argparse
import getpass
import ipaddress
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from pirewall.api.auth import hash_password
from pirewall.config.loader import load_config
from pirewall.core.exceptions import ConfigurationError
from scripts.deployment.discovery import DiscoveredNetwork, DiscoveryError, discover

DEFAULT_CONFIG_PATH = Path("config/local_config.toml")

# The Admin PC allowlist entry (ADDENDUM.md A2) is rewritten by
# `--set-admin-pc` alongside `[admin] admin_pc_ip`, so it is tagged rather
# than found by guessing at TOML structure.
_ADMIN_PC_ALLOWLIST_MARKER = "# pirewall:admin-pc-allowlist"

EXIT_OK = 0
EXIT_FAILURE = 1


@dataclass(frozen=True, slots=True)
class Answers:
    """The values a human supplies, as opposed to the ones `discovery` observes."""

    admin_pc_ip: ipaddress.IPv4Address
    admin_username: str
    admin_password_hash: str


# --------------------------------------------------------------------- prompts


def _prompt(question: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        answer = input(f"{question}{suffix}: ").strip()
        if answer:
            return answer
        if default is not None:
            return default
        print("  A value is required.")


def prompt_admin_pc_ip(discovered: DiscoveredNetwork) -> ipaddress.IPv4Address:
    """Ask which host may administer the firewall, offering detected neighbours as candidates.

    Deliberately never defaults to a candidate, even when exactly one was
    found: "this host has talked to the Pi recently" is not evidence that it
    should be allowed to administer the firewall. A host that is powered off
    right now is a perfectly valid answer, which is why typing an address
    directly is always available.
    """
    print("\nWhich machine may administer pirewall? (config: admin.admin_pc_ip)")
    print("  Only this address can reach the control panel or the API (spec §29),")
    print("  and adaptive rules can never block it (spec §24).")

    candidates = discovered.admin_pc_candidates
    if candidates:
        print(f"\n  Hosts seen on {discovered.lan_interface} — these are candidates, not a guess:")
        for index, candidate in enumerate(candidates, start=1):
            print(f"    {index}) {candidate}")
        print("    or type any IPv4 address (e.g. a machine that is currently switched off)")
    else:
        print(f"\n  No other hosts seen on {discovered.lan_interface} yet — type the address.")

    while True:
        answer = _prompt("  Admin PC")
        if candidates and answer.isdigit():
            choice = int(answer)
            if 1 <= choice <= len(candidates):
                return candidates[choice - 1]
            print(f"  Pick 1-{len(candidates)}, or type an IPv4 address.")
            continue
        try:
            address = ipaddress.IPv4Address(answer)
        except ValueError:
            print(f"  {answer!r} is not a valid IPv4 address.")
            continue
        if address not in discovered.protected_network:
            # Not fatal: an Admin PC reached over a VPN or a routed segment
            # is legitimate. But it is worth an explicit confirmation,
            # because the usual cause is a typo.
            print(
                f"  Warning: {address} is outside the protected network "
                f"({discovered.protected_network}), so it may not be able to reach the Pi."
            )
            if _prompt("  Use it anyway? (yes/no)", "no").lower() not in {"y", "yes"}:
                continue
        return address


def prompt_password_hash() -> str:
    """Ask for the admin password twice and return its hash. The plaintext is never stored."""
    print("\nAdmin password for the control panel (config: authentication.admin_password_hash)")
    print("  Only the hash is written to the config file; the password itself is never stored.")
    while True:
        password = getpass.getpass("  Password: ")
        if not password:
            print("  A password is required.")
            continue
        if password != getpass.getpass("  Confirm: "):
            print("  The two entries did not match.")
            continue
        return hash_password(password)


def collect_answers(discovered: DiscoveredNetwork) -> Answers:
    """Ask for everything that is a policy decision rather than an observable fact."""
    admin_pc_ip = prompt_admin_pc_ip(discovered)
    username = _prompt("\nAdmin username (config: authentication.admin_username)", "admin")
    return Answers(
        admin_pc_ip=admin_pc_ip,
        admin_username=username,
        admin_password_hash=prompt_password_hash(),
    )


# ------------------------------------------------------------------- rendering


def render_config(discovered: DiscoveredNetwork, answers: Answers) -> str:
    """Build the full `local_config.toml` text.

    Every value here is either detected or answered — there are no
    `CHANGE_ME` placeholders left in the output, which is the whole point:
    a config this script wrote is one both entry points will accept.
    """
    return f'''# pirewall local configuration.
#
# Generated by `python -m scripts.deployment.configure`. Gitignored and
# never committed — it holds your real network layout and a password hash.
#
# The [network] and [capture] values below were DETECTED from this machine
# (`ip route show default`, `ip addr show`). The Admin PC and credentials
# were supplied by an operator — see that script's docstring for why those
# two are never guessed.
#
# Re-run after any change:
#   python -m scripts.deployment.configure --set-admin-pc   # move the Admin PC
#   python -m scripts.deployment.configure --set-password   # rotate the password
#   python -m pirewall.main --check-config                  # validate
#
# Editing by hand is fine too; `--check-config` is the safety net either way.

[network]
wan_interface = "{discovered.wan_interface}"
lan_interface = "{discovered.lan_interface}"
protected_network = "{discovered.protected_network}"
# The home router on the WAN side. Safety validation refuses to ever block
# this, so a wrong value means the rule that severs your internet would not
# be caught (spec §24).
upstream_gateway = "{discovered.upstream_gateway}"
# The Pi's own LAN address: every client's default gateway, and where the
# Admin PC reaches the control panel. Also never blockable (spec §24).
pirewall_lan_ip = "{discovered.pirewall_lan_ip}"

[capture]
# The interface facing the protected LAN — not the uplink.
interface = "{discovered.lan_interface}"
snap_len = 65535
promiscuous = true
buffer_size_bytes = 2097152

[flow]
active_timeout_seconds = 1800
inactive_timeout_seconds = 60
max_flows = 100000
cleanup_interval_seconds = 30

[features]
schema_version = "1.0.0"

[detection]
known_attack_confidence_threshold = 0.8
anomaly_score_threshold = 0.0
behavior_window_seconds = 300
max_tracked_sources = 10000
max_tracked_destinations_per_source = 200
max_tracked_ports_per_source = 200
recent_connections_window = 50
repeated_connections_threshold = 20
high_frequency_per_second_threshold = 2.0
burst_window_seconds = 5.0
burst_count_threshold = 10
persistence_seconds_threshold = 1800.0
destination_diversity_threshold = 15
scanning_port_threshold = 10
repeated_failures_threshold = 10
temporal_pattern_cv_threshold = 0.15

[ml]
# Both artifacts are gitignored and trained separately. If either is
# missing, pirewall-core logs a warning and runs behaviour-only detection
# rather than refusing to start.
lightgbm_model_path = "pirewall/ml/artifacts/lightgbm_model.txt"
isolation_forest_model_path = "pirewall/ml/artifacts/isolation_forest_model.joblib"
feature_schema_version = "1.0.0"

[threat]
low_threshold = 25.0
medium_threshold = 50.0
high_threshold = 75.0
critical_threshold = 90.0
known_attack_weight = 50.0
anomaly_weight = 25.0
behavior_weight = 25.0

[firewall]
# ADDENDUM.md A1 — SHADOW logs what it would enforce and enforces nothing.
# Leave it here until you have watched the control panel and agree with the
# decisions being made, then move to "assisted", then "active".
enforcement_mode = "shadow"
assisted_review_threshold = 75.0
max_adaptive_rules_per_window = 20
rate_window_seconds = 60
default_rule_ttl_seconds = 3600
max_active_rules = 500
min_rule_prefix_length = 24
rate_limit_per_second = 10

# ADDENDUM.md A2 — outranks every adaptive rule unconditionally. Safety
# validation already refuses to block the Admin PC (spec §24); this is the
# second, independent layer. `--set-admin-pc` rewrites this entry with the
# [admin] section below, which is what the marker comment is for.
{_ADMIN_PC_ALLOWLIST_MARKER}
[[firewall.allowlist]]
target = "{answers.admin_pc_ip}/32"
reason = "Admin PC — must never be adaptively blocked (ADDENDUM.md A2)"
created_by = "scripts.deployment.configure"
created_at = "2026-01-01T00:00:00Z"

[api]
# Bound to the Pi's LAN address so the Admin PC can reach it. Access is
# still restricted to admin.admin_pc_ip below.
host = "{discovered.pirewall_lan_ip}"
port = 8443
tls_cert_path = "deploy/certificates/pirewall.crt"
tls_key_path = "deploy/certificates/pirewall.key"
cors_origins = []
history_size = 500
rpc_socket_path = "/run/pirewall/core.sock"

[authentication]
admin_username = "{answers.admin_username}"
# scrypt hash. Rotate with: python -m scripts.deployment.configure --set-password
admin_password_hash = "{answers.admin_password_hash}"
token_expiry_seconds = 3600

[admin]
admin_pc_ip = "{answers.admin_pc_ip}"

[logging]
level = "INFO"
log_dir = "/var/log/pirewall"
max_bytes = 10485760
backup_count = 5

[integration]
# Hosts default to the Admin PC. Flip *_enabled to true once Wazuh and
# Netdata are actually listening there — enabling them earlier just
# produces forwarding-failure warnings.
wazuh_enabled = false
wazuh_host = "{answers.admin_pc_ip}"
wazuh_port = 514
netdata_enabled = false
netdata_host = "{answers.admin_pc_ip}"
netdata_port = 8125

[security]
min_tls_version = "TLSv1.3"
restrict_to_admin_pc = true
session_timeout_seconds = 1800

[failure]
mode = "fail_open"
# Keep in sync with WatchdogSec= in deploy/systemd/pirewall-core.service.
watchdog_sec = 30
crash_loop_restart_count = 3
crash_loop_window_seconds = 300
'''


# --------------------------------------------------------------- file surgery


def replace_scalar(text: str, section: str, key: str, value: str) -> str:
    """Replace one `key = "..."` inside one `[section]`, leaving the rest of the file untouched.

    A targeted edit rather than a regenerate, so `--set-admin-pc` and
    `--set-password` preserve every comment and every hand-tuned threshold
    an operator has since changed. Raises `ConfigurationError` if the
    section or key is missing — silently appending a duplicate key would
    produce a file whose meaning depends on TOML parse order.
    """
    lines = text.splitlines(keepends=True)
    in_section = False
    key_pattern = re.compile(rf"^(\s*){re.escape(key)}(\s*=\s*).*$")
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped == f"[{section}]"
            continue
        if not in_section:
            continue
        match = key_pattern.match(line.rstrip("\n"))
        if match is not None:
            lines[index] = f'{match.group(1)}{key}{match.group(2)}"{value}"\n'
            return "".join(lines)
    raise ConfigurationError(f"could not find `{key}` under `[{section}]` — edit the file by hand")


def replace_admin_pc_allowlist(text: str, admin_pc_ip: ipaddress.IPv4Address) -> str:
    """Retarget the marked Admin PC allowlist entry, if this file has one.

    Returns the text unchanged when the marker is absent: a hand-written
    config need not have that entry, and safety validation protects the
    Admin PC regardless (spec §24). The allowlist entry is the second,
    independent layer — worth keeping in step, not worth failing over.
    """
    if _ADMIN_PC_ALLOWLIST_MARKER not in text:
        return text
    lines = text.splitlines(keepends=True)
    marker_index = next(
        index for index, line in enumerate(lines) if _ADMIN_PC_ALLOWLIST_MARKER in line
    )
    target_pattern = re.compile(r"^(\s*)target(\s*=\s*).*$")
    for index in range(marker_index, min(marker_index + 6, len(lines))):
        match = target_pattern.match(lines[index].rstrip("\n"))
        if match is not None:
            lines[index] = f'{match.group(1)}target{match.group(2)}"{admin_pc_ip}/32"\n'
            return "".join(lines)
    return text


# ------------------------------------------------------------------- workflow


def write_validated(path: Path, text: str) -> None:
    """Validate `text` as a real `PirewallConfig`, then write it atomically.

    Validation happens before the file moves into place, so a bug in this
    script cannot leave a running deployment with a config that
    `pirewall-core` will refuse at its next restart.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(f"{path.name}.new")
    staging.write_text(text, encoding="utf-8")
    try:
        load_config(staging)
    except ConfigurationError:
        staging.unlink(missing_ok=True)
        raise
    staging.replace(path)


def describe(discovered: DiscoveredNetwork) -> str:
    lines = [
        "Detected network layout:",
        f"  WAN interface      {discovered.wan_interface}",
        f"  Upstream gateway   {discovered.upstream_gateway}",
        f"  LAN interface      {discovered.lan_interface}   (capture happens here)",
        f"  Protected network  {discovered.protected_network}",
        f"  This Pi's LAN IP   {discovered.pirewall_lan_ip}",
    ]
    if discovered.admin_pc_candidates:
        seen = ", ".join(str(candidate) for candidate in discovered.admin_pc_candidates)
        lines.append(f"  Hosts seen on LAN  {seen}   (candidates only — you choose)")
    for warning in discovered.warnings:
        lines.append(f"  ! {warning}")
    return "\n".join(lines)


def run_full_setup(path: Path) -> int:
    discovered = discover()
    print(describe(discovered))
    if path.exists() and _prompt(f"\n{path} exists. Overwrite? (yes/no)", "no").lower() not in {
        "y",
        "yes",
    }:
        print("Left unchanged. Use --set-admin-pc or --set-password for targeted edits.")
        return EXIT_OK

    answers = collect_answers(discovered)
    write_validated(path, render_config(discovered, answers))
    print(f"\nWrote {path} (validated).")
    print("\nNext:")
    print(f"  scripts/deployment/make_certs.sh {discovered.pirewall_lan_ip}")
    print(f"  python -m pirewall.main --config {path} --check-config")
    print(f"  python -m pirewall.api  --config {path} --check-config")
    print("\nSee docs/SETUP.md for the rest.")
    return EXIT_OK


def run_set_admin_pc(path: Path, requested: str | None) -> int:
    """Change only `admin.admin_pc_ip`, the matching allowlist entry, and the integration hosts."""
    text = path.read_text(encoding="utf-8")
    if requested is not None:
        admin_pc_ip = ipaddress.IPv4Address(requested)
    else:
        try:
            discovered = discover()
        except DiscoveryError as exc:
            print(f"Could not scan the network ({exc})", file=sys.stderr)
            print("Pass the address directly: --set-admin-pc --admin-pc-ip <address>", file=sys.stderr)
            return EXIT_FAILURE
        print(describe(discovered))
        admin_pc_ip = prompt_admin_pc_ip(discovered)

    current = load_config(path)
    previous = current.admin.admin_pc_ip
    text = replace_scalar(text, "admin", "admin_pc_ip", str(admin_pc_ip))
    text = replace_admin_pc_allowlist(text, admin_pc_ip)

    # Follow the Admin PC only for an integration host that still points at
    # the *old* one — an operator who aimed Wazuh somewhere else meant it.
    # Best-effort per key: a hand-written config may not have the key at
    # all, and that must not fail a change to admin_pc_ip.
    followers = {
        "wazuh_host": current.integration.wazuh_host,
        "netdata_host": current.integration.netdata_host,
    }
    for key, host in followers.items():
        if host != str(previous):
            continue
        try:
            text = replace_scalar(text, "integration", key, str(admin_pc_ip))
        except ConfigurationError:
            print(f"  note: left integration.{key} unchanged (not found in the file)")
    write_validated(path, text)

    print(f"\nAdmin PC changed: {previous} -> {admin_pc_ip}")
    print("Restart pirewall-api for it to take effect:  sudo systemctl restart pirewall-api")
    print(f"The old Admin PC ({previous}) can no longer reach the control panel.")
    return EXIT_OK


def run_set_password(path: Path) -> int:
    text = replace_scalar(
        path.read_text(encoding="utf-8"),
        "authentication",
        "admin_password_hash",
        prompt_password_hash(),
    )
    write_validated(path, text)
    print(f"\nPassword updated in {path}.")
    print("Restart pirewall-api:  sudo systemctl restart pirewall-api")
    print("Existing sessions stay valid until they expire; log out to invalidate yours now.")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pirewall-configure",
        description="Detect this machine's network layout and write config/local_config.toml.",
        epilog="Writes one config file. Never changes network configuration (spec §21).",
    )
    parser.add_argument(
        "--config", type=Path, default=DEFAULT_CONFIG_PATH, help="config file to write or edit"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--detect", action="store_true", help="show what would be detected and exit, writing nothing"
    )
    mode.add_argument(
        "--set-admin-pc", action="store_true", help="change only the Admin PC in an existing config"
    )
    mode.add_argument(
        "--set-password", action="store_true", help="rotate only the admin password hash"
    )
    parser.add_argument(
        "--admin-pc-ip",
        default=None,
        help="with --set-admin-pc, set this address instead of prompting (for scripted use)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path: Path = args.config
    try:
        if args.detect:
            print(describe(discover()))
            return EXIT_OK
        if args.set_admin_pc or args.set_password:
            if not path.is_file():
                print(
                    f"{path} does not exist — run `python -m scripts.deployment.configure` first.",
                    file=sys.stderr,
                )
                return EXIT_FAILURE
            if args.set_admin_pc:
                return run_set_admin_pc(path, args.admin_pc_ip)
            return run_set_password(path)
        return run_full_setup(path)
    except DiscoveryError as exc:
        print(f"Network detection failed: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except ConfigurationError as exc:
        print(f"Refusing to write an invalid config: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except ValueError as exc:
        print(f"Invalid value: {exc}", file=sys.stderr)
        return EXIT_FAILURE
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled; nothing was written.", file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())

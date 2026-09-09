"""Static checks on `scripts/deployment/pirewall-start` (docs/SETUP.md §5-§10).

The script loads nftables rules and manages services on a live box, so the
properties worth pinning are the ones whose absence is silent: a shell that
continues past an error, a ruleset applied without a syntax check first, and
the two ordering constraints that gate the protected network.

These parse the script as text. Running it needs root, a real `nft`, and a
real systemd — that stays Environment-dependent (`docs/PROGRESS.md`).
"""

import re
import stat
from pathlib import Path

import pytest

import pirewall

_REPO_ROOT = Path(pirewall.__file__).resolve().parent.parent
_SCRIPT = _REPO_ROOT / "scripts" / "deployment" / "pirewall-start"


@pytest.fixture(scope="module")
def script() -> str:
    return _SCRIPT.read_text(encoding="utf-8")


def test_the_script_exists_and_is_executable() -> None:
    assert _SCRIPT.is_file(), f"missing {_SCRIPT}"
    assert stat.S_IMODE(_SCRIPT.stat().st_mode) & stat.S_IXUSR, "pirewall-start must be executable"


def test_it_aborts_on_error_and_on_unset_variables(script: str) -> None:
    """Without `set -euo pipefail` a failed step is invisible and the script marches on.

    That matters more here than in most scripts: the steps after a failure
    load firewall rules and start services against whatever half-configured
    state the failure left behind.
    """
    assert re.search(r"^set -euo pipefail$", script, re.M), (
        "pirewall-start must use `set -euo pipefail`"
    )


def test_every_ruleset_is_syntax_checked_before_it_is_loaded(script: str) -> None:
    """`nft -c -f` before `nft -f`, every time.

    Applying a bad ruleset to a live box is how you lose the network you are
    connected over. `nft -c` is the cheap guard and there is no reason to
    ever skip it.
    """
    loads = re.findall(r"run nft -f \"\$(\w+)\"", script)
    assert loads, "expected at least one ruleset load"
    for variable in loads:
        assert re.search(rf'run nft -c -f "\${variable}"', script), (
            f"ruleset ${variable} is loaded without a preceding `nft -c -f` check"
        )


def test_the_portal_gate_is_loaded_after_the_portal_is_serving(script: str) -> None:
    """Ordering constraint, and the one with the worst failure mode.

    `pirewall_portal` rejects forwarding for unauthenticated LAN clients.
    Loading it while the sign-in page is down gates the whole protected
    network with nowhere to sign in.
    """
    body = script[script.index("main() {") :]
    assert body.index("start_portal") < body.index("load_portal_gate"), (
        "load_portal_gate must run after start_portal"
    )


def test_core_starts_before_the_portal(script: str) -> None:
    """pirewall-core is what creates the portal's RPC socket."""
    body = script[script.index("main() {") :]
    assert body.index("start_core_and_api") < body.index("start_portal")


def test_the_ruleset_is_snapshotted_before_anything_is_changed(script: str) -> None:
    """The rollback artifact has to be written before the thing it rolls back."""
    body = script[script.index("main() {") :]
    assert body.index("snapshot_ruleset") < body.index("load_base_ruleset")
    assert body.index("snapshot_ruleset") < body.index("ensure_accounts")


def test_it_refuses_to_run_with_placeholder_credentials(script: str) -> None:
    """A CHANGE_ME hash would otherwise reach a running, listening control panel."""
    assert "CHANGE_ME" in script


def test_it_never_generates_configuration_or_tls_material(script: str) -> None:
    """Both need answers the script cannot invent (spec §29, and configure.py's own contract).

    `configure.py` deliberately refuses to guess the Admin PC address or the
    admin password; a bring-up script that ran it unattended would have to.
    """
    assert not re.search(r"^\s*run .*deployment\.configure", script, re.M)
    assert not re.search(r"^\s*run .*make_certs", script, re.M)


def test_it_asserts_the_portal_privilege_boundary(script: str) -> None:
    """ADDENDUM_3.md C1: pirewall-portal must never be in `pirewall-ipc`.

    That group reaches the socket carrying the kill switch and every rule
    mutation. The script creates these accounts, so it is the right place to
    catch a hand-edited group membership before starting anything.
    """
    assert "pirewall-portal is in pirewall-ipc" in script or "grep -qx pirewall-ipc" in script


def test_dry_run_routes_every_mutation_through_one_helper(script: str) -> None:
    """`--dry-run` is only trustworthy if nothing bypasses it.

    Mutating commands go through `run`, which prints instead of executing.
    A bare `nft -f`/`systemctl restart`/`useradd` outside that helper would
    make a dry run change the system.
    """
    mutators = ("nft -f", "systemctl restart", "systemctl daemon-reload", "useradd", "groupadd")
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "run " in stripped:
            continue
        for mutator in mutators:
            # `$ nft -f ...` inside a here-doc/usage block is documentation.
            if stripped.startswith(mutator):
                pytest.fail(f"mutating command outside the `run` helper: {stripped!r}")


def test_it_does_not_blindly_load_nat_masquerade(script: str) -> None:
    """NetworkManager's shared mode already masquerades the LAN.

    Loading ours on top leaves two masquerade rules where one is wanted, so
    the script detects the existing table — and distinguishes "cannot look"
    from "not there", because treating an unreadable ruleset as absent is how
    the duplicate gets added.
    """
    assert "nm_shared_nat_state" in script
    assert "unknown" in script

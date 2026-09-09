"""Static assertions on `deploy/systemd/*.service` hardening directives (spec §27, Phase 8).

These parse the checked-in unit files as text — they never install, start,
or otherwise touch a real systemd instance (this repository's dev/CI
machines aren't guaranteed to be Linux at all, and even on Linux, applying
these units for real is explicitly out of scope for automated tests, spec
§21/`CLAUDE.md`). Real-hardware verification is documented as
Environment-dependent in `docs/PROGRESS.md`.
"""

from pathlib import Path

import pytest

import pirewall

_REPO_ROOT = Path(pirewall.__file__).resolve().parent.parent
_SYSTEMD_DIR = _REPO_ROOT / "deploy" / "systemd"


def _parse_service(name: str) -> dict[str, list[str]]:
    """Parse `Key=Value` lines from a `.service` file into `{key: [values...]}`.

    A `dict[str, list[str]]` because some directives (`SystemCallFilter=`)
    legitimately appear more than once, each line additive.

    Section-blind on purpose: most assertions here are about a directive
    being present at all. Where the *section* is what matters — systemd
    silently ignores some keys in the wrong one — use `_parse_sections`.
    """
    directives: dict[str, list[str]] = {}
    for section_directives in _parse_sections(name).values():
        for key, values in section_directives.items():
            directives.setdefault(key, []).extend(values)
    return directives


def _parse_sections(name: str) -> dict[str, dict[str, list[str]]]:
    """Parse a `.service` file into `{section: {key: [values...]}}`.

    Needed because systemd does not warn loudly about a directive in the
    wrong section — it logs once and ignores the line — so a misplaced key
    is invisible until the behaviour it was supposed to configure quietly
    fails to happen.
    """
    text = (_SYSTEMD_DIR / name).read_text(encoding="utf-8")
    sections: dict[str, dict[str, list[str]]] = {}
    current = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections.setdefault(current, {})
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        sections.setdefault(current, {}).setdefault(key.strip(), []).append(value.strip())
    return sections


def _first(directives: dict[str, list[str]], key: str) -> str | None:
    values = directives.get(key)
    return values[0] if values else None


class TestPirewallCoreService:
    def setup_method(self) -> None:
        self.directives = _parse_service("pirewall-core.service")

    def test_required_hardening_directives_present(self) -> None:
        d = self.directives
        assert _first(d, "NoNewPrivileges") == "true"
        assert _first(d, "PrivateTmp") == "true"
        assert _first(d, "User") == "pirewall-core"
        assert _first(d, "User") != "root"

    def test_resource_limits_present(self) -> None:
        d = self.directives
        assert "MemoryMax" in d
        assert "TasksMax" in d

    def test_watchdog_configured(self) -> None:
        """ADDENDUM.md A6: Type=notify + a WatchdogSec= value."""
        d = self.directives
        assert _first(d, "Type") == "notify"
        watchdog = _first(d, "WatchdogSec")
        assert watchdog is not None and watchdog != ""

    def test_crash_loop_detection_configured(self) -> None:
        """ADDENDUM.md A6: restart-on-failure with a bounded crash-loop window/burst."""
        d = self.directives
        assert _first(d, "Restart") == "on-failure"
        assert "StartLimitIntervalSec" in d
        assert "StartLimitBurst" in d

    def test_capabilities_scoped_to_capture_and_firewall_only(self) -> None:
        """ADDENDUM.md A4: pirewall-core needs exactly CAP_NET_RAW + CAP_NET_ADMIN, nothing broader."""
        d = self.directives
        bounding = set((_first(d, "CapabilityBoundingSet") or "").split())
        assert bounding == {"CAP_NET_RAW", "CAP_NET_ADMIN"}
        # No capability implying broader privilege (e.g. CAP_SYS_ADMIN) leaked in.
        for cap in bounding:
            assert cap in {"CAP_NET_RAW", "CAP_NET_ADMIN"}

    def test_group_is_shared_ipc_group_for_socket_ownership(self) -> None:
        """The umask/group-ownership approach documented in deploy/systemd/README.md."""
        d = self.directives
        assert _first(d, "Group") == "pirewall-ipc"
        assert _first(d, "UMask") is not None

    def test_the_rpc_socket_directories_are_declared_in_tmpfiles_not_the_unit(self) -> None:
        """ADDENDUM_3.md C1: the two sockets must land in two *different* groups.

        `RuntimeDirectory=` gives every entry the service's primary `Group=`,
        so it cannot express that. The directories, their modes, and the
        setgid bit that gives the portal socket its group are declared in
        `deploy/systemd/pirewall-tmpfiles.conf` instead — and the unit must
        still be able to write into both.
        """
        d = self.directives
        assert "RuntimeDirectory" not in d, (
            "RuntimeDirectory= would force both sockets into pirewall-core's primary group"
        )
        writable = _first(d, "ReadWritePaths") or ""
        assert "/run/pirewall" in writable
        assert "/run/pirewall-portal" in writable
        assert "/var/lib/pirewall" in writable

    def test_core_can_hand_the_portal_socket_to_the_portal_group(self) -> None:
        """It serves both sockets, so it needs membership in both groups."""
        d = self.directives
        assert "pirewall-portal-ipc" in (_first(d, "SupplementaryGroups") or "")


class TestPirewallApiService:
    def setup_method(self) -> None:
        self.directives = _parse_service("pirewall-api.service")

    def test_required_hardening_directives_present(self) -> None:
        d = self.directives
        assert _first(d, "NoNewPrivileges") == "true"
        assert _first(d, "PrivateTmp") == "true"
        assert _first(d, "User") == "pirewall-api"
        assert _first(d, "User") != "root"

    def test_resource_limits_present(self) -> None:
        d = self.directives
        assert "MemoryMax" in d
        assert "TasksMax" in d

    def test_no_raw_socket_or_net_admin_style_capabilities(self) -> None:
        """ADDENDUM.md A4: verify actually absent, not just unused."""
        d = self.directives
        bounding = _first(d, "CapabilityBoundingSet")
        ambient = _first(d, "AmbientCapabilities")
        assert bounding == ""
        assert ambient == ""
        for forbidden in ("CAP_NET_RAW", "CAP_NET_ADMIN", "CAP_SYS_ADMIN", "CAP_NET_BIND_SERVICE"):
            assert forbidden not in (bounding or "")
            assert forbidden not in (ambient or "")

    def test_different_user_from_core_service(self) -> None:
        api_directives = self.directives
        core_directives = _parse_service("pirewall-core.service")
        assert _first(api_directives, "User") != _first(core_directives, "User")

    def test_reaches_shared_ipc_group_only_as_supplementary(self) -> None:
        d = self.directives
        assert _first(d, "Group") != "pirewall-ipc"
        assert "pirewall-ipc" in (_first(d, "SupplementaryGroups") or "")

    def test_does_not_own_runtime_directory(self) -> None:
        """pirewall-core owns /run/pirewall's lifecycle; pirewall-api only reaches into it."""
        d = self.directives
        assert "RuntimeDirectory" not in d


@pytest.mark.parametrize(
    "unit", ["pirewall-core.service", "pirewall-api.service", "pirewall-portal.service"]
)
def test_start_limit_directives_are_in_the_unit_section(unit: str) -> None:
    """`StartLimit*` under `[Service]` is read by nothing (ADDENDUM.md A6).

    Regression test for a real fault in all three unit templates: systemd
    parses `StartLimitIntervalSec=`/`StartLimitBurst=` only in `[Unit]`, and
    logs "Unknown key ... in section [Service], ignoring" for them anywhere
    else. Every unit therefore *looked* like it bounded its own crash loop
    while restarting forever. `systemd-analyze verify` reports it; a
    section-blind text assertion does not, which is why this one is
    section-aware.
    """
    sections = _parse_sections(unit)
    service = sections.get("Service", {})
    unit_section = sections.get("Unit", {})
    for key in ("StartLimitIntervalSec", "StartLimitBurst"):
        assert key not in service, f"{unit}: {key} under [Service] is silently ignored by systemd"
        assert key in unit_section, f"{unit}: {key} must be in [Unit] to take effect"


class TestPirewallPortalService:
    """ADDENDUM_3.md C1: the LAN-facing process is the least privileged of the three."""

    def setup_method(self) -> None:
        self.directives = _parse_service("pirewall-portal.service")

    def test_runs_as_its_own_unprivileged_user(self) -> None:
        d = self.directives
        assert _first(d, "User") == "pirewall-portal"
        assert _first(d, "User") != "root"
        assert _first(d, "NoNewPrivileges") == "true"

    def test_holds_no_capabilities_at_all(self) -> None:
        """Explicitly empty, not merely absent — including no CAP_NET_BIND_SERVICE.

        The portal binds an unprivileged port; port 80 reaches it through the
        nat redirect. A captive portal holding a capability would be the
        widest-exposed process on the box also being the only privileged one.
        """
        d = self.directives
        assert _first(d, "CapabilityBoundingSet") == ""
        assert _first(d, "AmbientCapabilities") == ""

    def test_is_not_in_the_privileged_ipc_group(self) -> None:
        """The whole point of the two-socket split (ADDENDUM_3.md C1).

        `pirewall-ipc` reaches `core.sock`, which carries the kill switch and
        every rule mutation. This process must reach only the portal socket.
        """
        d = self.directives
        groups = set((_first(d, "SupplementaryGroups") or "").split())
        assert groups == {"pirewall-portal-ipc"}
        assert "pirewall-ipc" not in groups
        assert _first(d, "Group") == "pirewall-portal"

    def test_cannot_read_the_user_store(self) -> None:
        """ADDENDUM_3.md C3: pirewall-core is the only reader and writer of the hashes."""
        d = self.directives
        assert "/var/lib/pirewall" in (_first(d, "InaccessiblePaths") or "")
        assert "/var/lib/pirewall" not in (_first(d, "ReadWritePaths") or "")
        assert "/var/lib/pirewall" not in (_first(d, "ReadOnlyPaths") or "")

    def test_has_no_raw_socket_or_netlink_access(self) -> None:
        d = self.directives
        families = set((_first(d, "RestrictAddressFamilies") or "").split())
        assert families == {"AF_UNIX", "AF_INET"}
        assert "AF_PACKET" not in families
        assert "AF_NETLINK" not in families

    def test_resource_limits_are_the_tightest_of_the_three(self) -> None:
        """It renders two small pages; anything near these numbers is abuse."""
        core = _parse_service("pirewall-core.service")
        api = _parse_service("pirewall-api.service")
        portal = self.directives

        def megabytes(directives: dict[str, list[str]]) -> int:
            return int((_first(directives, "MemoryMax") or "0M").rstrip("M"))

        assert megabytes(portal) < megabytes(api) < megabytes(core)


def test_tmpfiles_makes_the_portal_socket_directory_setgid() -> None:
    """The setgid bit is what gives the portal socket its group (ADDENDUM_3.md C1).

    pirewall-core cannot `chown` — its own `SystemCallFilter=~@privileged`
    includes the chown family — so the socket inherits its group from a
    setgid directory instead. Without the leading `2` here, the socket lands
    in `pirewall-ipc` and pirewall-portal can never reach it, which
    `UnixSocketRpcServer` turns into a loud startup failure.
    """
    text = (_SYSTEMD_DIR / "pirewall-tmpfiles.conf").read_text(encoding="utf-8")
    lines = [
        line.split()
        for line in text.splitlines()
        if line.startswith("d ") and "/run/pirewall-portal" in line
    ]
    assert lines, "pirewall-tmpfiles.conf must declare /run/pirewall-portal"
    _type, _path, mode, owner, group = lines[0][:5]
    assert mode == "2750", f"portal socket directory must be setgid 2750, got {mode}"
    assert owner == "pirewall-core"
    assert group == "pirewall-portal-ipc"


def test_tmpfiles_keeps_the_two_socket_directories_in_different_groups() -> None:
    """If both were in one group, reaching one socket would imply reaching the other."""
    text = (_SYSTEMD_DIR / "pirewall-tmpfiles.conf").read_text(encoding="utf-8")
    groups: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("d "):
            continue
        fields = line.split()
        if len(fields) >= 5 and fields[1] in {"/run/pirewall", "/run/pirewall-portal"}:
            groups[fields[1]] = fields[4]
    assert groups["/run/pirewall"] == "pirewall-ipc"
    assert groups["/run/pirewall-portal"] == "pirewall-portal-ipc"
    assert groups["/run/pirewall"] != groups["/run/pirewall-portal"]

"""Static assertions on `deploy/systemd/*.service` hardening directives (spec §27, Phase 8).

These parse the checked-in unit files as text — they never install, start,
or otherwise touch a real systemd instance (this repository's dev/CI
machines aren't guaranteed to be Linux at all, and even on Linux, applying
these units for real is explicitly out of scope for automated tests, spec
§21/`CLAUDE.md`). Real-hardware verification is documented as
Environment-dependent in `docs/PROGRESS.md`.
"""

from pathlib import Path

import pirewall

_REPO_ROOT = Path(pirewall.__file__).resolve().parent.parent
_SYSTEMD_DIR = _REPO_ROOT / "deploy" / "systemd"


def _parse_service(name: str) -> dict[str, list[str]]:
    """Parse `Key=Value` lines from a `.service` file into `{key: [values...]}`.

    A `dict[str, list[str]]` because some directives (`SystemCallFilter=`)
    legitimately appear more than once, each line additive.
    """
    text = (_SYSTEMD_DIR / name).read_text(encoding="utf-8")
    directives: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "[")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        directives.setdefault(key.strip(), []).append(value.strip())
    return directives


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

    def test_runtime_directory_hosts_the_rpc_socket(self) -> None:
        d = self.directives
        assert _first(d, "RuntimeDirectory") == "pirewall"


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

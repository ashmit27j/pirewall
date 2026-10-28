"""Phase 12 access hardening in pirewall-api (PLAN_FINAL §4.9).

Admin login throttle (429 + Retry-After, one event per lockout), allowlist
re-authentication, the admin-session idle timeout (KNOWN_ISSUES.md #17) and
the optional admin-interface address check.
"""

from datetime import UTC, datetime, timedelta

import pytest

from pirewall.api import app as api_app
from pirewall.api.auth import SessionStore, enforce_admin_pc_ip
from pirewall.core.enums import EventSeverity, SecurityEventType
from pirewall.core.exceptions import AuthenticationError
from tests.helpers.api import TestHarness as Harness
from tests.helpers.api import auth_headers, login, make_harness
from tests.helpers.config import TEST_ADMIN_PASSWORD

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _fail_login(harness: Harness) -> int:
    response = harness.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
    return response.status_code


def _auth_failures(harness: Harness) -> list[str]:
    return [
        event.reason or ""
        for event in harness.state.events
        if event.event_type is SecurityEventType.AUTHENTICATION_FAILURE
    ]


# ------------------------------------------------------------ login throttle


def test_admin_login_is_throttled_per_ip_with_retry_after() -> None:
    harness = make_harness(
        NOW,
        authentication={"max_failed_logins_per_ip": 3, "failed_login_window_seconds": 120},
    )
    assert [_fail_login(harness) for _ in range(3)] == [401, 401, 401]

    response = harness.post(
        "/api/v1/auth/login", json={"username": "admin", "password": TEST_ADMIN_PASSWORD}
    )
    assert response.status_code == 429, "a lockout must refuse the right password too"
    retry_after = int(response.headers["retry-after"])
    assert 1 <= retry_after <= 120


def test_admin_global_limit_trips_before_the_per_ip_one() -> None:
    harness = make_harness(
        NOW,
        authentication={"max_failed_logins_per_ip": 10, "max_failed_logins_global": 2},
    )
    assert [_fail_login(harness) for _ in range(2)] == [401, 401]
    assert _fail_login(harness) == 429
    assert any("lockout started (global)" in reason for reason in _auth_failures(harness))


def test_every_lockout_emits_one_event_and_refused_attempts_do_not_flood() -> None:
    harness = make_harness(NOW, authentication={"max_failed_logins_per_ip": 2})
    _fail_login(harness)
    _fail_login(harness)
    for _ in range(5):
        assert _fail_login(harness) == 429

    reasons = _auth_failures(harness)
    assert sum("lockout started (source)" in reason for reason in reasons) == 1
    # Two failed logins plus one lockout; the five refused attempts add nothing.
    assert len(reasons) == 3


def test_a_successful_login_clears_the_per_ip_count() -> None:
    harness = make_harness(NOW, authentication={"max_failed_logins_per_ip": 2})
    _fail_login(harness)
    login(harness)
    _fail_login(harness)
    login(harness)


# ------------------------------------------------- allowlist re-authentication


def _allowlist_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "target": "192.168.1.77/32",
        "reason": "printer",
        "password": TEST_ADMIN_PASSWORD,
    }
    body.update(overrides)
    return body


def test_allowlist_addition_with_the_password_succeeds_and_emits_a_warning() -> None:
    harness = make_harness(NOW)
    token = login(harness)
    response = harness.post("/api/v1/allowlist", json=_allowlist_body(), headers=auth_headers(token))
    assert response.status_code == 200, response.json()
    assert "password" not in response.json()

    warnings = [
        event
        for event in harness.state.events
        if event.event_type is SecurityEventType.FIREWALL_ALLOW and event.subsystem == "api.allowlist"
    ]
    assert len(warnings) == 1
    assert warnings[0].severity is EventSeverity.WARNING
    reason = warnings[0].reason or ""
    assert "192.168.1.77/32" in reason
    assert TEST_ADMIN_PASSWORD not in reason


def test_allowlist_addition_with_a_wrong_password_is_refused_and_counted() -> None:
    harness = make_harness(NOW, authentication={"max_failed_logins_per_ip": 2})
    token = login(harness)
    for _ in range(2):
        response = harness.post(
            "/api/v1/allowlist", json=_allowlist_body(password="wrong"), headers=auth_headers(token)
        )
        assert response.status_code == 403
    assert harness.manager.allowlist == ()

    # The wrong confirmations counted as failed logins: now locked out.
    response = harness.post("/api/v1/allowlist", json=_allowlist_body(), headers=auth_headers(token))
    assert response.status_code == 429
    assert "retry-after" in response.headers


@pytest.mark.parametrize(
    "overrides",
    [
        {"password": None},
        {"reason": None},
        {"reason": "   "},
        {"target": "192.168.1.0/24"},
        {"target": "192.168.1.76/31"},
    ],
    ids=["missing-password", "missing-reason", "blank-reason", "slash-24", "slash-31"],
)
def test_allowlist_addition_rejects_malformed_requests(overrides: dict[str, object]) -> None:
    harness = make_harness(NOW)
    token = login(harness)
    body = {key: value for key, value in _allowlist_body(**overrides).items() if value is not None}
    response = harness.post("/api/v1/allowlist", json=body, headers=auth_headers(token))
    assert response.status_code == 422
    assert harness.manager.allowlist == ()


def test_a_rejected_allowlist_request_never_echoes_the_password() -> None:
    harness = make_harness(NOW)
    token = login(harness)
    response = harness.post(
        "/api/v1/allowlist",
        json=_allowlist_body(target="192.168.1.0/24", reason=""),
        headers=auth_headers(token),
    )
    assert response.status_code == 422
    assert TEST_ADMIN_PASSWORD not in response.text


def test_allowlist_mac_is_validated_and_reaches_core_normalised() -> None:
    """Phase 12 refused a MAC until core could hold one; phase 14 (D3) passes it through."""
    harness = make_harness(NOW)
    token = login(harness)
    multicast = harness.post(
        "/api/v1/allowlist", json=_allowlist_body(mac="01:00:5e:00:00:01"), headers=auth_headers(token)
    )
    assert multicast.status_code == 422
    assert harness.manager.allowlist == ()

    unicast = harness.post(
        "/api/v1/allowlist", json=_allowlist_body(mac="AA-BB-CC-00-11-22"), headers=auth_headers(token)
    )
    assert unicast.status_code == 200
    assert unicast.json()["mac"] == "aa:bb:cc:00:11:22"
    (entry,) = harness.manager.allowlist
    assert entry.mac == "aa:bb:cc:00:11:22"
    assert any("(aa:bb:cc:00:11:22)" in (event.reason or "") for event in harness.state.events)


# ------------------------------------------------------------- idle timeout


def test_an_idle_session_expires_before_its_absolute_lifetime() -> None:
    store = SessionStore(token_expiry_seconds=3600, idle_timeout_seconds=600)
    session = store.create("admin", NOW)
    assert store.validate(session.token, NOW + timedelta(seconds=599)) is not None
    # That request reset the idle clock.
    assert store.validate(session.token, NOW + timedelta(seconds=1100)) is not None
    assert store.validate(session.token, NOW + timedelta(seconds=1700)) is None
    # Gone for good, not merely refused once.
    assert store.validate(session.token, NOW + timedelta(seconds=1701)) is None


def test_the_absolute_lifetime_still_applies_to_an_active_session() -> None:
    store = SessionStore(token_expiry_seconds=1000, idle_timeout_seconds=600)
    session = store.create("admin", NOW)
    for offset in (300, 600, 900):
        assert store.validate(session.token, NOW + timedelta(seconds=offset)) is not None
    assert store.validate(session.token, NOW + timedelta(seconds=1000)) is None


def test_the_api_applies_security_session_timeout_as_the_idle_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = make_harness(NOW, security={"session_timeout_seconds": 60})
    token = login(harness)
    assert harness.get("/api/v1/status", headers=auth_headers(token)).status_code == 200

    later = datetime.now(UTC) + timedelta(seconds=61)

    class _Later(datetime):
        @classmethod
        def now(cls, tz: object = None) -> "_Later":
            return cls.fromtimestamp(later.timestamp(), tz=UTC)

    monkeypatch.setattr(api_app, "datetime", _Later)
    assert harness.get("/api/v1/status", headers=auth_headers(token)).status_code == 401


# ------------------------------------------------- admin-interface address


def test_the_server_address_check_passes_on_the_expected_address() -> None:
    enforce_admin_pc_ip(
        "192.168.1.50",
        "192.168.1.50",
        restrict=True,
        server_host="10.0.0.1",
        expected_server_address="10.0.0.1",
    )


def test_the_server_address_check_refuses_a_request_on_another_address() -> None:
    with pytest.raises(AuthenticationError, match="admin interface"):
        enforce_admin_pc_ip(
            "192.168.1.50",
            "192.168.1.50",
            restrict=True,
            server_host="192.168.100.1",
            expected_server_address="10.0.0.1",
        )


def test_the_server_address_check_is_off_by_default() -> None:
    enforce_admin_pc_ip("192.168.1.50", "192.168.1.50", restrict=True, server_host="anything")


def test_the_local_console_is_not_subject_to_the_server_address_check() -> None:
    enforce_admin_pc_ip(
        "127.0.0.1",
        "192.168.1.50",
        restrict=True,
        allow_local_console=True,
        server_host="127.0.0.1",
        expected_server_address="10.0.0.1",
    )


def test_the_api_applies_the_server_address_check() -> None:
    """The test client's connection arrives on `testserver`, not the configured address."""
    harness = make_harness(NOW, security={"admin_server_address": "10.0.0.1"})
    response = harness.post(
        "/api/v1/auth/login", json={"username": "admin", "password": TEST_ADMIN_PASSWORD}
    )
    assert response.status_code == 403


# ------------------------------------------------------------ api log dir


def test_pirewall_api_logs_into_its_own_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    """KNOWN_ISSUES.md #15: `[api] log_dir`, never core's `logging.log_dir`."""
    from pirewall.api import __main__ as api_main
    from pirewall.config.models import LoggingConfig, PirewallConfig
    from tests.helpers.config import make_config

    config = make_config(api={"log_dir": "/var/log/pirewall-api-test"})
    seen: list[LoggingConfig] = []

    class _Server:
        def run(self) -> None:
            return None

    def _load(_path: object) -> PirewallConfig:
        return config

    def _validate(_config: PirewallConfig) -> None:
        return None

    def _configure(logging_config: LoggingConfig, _component: str) -> None:
        seen.append(logging_config)

    def _build(_config: PirewallConfig) -> _Server:
        return _Server()

    monkeypatch.setattr(api_main, "load_config", _load)
    monkeypatch.setattr(api_main, "validate_runtime_prerequisites", _validate)
    monkeypatch.setattr(api_main, "configure_logging", _configure)
    monkeypatch.setattr(api_main, "build_server", _build)

    assert api_main.main(["--config", "unused.toml"]) == api_main.EXIT_OK
    assert [entry.log_dir for entry in seen] == ["/var/log/pirewall-api-test"]
    assert config.logging.log_dir == "/var/log/pirewall", "core's own setting is left alone"

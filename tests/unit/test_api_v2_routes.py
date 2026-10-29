"""The v2 API routes: guards, panic, offenders, bindings, engine (phase 16, V2_CONTRACTS §9).

Auth is the point: every route needs a session from the Admin PC; a guard
flip to ENFORCE needs the admin password again (422 without it, 403 and a
throttle count when wrong); panic needs the typed confirmation.
"""

from datetime import UTC, datetime

import pytest

from pirewall.core import nft_names
from pirewall.core.enums import GuardMode, GuardName, SecurityEventType
from pirewall.firewall.backend.fake_sets import FakeSetBackend
from tests.helpers.api import TestHarness, auth_headers, login, make_harness
from tests.helpers.config import TEST_ADMIN_PASSWORD

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


@pytest.fixture
def harness() -> TestHarness:
    return make_harness(NOW, v2=True)


def _sets(harness: TestHarness) -> FakeSetBackend:
    assert harness.sets is not None
    return harness.sets


@pytest.mark.parametrize(
    ("method", "url", "body"),
    [
        ("get", "/api/v1/guards", None),
        ("post", "/api/v1/guards/forward", {"mode": "observe"}),
        ("post", "/api/v1/firewall/panic", {"confirm": "panic"}),
        ("get", "/api/v1/offenders", None),
        ("get", "/api/v1/bindings", None),
        ("get", "/api/v1/engine", None),
    ],
)
def test_every_v2_route_needs_a_session(
    harness: TestHarness, method: str, url: str, body: dict[str, str] | None
) -> None:
    response = harness.get(url) if method == "get" else harness.post(url, json=body)

    assert response.status_code == 401
    assert _sets(harness).table_exists(nft_names.INET_FAMILY, nft_names.STATIC_TABLE)


def test_every_v2_route_refuses_a_host_that_is_not_the_admin_pc() -> None:
    harness = make_harness(NOW, v2=True, client_address=("192.168.1.99", 4000))

    assert harness.get("/api/v1/guards").status_code == 403
    assert harness.post("/api/v1/firewall/panic", json={"confirm": "panic"}).status_code == 403


def test_get_guards_reads_the_modes(harness: TestHarness) -> None:
    token = login(harness)

    response = harness.get("/api/v1/guards", headers=auth_headers(token))

    assert response.status_code == 200
    assert response.json()["forward"] == "observe"


def test_switching_to_observe_needs_no_password(harness: TestHarness) -> None:
    token = login(harness)

    response = harness.post("/api/v1/guards/input", json={"mode": "observe"}, headers=auth_headers(token))

    assert response.status_code == 200, response.json()
    assert _sets(harness).guard_mode(GuardName.INPUT) is GuardMode.OBSERVE
    audit = [event for event in harness.state.events if "guard input set to observe" in (event.reason or "")]
    assert audit, "every flip is an audit event"


def test_switching_to_enforce_without_the_password_is_refused(harness: TestHarness) -> None:
    token = login(harness)

    response = harness.post("/api/v1/guards/forward", json={"mode": "enforce"}, headers=auth_headers(token))

    assert response.status_code == 422
    assert _sets(harness).guard_mode(GuardName.FORWARD) is GuardMode.OBSERVE


def test_switching_to_enforce_with_a_wrong_password_is_403_and_a_failed_login(harness: TestHarness) -> None:
    token = login(harness)

    response = harness.post(
        "/api/v1/guards/forward", json={"mode": "enforce", "password": "wrong"}, headers=auth_headers(token)
    )

    assert response.status_code == 403
    assert _sets(harness).guard_mode(GuardName.FORWARD) is GuardMode.OBSERVE
    failures = [e for e in harness.state.events if e.event_type is SecurityEventType.AUTHENTICATION_FAILURE]
    assert any("guard forward -> enforce" in (event.reason or "") for event in failures)


def test_switching_to_enforce_with_the_password_flips_the_guard(harness: TestHarness) -> None:
    token = login(harness)

    response = harness.post(
        "/api/v1/guards/forward",
        json={"mode": "enforce", "password": TEST_ADMIN_PASSWORD},
        headers=auth_headers(token),
    )

    assert response.status_code == 200, response.json()
    assert response.json()["forward"] == "enforce"
    assert _sets(harness).guard_mode(GuardName.FORWARD) is GuardMode.ENFORCE


def test_an_unknown_guard_is_a_422(harness: TestHarness) -> None:
    token = login(harness)

    response = harness.post("/api/v1/guards/sideways", json={"mode": "observe"}, headers=auth_headers(token))

    assert response.status_code == 422


@pytest.mark.parametrize("body", [{}, {"confirm": "yes"}, {"confirm": "PANIC"}, {"confirm": True}])
def test_panic_without_the_typed_confirmation_does_nothing(
    harness: TestHarness, body: dict[str, object]
) -> None:
    token = login(harness)

    response = harness.post("/api/v1/firewall/panic", json=body, headers=auth_headers(token))

    assert response.status_code == 422
    assert _sets(harness).table_exists(nft_names.INET_FAMILY, nft_names.STATIC_TABLE)


def test_panic_deletes_the_v2_tables_and_names_the_restore_command(harness: TestHarness) -> None:
    token = login(harness)

    response = harness.post("/api/v1/firewall/panic", json={"confirm": "panic"}, headers=auth_headers(token))

    assert response.status_code == 200, response.json()
    body = response.json()
    assert body["actor"] == "admin"
    assert "pirewall-start" in body["restore_command"]
    sets = _sets(harness)
    assert not sets.table_exists(nft_names.INET_FAMILY, nft_names.ADAPTIVE_TABLE)
    assert sets.table_exists(nft_names.INET_FAMILY, nft_names.BASE_TABLE)


def test_the_reads_answer_with_a_session(harness: TestHarness) -> None:
    token = login(harness)
    headers = auth_headers(token)

    assert harness.get("/api/v1/offenders", headers=headers).json() == []
    assert harness.get("/api/v1/bindings", headers=headers).json() == []
    # No engine counters were published in this harness: core says so, and
    # the API reports pirewall-core's answer rather than inventing zeros.
    assert harness.get("/api/v1/engine", headers=headers).status_code == 503


def test_the_dashboard_renders_the_v2_panel(harness: TestHarness) -> None:
    token = login(harness)

    page = harness.get("/control-panel", headers=auth_headers(token))

    assert page.status_code == 200
    assert "Kernel guards &amp; identity" in page.text
    assert 'data-guard="forward" data-mode="enforce"' in page.text
    assert 'id="guard-password-forward"' in page.text
    assert "data-panic" in page.text


def test_the_dashboard_still_renders_without_v2() -> None:
    harness = make_harness(NOW)
    token = login(harness)

    page = harness.get("/control-panel", headers=auth_headers(token))

    assert page.status_code == 200
    assert "Guard modes unavailable" in page.text

"""`pirewall.web.render`: every control panel section renders from fixture data (spec §30)."""

from datetime import UTC, datetime
from ipaddress import IPv4Network

from pirewall.core.enums import (
    EnforcementMode,
    EventSeverity,
    FailureMode,
    ModelType,
    RuleStatus,
    SecurityEventType,
    ThreatLevel,
)
from pirewall.core.models.allowlist import AllowlistEntry
from pirewall.core.models.event import SecurityEvent
from pirewall.core.models.model_metadata import ModelMetadata
from pirewall.core.models.status import StatusResult
from pirewall.web.render import render_dashboard, render_login_page
from tests.helpers.rules import make_firewall_rule

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _status() -> StatusResult:
    return StatusResult(
        started_at=NOW,
        uptime_seconds=3600.0,
        enforcement_mode=EnforcementMode.SHADOW,
        failure_mode=FailureMode.FAIL_OPEN,
        active_rule_count=1,
        pending_approval_count=1,
        tracked_flow_count=5,
        lightgbm_loaded=True,
        isolation_forest_loaded=True,
    )


def _threat_assessment():
    from pirewall.core.models.threat import ThreatAssessment

    return ThreatAssessment.model_validate(
        {
            "id": "a1",
            "flow_id": "f1",
            "source_ip": "203.0.113.5",
            "destination_ip": "192.168.1.10",
            "threat_score": 90.0,
            "threat_level": ThreatLevel.CRITICAL,
            "confidence": 0.9,
            "explanation": "test explanation",
            "assessed_at": NOW,
        }
    )


def _model_metadata() -> ModelMetadata:
    return ModelMetadata(
        model_type=ModelType.LIGHTGBM,
        model_version="1.0.0",
        training_dataset="synthetic",
        feature_schema_version="1.0.0",
        feature_ordering=("a",),
        training_timestamp=NOW,
        preprocessing_version="1.0.0",
        is_placeholder=True,
    )


def _event() -> SecurityEvent:
    return SecurityEvent(
        timestamp=NOW,
        severity=EventSeverity.WARNING,
        event_type=SecurityEventType.FIREWALL_BLOCK,
        subsystem="firewall.manager",
        reason="test event",
    )


def _allowlist_entry() -> AllowlistEntry:
    return AllowlistEntry.model_validate(
        {"target": "192.168.1.50/32", "reason": "admin PC", "created_at": NOW, "created_by": "admin"}
    )


def test_dashboard_renders_every_spec_section() -> None:
    html = render_dashboard(
        status=_status(),
        rules=[make_firewall_rule(status=RuleStatus.ACTIVE), make_firewall_rule(status=RuleStatus.SHADOWED)],
        events=[_event()],
        threats=[_threat_assessment()],
        models=[_model_metadata()],
        allowlist=[_allowlist_entry()],
    )

    for heading in ("System", "Threats", "Firewall", "Shadow log", "Allowlist", "Events", "ML"):
        assert heading in html


def test_dashboard_includes_addendum_specific_sections() -> None:
    html = render_dashboard(_status(), [], [], [], [], [])
    assert "Shadow log" in html
    assert "kill-switch" in html.lower()
    assert "Allowlist" in html
    assert "shadow" in html.lower()  # enforcement mode displayed


def test_dashboard_escapes_untrusted_content() -> None:
    malicious_event = SecurityEvent(
        timestamp=NOW,
        severity=EventSeverity.WARNING,
        event_type=SecurityEventType.FIREWALL_ERROR,
        subsystem="test",
        reason="<script>alert('xss')</script>",
    )
    html = render_dashboard(_status(), [], [malicious_event], [], [], [])
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_ids_never_reach_an_inline_js_handler() -> None:
    """Regression test: `html.escape` is not sufficient for JS-string context.

    Rule/allowlist ids used to be interpolated into an inline
    `onclick="pirewallCall('POST', '/api/v1/rules/<id>/disable')"`. The HTML
    parser decodes the escaped `&#x27;` back to `'` before the JS engine
    parses the attribute, so an id containing a quote broke out of the
    string literal and executed — escaping notwithstanding. Ids now travel
    in `data-` attributes (a context `html.escape` genuinely covers).

    Not reachable today, since ids are generated UUIDs; this pins the
    property so it stays true if an id ever becomes operator- or
    evidence-derived.
    """
    hostile_id = "x')+alert(1)+('"
    rules = [
        make_firewall_rule(id=hostile_id, status=RuleStatus.ACTIVE),
        make_firewall_rule(id=hostile_id, status=RuleStatus.PENDING_APPROVAL),
    ]
    allowlist = [
        AllowlistEntry(
            id=hostile_id,
            target=IPv4Network("192.168.1.77/32"),
            reason="test",
            created_at=NOW,
            created_by="admin",
        )
    ]

    html = render_dashboard(_status(), rules, [], [], [], allowlist)

    assert "alert(1)" not in html
    # The decoded form is what the JS engine would have seen.
    assert "&#x27;)+alert" not in html
    assert "onclick=\"pirewallCall(" not in html


def test_action_buttons_still_carry_their_target_url() -> None:
    """The escaping fix must not have silently broken the buttons it protects."""
    html = render_dashboard(
        _status(), [make_firewall_rule(id="abc123", status=RuleStatus.ACTIVE)], [], [], [], []
    )

    assert 'data-action="/api/v1/rules/abc123/disable"' in html
    assert 'data-action="/api/v1/rules/abc123/remove"' in html
    assert 'data-method="POST"' in html


def test_dashboard_handles_empty_state_gracefully() -> None:
    html = render_dashboard(_status(), [], [], [], [], [])
    assert "No rules yet" in html
    assert "No events recorded yet" in html


def test_login_page_renders_without_error() -> None:
    html = render_login_page()
    assert "<form" in html
    assert "username" in html


def test_render_module_cannot_invoke_any_rpc_action() -> None:
    """Structural proof, not just behavioral: `render.py` never even imports the RPC client.

    `render_dashboard`/`render_login_page` take only plain data — there is
    no `BaseRpcClient` reference anywhere in this module for a rendering
    call to invoke a mutating action through, even by accident.
    """
    import inspect

    from pirewall.web import render

    source = inspect.getsource(render)
    assert "ipc" not in source
    assert "RpcClient" not in source

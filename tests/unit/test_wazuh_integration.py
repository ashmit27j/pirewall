"""`pirewall.integration.wazuh` payload shaping (spec §32, Phase 8)."""

from datetime import UTC, datetime

import pytest

from pirewall.core.enums import EventSeverity, FirewallAction, Protocol, SecurityEventType
from pirewall.core.exceptions import IntegrationError
from pirewall.core.models.event import SecurityEvent
from pirewall.integration.fake import FakeWazuhTransport
from pirewall.integration.wazuh import WazuhForwarder, format_event

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _event(**overrides: object) -> SecurityEvent:
    base: dict[str, object] = {
        "timestamp": NOW,
        "severity": EventSeverity.WARNING,
        "event_type": SecurityEventType.FIREWALL_BLOCK,
        "subsystem": "firewall.manager",
        "source": "203.0.113.5",
        "destination": "10.0.0.5",
        "protocol": Protocol.TCP,
        "threat_score": 91.5,
        "decision": FirewallAction.BLOCK,
        "rule_id": "rule-123",
        "reason": "SYN-flood-like behavior",
        "model_version": "1.0.0",
    }
    base.update(overrides)
    return SecurityEvent.model_validate(base)


def test_format_event_includes_every_populated_field() -> None:
    payload = format_event(_event())

    assert payload["source"] == "pirewall"
    assert payload["severity"] == "warning"
    assert payload["event_type"] == "firewall_block"
    assert payload["subsystem"] == "firewall.manager"
    assert payload["source_ip"] == "203.0.113.5"
    assert payload["destination_ip"] == "10.0.0.5"
    assert payload["protocol"] == "tcp"
    assert payload["threat_score"] == 91.5
    assert payload["decision"] == "block"
    assert payload["rule_id"] == "rule-123"
    assert payload["reason"] == "SYN-flood-like behavior"
    assert payload["model_version"] == "1.0.0"
    assert payload["timestamp"] == NOW.isoformat()
    assert "id" in payload


def test_format_event_omits_unset_optional_fields() -> None:
    minimal = SecurityEvent(
        timestamp=NOW,
        severity=EventSeverity.INFO,
        event_type=SecurityEventType.SYSTEM_WARNING,
        subsystem="core",
    )
    payload = format_event(minimal)

    for field in (
        "source_ip",
        "destination_ip",
        "protocol",
        "flow_id",
        "threat_score",
        "decision",
        "rule_id",
        "reason",
        "model_version",
    ):
        assert field not in payload


def test_forwarder_sends_json_when_enabled() -> None:
    transport = FakeWazuhTransport()
    forwarder = WazuhForwarder(transport, enabled=True)

    forwarder.forward(_event())

    assert len(transport.sent_messages) == 1
    assert '"event_type": "firewall_block"' in transport.sent_messages[0]


def test_forwarder_is_noop_when_disabled() -> None:
    transport = FakeWazuhTransport()
    forwarder = WazuhForwarder(transport, enabled=False)

    forwarder.forward(_event())

    assert transport.sent_messages == []


def test_forwarder_propagates_transport_failure() -> None:
    transport = FakeWazuhTransport(fail=True)
    forwarder = WazuhForwarder(transport, enabled=True)

    with pytest.raises(IntegrationError):
        forwarder.forward(_event())

"""`deploy/wazuh/pirewall_decoder.xml` (phase 17): well-formed, and it names only what pirewall emits.

Loading it into a real Wazuh manager is Environment-dependent (see the
file's header); this pins its consistency with `format_event`.
"""

import json
import re
import xml.etree.ElementTree as ElementTree
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from pirewall.core.enums import EventSeverity, FirewallAction, PipelineEngine, SecurityEventType
from pirewall.core.models.event import SecurityEvent
from pirewall.integration.wazuh import format_event

DECODER: Final = Path(__file__).resolve().parents[2] / "deploy" / "wazuh" / "pirewall_decoder.xml"


def _root() -> ElementTree.Element:
    # Wazuh files hold several top-level elements; wrap them to parse.
    return ElementTree.fromstring(f"<root>{DECODER.read_text(encoding='utf-8')}</root>")


def _event() -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime(2026, 10, 29, tzinfo=UTC),
        severity=EventSeverity.CRITICAL,
        event_type=SecurityEventType.POLICY_DECISION,
        subsystem="policy",
        decision=FirewallAction.BLOCK,
        mac="02:00:00:00:00:66",
        engine=PipelineEngine.V2,
        policy_decision_id="d-1",
        evidence_ids=("d1:x",),
        requires_approval=True,
        reason="test",
    )


def test_the_prematch_matches_a_real_line() -> None:
    prematch = _root().find("decoder/prematch")
    assert prematch is not None and prematch.text is not None
    line = json.dumps(format_event(_event()), sort_keys=True)  # exactly what WazuhForwarder sends

    assert re.search(prematch.text, line)


def test_every_field_and_value_a_rule_names_is_one_pirewall_emits() -> None:
    payload_fields = set(format_event(_event())) | {"source_ip", "destination_ip", "rule_id"}
    event_types = {member.value for member in SecurityEventType}
    severities = {member.value for member in EventSeverity}
    decisions = {member.value for member in FirewallAction}
    rule_ids: list[str] = []
    for rule in _root().iter("rule"):
        rule_ids.append(rule.get("id", ""))
        for field in rule.iter("field"):
            name = field.get("name", "")
            assert name in payload_fields, name
            value = (field.text or "").strip("^$")
            allowed = {
                "event_type": event_types,
                "severity": severities,
                "decision": decisions,
                "requires_approval": {"true", "false"},
            }.get(name)
            if allowed is not None:
                assert value in allowed, (name, value)

    assert len(rule_ids) == len(set(rule_ids))
    assert all(100700 <= int(rule_id) < 100800 for rule_id in rule_ids)  # Wazuh's local-rule range

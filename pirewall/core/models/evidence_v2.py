"""Evidence variants for `pipeline.engine = "v2"` (ADDENDUM_4.md D4, docs/V2_CONTRACTS.md).

Contract stubs frozen by phase 11; phase 17 produces and consumes them.
Evidence, never commands (CLAUDE.md): nothing here may be treated as
authorization to touch the firewall. The policy table turns an evidence
bundle into a `PolicyDecision`, which then passes the full validator chain.

Four sources, with fixed ceilings on what they can cause on their own
(enforced by phase 17's policy-matrix tests, stated here so no producer
has to guess):

* `KernelGuardEvidence` (tier K): an `@offenders` element. Observe-mode
  guard => at most MONITOR. Enforce-mode guard => may RATE_LIMIT once
  `sustained_polls >= policy.sustained_polls`.
* `D1Evidence` (deterministic detectors): the only non-kernel tier that may
  act.
* `AnomalyEvidence` (D2, Isolation Forest; the existing v1 model, reused)
  => at most MONITOR, alone or combined with D3.
* `ClassifierEvidence` (D3, LightGBM) => at most MONITOR, alone or combined
  with D2; corroboration only when D1 is also present.
"""

from typing import Annotated
from uuid import uuid4

from pydantic import AwareDatetime, Field, model_validator

from pirewall.core.enums import D1Detector, GuardMode, GuardName
from pirewall.core.models.common import PirewallModel, UnicastMacAddress
from pirewall.core.models.evidence import AnomalyEvidence
from pirewall.core.nft_names import OFFENDER_GUARD, OffenderCode

__all__ = [
    "AnomalyEvidence",
    "ClassifierEvidence",
    "D1Evidence",
    "EvidenceV2",
    "KernelGuardEvidence",
    "evidence_id",
]


def _new_id() -> str:
    return str(uuid4())


class KernelGuardEvidence(PirewallModel):
    """A MAC seen in `@offenders` by the kernel poller (tier K).

    `guard_mode` is the mode of `guard` *when the element was polled*, not
    the mode now: an offender recorded while a guard was observing stays
    observe-mode evidence (MONITOR at most) even if the guard is flipped to
    enforce a second later. `sustained_polls` counts consecutive 1 s polls in
    which the same (code, MAC) element was present.

    Meter-set membership is never evidence (RESULTS.md finding 3); only an
    `@offenders` element produces one of these.
    """

    id: str = Field(default_factory=_new_id, min_length=1)
    code: OffenderCode
    mac: UnicastMacAddress
    guard: GuardName
    guard_mode: GuardMode
    sustained_polls: int = Field(ge=1)
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def _check_guard_matches_code(self) -> "KernelGuardEvidence":
        expected = OFFENDER_GUARD[self.code]
        if self.guard is not expected:
            raise ValueError(f"offender code {self.code.value} is raised by the {expected.value} guard")
        return self


class D1Evidence(PirewallModel):
    """One D1 detector firing for one device over one window.

    `value` is what was measured over `window_seconds` (e.g. distinct
    destination ports in 60 s) and `threshold` the frozen threshold it
    exceeded, both in the detector's own unit. `mac` is None only for the
    aggregate detectors with no single source (global portal auth failures,
    fan-in toward one destination); such evidence cannot target a device on
    its own.
    """

    id: str = Field(default_factory=_new_id, min_length=1)
    detector: D1Detector
    window_seconds: int = Field(gt=0)
    value: float = Field(ge=0.0)
    threshold: float = Field(ge=0.0)
    mac: UnicastMacAddress | None = None
    observed_at: AwareDatetime


class ClassifierEvidence(PirewallModel):
    """D3 (LightGBM, feature schema 3.0.0) output for one flow: supporting evidence only.

    `is_attack` is `attack_probability >= operating_threshold`, where the
    operating point is chosen by benign false-positive rate (PLAN_FINAL
    §4.5). `family` is the coarse family head's label, absent when that
    head is cut or abstains.
    """

    id: str = Field(default_factory=_new_id, min_length=1)
    flow_id: str = Field(min_length=1)
    mac: UnicastMacAddress | None = None
    attack_probability: float = Field(ge=0.0, le=1.0)
    operating_threshold: float = Field(ge=0.0, le=1.0)
    is_attack: bool
    family: str | None = Field(default=None, min_length=1)
    family_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    model_version: str = Field(min_length=1)
    feature_schema_version: str = Field(min_length=1)
    generated_at: AwareDatetime

    @model_validator(mode="after")
    def _check_consistency(self) -> "ClassifierEvidence":
        if self.is_attack != (self.attack_probability >= self.operating_threshold):
            raise ValueError("is_attack must equal attack_probability >= operating_threshold")
        if (self.family is None) != (self.family_probability is None):
            raise ValueError("family and family_probability are set together or not at all")
        return self


EvidenceV2 = Annotated[
    KernelGuardEvidence | D1Evidence | AnomalyEvidence | ClassifierEvidence,
    Field(union_mode="smart"),
]
"""Any v2 evidence item. The variants share no field set, so `extra="forbid"` disambiguates them."""


def evidence_id(evidence: KernelGuardEvidence | D1Evidence | AnomalyEvidence | ClassifierEvidence) -> str:
    """The id a `PolicyDecision.evidence_ids` entry uses for `evidence`.

    The reused v1 `AnomalyEvidence` has no id of its own, so it is named by
    its flow: `anomaly:<flow_id>`.
    """
    if isinstance(evidence, AnomalyEvidence):
        return f"anomaly:{evidence.flow_id}"
    return evidence.id

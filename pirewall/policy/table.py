"""Load and check `policy/table.toml`, the reviewable v2 policy table (ADDENDUM_4.md D4).

The table is data so it can be reviewed, but a typo in it must not be able
to break a D4 ceiling. `load_policy_table` therefore refuses a table that:

* lacks a row for any `EvidenceClass`, or has one twice;
* puts anything but "log" in the SHADOW column (A1);
* lets `ml_only`, `k_observe` or `k_enforce_pending` do more than MONITOR;
* names an unknown action or D1 detector, or a detector in both tiers.
"""

import tomllib
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Final

from pydantic import Field, ValidationError, model_validator

from pirewall.core.enums import D1Detector, EnforcementMode
from pirewall.core.exceptions import ConfigurationError
from pirewall.core.models.common import PirewallModel

__all__ = [
    "MONITOR_CEILING_CLASSES",
    "EvidenceClass",
    "PolicyRow",
    "PolicyTable",
    "TableAction",
    "load_policy_table",
]


class EvidenceClass(StrEnum):
    """The table's row keys: what kind of evidence a device's bundle holds."""

    K_OBSERVE = "k_observe"
    K_ENFORCE_PENDING = "k_enforce_pending"
    K_ENFORCE_SUSTAINED = "k_enforce_sustained"
    D1_HIGH = "d1_high"
    D1_STANDARD = "d1_standard"
    D1_ESCALATED = "d1_escalated"
    ML_ONLY = "ml_only"
    ML_WITH_D1 = "ml_with_d1"


class TableAction(StrEnum):
    """What one cell may say."""

    LOG = "log"
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"
    BLOCK = "block"
    BLOCK_APPROVAL = "block_approval"


MONITOR_CEILING_CLASSES: Final = frozenset(
    {EvidenceClass.ML_ONLY, EvidenceClass.K_OBSERVE, EvidenceClass.K_ENFORCE_PENDING}
)
"""Rows D4 caps at MONITOR whatever the file says."""


class PolicyRow(PirewallModel):
    """One evidence class's actions per enforcement mode."""

    evidence: EvidenceClass
    shadow: tuple[TableAction, ...] = Field(min_length=1)
    assisted: tuple[TableAction, ...] = Field(min_length=1)
    active: tuple[TableAction, ...] = Field(min_length=1)
    escalate: bool = False

    @model_validator(mode="after")
    def _check_cells(self) -> "PolicyRow":
        if self.shadow != (TableAction.LOG,):
            raise ValueError(f'{self.evidence.value}: the SHADOW column is always ["log"] (A1)')
        for column in (self.assisted, self.active):
            if TableAction.LOG in column:
                raise ValueError(f'{self.evidence.value}: "log" belongs to the SHADOW column only')
        if self.evidence in MONITOR_CEILING_CLASSES:
            for column in (self.assisted, self.active):
                if set(column) - {TableAction.MONITOR}:
                    raise ValueError(f"{self.evidence.value}: D4 caps this evidence at MONITOR")
        if TableAction.BLOCK_APPROVAL in self.active:
            raise ValueError(f"{self.evidence.value}: the approval queue is ASSISTED's (A7)")
        return self

    def cell(self, mode: EnforcementMode) -> tuple[TableAction, ...]:
        """The actions for `mode`. SHADOW reads the ACTIVE column: what would happen, recorded SHADOWED."""
        if mode is EnforcementMode.ASSISTED:
            return self.assisted
        return self.active


class PolicyTable(PirewallModel):
    """The whole table: one row per evidence class, and the D1 certainty tiers."""

    version: int = 1
    high: frozenset[D1Detector]
    standard: frozenset[D1Detector]
    rows: Mapping[EvidenceClass, PolicyRow]

    @model_validator(mode="after")
    def _check_complete(self) -> "PolicyTable":
        if self.version != 1:
            raise ValueError(f"unsupported policy table version {self.version}")
        missing = set(EvidenceClass) - set(self.rows)
        if missing:
            raise ValueError(f"policy table lacks rows for {sorted(item.value for item in missing)}")
        if self.high & self.standard:
            raise ValueError("a D1 detector cannot be both high and standard certainty")
        return self


def load_policy_table(path: str | Path) -> PolicyTable:
    """Read and check the table. Raises `ConfigurationError` naming the problem."""
    file_path = Path(path)
    try:
        with file_path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"policy table {file_path} is unreadable: {exc}") from exc
    try:
        rows = [PolicyRow.model_validate(item) for item in raw.get("row", [])]
        by_class = {row.evidence: row for row in rows}
        if len(by_class) != len(rows):
            raise ValueError("policy table has a duplicate row")
        tiers = raw.get("d1", {})
        return PolicyTable(
            version=raw.get("version", 1),
            high=frozenset(D1Detector(item) for item in tiers.get("high", [])),
            standard=frozenset(D1Detector(item) for item in tiers.get("standard", [])),
            rows=by_class,
        )
    except (ValidationError, ValueError) as exc:
        raise ConfigurationError(f"policy table {file_path} is invalid: {exc}") from exc

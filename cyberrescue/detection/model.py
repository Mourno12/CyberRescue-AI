"""Detection result types - frozen, explainable, deterministic.

A rule turns evidence into one of two outputs:

* ``Detection`` - every *required* condition matched and the rule's minimum
  corroboration was met. Only detections may become findings, and a detection
  cannot exist without supporting evidence ids.
* ``Observation`` - something worth showing an analyst that is NOT a finding:
  an indicator observed without malicious context, an uncorroborated vendor
  alert, an allowlisted (suppressed) candidate, or a partial chain. Observations
  are reported, never persisted.

Every result lists every condition its rule declares, matched or not, with the
evidence ids behind it - the explanation is the data, not prose. Identifiers are
content-derived (no clock, no randomness): identical evidence yields identical
results.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyberrescue.core.audit import canonical_json

RULESET_SCHEMA = "cyberrescue.detection/1"
MAX_WINDOW_SECONDS = 24 * 3600
_SEP = "\x1f"

Severity = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
CONFIDENCES: tuple[str, ...] = ("low", "medium", "high")
# Plain descriptive labels (not an ATT&CK mapping).
FindingType = Literal[
    "execution", "persistence", "recovery_inhibition", "credential_access",
    "lateral_movement", "command_and_control", "privilege_escalation", "exfiltration",
    "impact", "beaconing", "multi_stage", "vendor_alert"]
ObservationKind = Literal["indicator_observed", "uncorroborated_alert", "suppressed",
                          "partial_match"]

_RULE_ID_RE = re.compile(r"^[A-Z]+-\d{3}$")
_COND_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,47}$")


def digest(*parts: str) -> str:
    return hashlib.sha256(_SEP.join(parts).encode("utf-8")).hexdigest()


def raise_confidence(base: str, steps: int) -> str:
    """Move ``base`` up ``steps`` levels on low < medium < high (capped)."""
    i = CONFIDENCES.index(base) + max(0, steps)
    return CONFIDENCES[min(i, len(CONFIDENCES) - 1)]


def max_severity(values: list[str]) -> str:
    return max(values, key=SEVERITIES.index)


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --- rule metadata ---------------------------------------------------------------

class Window(_Frozen):
    name: str
    seconds: int

    @field_validator("seconds")
    @classmethod
    def _seconds(cls, v: int) -> int:
        if not 0 < v <= MAX_WINDOW_SECONDS:
            raise ValueError(f"window must be 1..{MAX_WINDOW_SECONDS} seconds")
        return v


class ConditionSpec(_Frozen):
    id: str
    description: str
    role: Literal["required", "corroborating"]

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _COND_ID_RE.match(v):
            raise ValueError("condition id must match ^[a-z][a-z0-9_]{0,47}$")
        return v


class RuleSpec(_Frozen):
    rule_id: str
    version: int
    name: str
    description: str
    finding_type: FindingType
    severity: Severity
    window: Window
    conditions: tuple[ConditionSpec, ...]
    base_confidence: Confidence = "low"
    min_corroboration: int = 0

    @field_validator("rule_id")
    @classmethod
    def _rule_id(cls, v: str) -> str:
        if not _RULE_ID_RE.match(v):
            raise ValueError("rule_id must match ^[A-Z]+-\\d{3}$")
        return v

    @field_validator("version")
    @classmethod
    def _version(cls, v: int) -> int:
        if v < 1:
            raise ValueError("version must be >= 1")
        return v

    @model_validator(mode="after")
    def _conditions(self) -> RuleSpec:
        ids = [c.id for c in self.conditions]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate condition ids")
        if not any(c.role == "required" for c in self.conditions):
            raise ValueError("a rule needs at least one required condition")
        if not 0 <= self.min_corroboration <= len(self.corroborating):
            raise ValueError("min_corroboration exceeds the corroborating conditions")
        return self

    @property
    def required(self) -> tuple[str, ...]:
        return tuple(c.id for c in self.conditions if c.role == "required")

    @property
    def corroborating(self) -> tuple[str, ...]:
        return tuple(c.id for c in self.conditions if c.role == "corroborating")


# --- results ------------------------------------------------------------------

class ConditionResult(_Frozen):
    id: str
    matched: bool
    evidence_ids: tuple[str, ...] = ()
    detail: dict[str, Any] = Field(default_factory=dict)


class WindowSpan(_Frozen):
    name: str
    seconds: int
    start: str
    end: str


class Detection(_Frozen):
    detection_id: str
    detection_key: str
    rule_id: str
    rule_version: int
    ruleset_version: str = ""
    finding_type: FindingType
    severity: Severity
    confidence: Confidence
    confidence_basis: str
    incident_id: str
    primary_host: str | None = None
    entities: dict[str, Any] = Field(default_factory=dict)
    window: WindowSpan
    conditions: tuple[ConditionResult, ...]
    supporting_evidence_ids: tuple[str, ...]
    context_evidence_ids: tuple[str, ...] = ()
    summary: str

    @model_validator(mode="after")
    def _evidence(self) -> Detection:
        if not self.supporting_evidence_ids:
            raise ValueError("a detection needs supporting evidence")
        if set(self.supporting_evidence_ids) & set(self.context_evidence_ids):
            raise ValueError("context evidence must not repeat supporting evidence")
        return self


class Observation(_Frozen):
    observation_id: str
    rule_id: str
    rule_version: int
    ruleset_version: str = ""
    kind: ObservationKind
    incident_id: str
    primary_host: str | None = None
    reason: str
    entities: dict[str, Any] = Field(default_factory=dict)
    conditions: tuple[ConditionResult, ...] = ()
    evidence_ids: tuple[str, ...]


class DetectionReport(_Frozen):
    incident_id: str
    ruleset_version: str
    inputs: dict[str, Any]
    detections: tuple[Detection, ...] = ()
    observations: tuple[Observation, ...] = ()

    def to_json(self) -> str:
        return canonical_json(self.model_dump(mode="json"))

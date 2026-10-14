"""Simulated execution report model - frozen, canonical, simulation-only.

An ``ExecutionReport`` records what a SIMULATED run of a Phase 4 response plan
did. Nothing in it touched a real system: ``simulation`` is the literal True
and the disclaimer is fixed.

Each plan step moves through an explicit state machine - no hidden
transitions; every result carries the full path it took:

    PENDING -> CHECKING -> BLOCKED | UNSUPPORTED            (terminal)
                        -> SIMULATED -> SUCCEEDED | FAILED  (terminal)

* BLOCKED      - an authorization, policy, veto, legal-hold, dependency,
                 integrity or target check failed (``block_category`` says which;
                 Phase 6 adds ``already_executed`` and ``expired``);
* UNSUPPORTED  - no safe simulation exists for the action;
* SUCCEEDED    - simulated, and every success criterion from the plan holds;
* FAILED       - simulated, but at least one success criterion does not hold.

Human decision points (tier-3 actions, protected targets) are never simulated:
they end BLOCKED (``human_decision`` / ``legal_hold``) or UNSUPPORTED.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cyberrescue.core.audit import canonical_json
from cyberrescue.response.model import PolicyPreview, Target, Untrusted

EXECUTION_SCHEMA = "cyberrescue.execution/1"
SIMULATION_DISCLAIMER = (
    "SIMULATION ONLY. No command was run and no host, network, firewall, identity system or "
    "other infrastructure was contacted or changed. Results describe a deterministic "
    "simulation built from the incident's evidence. Only actions the CyberRescue Core had "
    "already authorized were simulated; this report authorizes nothing.")

Status = Literal["PENDING", "CHECKING", "SIMULATED", "SUCCEEDED", "FAILED", "BLOCKED",
                 "UNSUPPORTED"]
TERMINAL = frozenset({"SUCCEEDED", "FAILED", "BLOCKED", "UNSUPPORTED"})
TRANSITIONS: dict[str, frozenset[str]] = {
    "PENDING": frozenset({"CHECKING"}),
    "CHECKING": frozenset({"BLOCKED", "UNSUPPORTED", "SIMULATED"}),
    "SIMULATED": frozenset({"SUCCEEDED", "FAILED"}),
}
BlockCategory = Literal["integrity", "authorization", "policy", "veto", "legal_hold",
                        "target", "dependency", "human_decision",
                        # Phase 6: the authorization was already used / is too old
                        "already_executed", "expired"]

__all__ = ["EXECUTION_SCHEMA", "SIMULATION_DISCLAIMER", "TERMINAL", "TRANSITIONS",
           "AuthorizationView", "CheckResult", "CriterionResult", "DecisionResult",
           "ExecutionReport", "SimEffect", "StepResult", "valid_path"]


def valid_path(path: tuple[str, ...]) -> bool:
    """A complete path: starts PENDING, ends terminal, only allowed transitions."""
    if len(path) < 2 or path[0] != "PENDING" or path[-1] not in TERMINAL:
        return False
    return all(b in TRANSITIONS.get(a, ()) for a, b in zip(path, path[1:]))


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CheckResult(_Frozen):
    """One pre-simulation check (integrity, authorization, policy, target ...)."""
    check: str
    passed: bool
    detail: str


class AuthorizationView(_Frozen):
    """The Core record that authorized the action (read, never created)."""
    request_id: str
    decision_id: str
    decision_event_uid: str
    authorized_event_uid: str
    binding: Literal["plan_step", "asset"]
    requested_by_role: str
    approval_id: str | None = None
    authorized_at: str


class SimEffect(_Frozen):
    """What the simulator did to its simulated environment."""
    applied: bool
    description: str
    evidence_ids: tuple[str, ...] = ()


class CriterionResult(_Frozen):
    check: str
    expected: str                    # the plan's success-criterion description
    satisfied: bool
    observed: str
    evidence_ids: tuple[str, ...] = ()


class StepResult(_Frozen):
    step_id: str
    order: int
    action: str
    tier: int
    target: Target
    params: dict[str, Untrusted] = Field(default_factory=dict)
    status: Status
    path: tuple[str, ...]
    block_category: BlockCategory | None = None
    reason: str
    checks: tuple[CheckResult, ...] = ()
    authorization: AuthorizationView | None = None
    current_policy: PolicyPreview | None = None
    effect: SimEffect | None = None
    criteria: tuple[CriterionResult, ...] = ()
    evidence_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _consistent(self) -> StepResult:
        if not valid_path(self.path) or self.path[-1] != self.status:
            raise ValueError(f"invalid state path {self.path} for status {self.status}")
        if (self.status == "BLOCKED") != (self.block_category is not None):
            raise ValueError("block_category is set exactly when the step is BLOCKED")
        simulated = "SIMULATED" in self.path
        if simulated and (self.authorization is None or self.effect is None):
            raise ValueError("a simulated step needs its Core authorization and an effect")
        if self.status == "SUCCEEDED" and not (self.criteria and
                                               all(c.satisfied for c in self.criteria)):
            raise ValueError("SUCCEEDED requires every success criterion to hold")
        if self.status == "FAILED" and all(c.satisfied for c in self.criteria) \
                and self.effect is not None and self.effect.applied:
            raise ValueError("FAILED requires an unmet criterion or an unapplied effect")
        if not simulated and (self.effect is not None or self.criteria):
            raise ValueError("only simulated steps carry effects and criteria")
        return self


class DecisionResult(_Frozen):
    decision_id: str
    action: str
    tier: int
    target: Target
    status: Literal["BLOCKED", "UNSUPPORTED"]
    path: tuple[str, ...]
    block_category: Literal["human_decision", "legal_hold"] | None = None
    reason: str
    authorization: AuthorizationView | None = None
    current_policy: PolicyPreview

    @model_validator(mode="after")
    def _consistent(self) -> DecisionResult:
        if not valid_path(self.path) or self.path[-1] != self.status or \
                "SIMULATED" in self.path:
            raise ValueError("decision points are never simulated")
        if (self.status == "BLOCKED") != (self.block_category is not None):
            raise ValueError("block_category is set exactly when BLOCKED")
        return self


class ExecutionReport(_Frozen):
    execution_schema: Literal["cyberrescue.execution/1"] = EXECUTION_SCHEMA
    simulation: Literal[True] = True
    disclaimer: Literal[SIMULATION_DISCLAIMER] = SIMULATION_DISCLAIMER
    run_id: str
    incident_id: str
    plan_id: str
    plan_sha256: str
    plan_integrity: tuple[CheckResult, ...]
    as_of: str
    state: dict[str, Any] = Field(default_factory=dict)
    steps: tuple[StepResult, ...] = ()
    decisions: tuple[DecisionResult, ...] = ()
    summary: dict[str, int] = Field(default_factory=dict)
    report_sha256: str = ""

    def content(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"report_sha256"})

    def to_json(self) -> str:
        return canonical_json(self.model_dump(mode="json"))

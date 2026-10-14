"""Response plan model - frozen, canonical, proposal-only.

A ``ResponsePlan`` is ADVICE. Nothing in it can authorize anything:

* ``PlanStep`` - a proposed catalogue action of tier 1 or 2 (never destructive,
  never tier 3; the validators refuse anything else).
* ``DecisionPoint`` - something only a human may decide: every tier-3 action,
  and tier-2 actions on protected targets. Shown with the policy requirements,
  never as a step.
* ``Task`` - an investigative open question (from a Phase 3 gap); not an action.
* ``PlanNote`` - a stated limitation (e.g. no catalogue action exists).

Every policy result is a ``PolicyPreview``: ``kind`` is always
``"policy_preview"`` and ``authorizes`` is the literal ``False``. The real
decision is made by the Core (``request_action`` / the Commander gate) at
request time, on the state at that time.

Free text derived from evidence is ``Untrusted`` (shared with the Phase 3 case
model); every other string is a plan constant, a template filled with safe
identifiers, or a Core identifier.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cyberrescue.core.audit import canonical_json
from cyberrescue.core.catalog import get_action
from cyberrescue.core.models import ActionTier
from cyberrescue.investigation.model import Untrusted, untrusted

PLAN_SCHEMA = "cyberrescue.response-plan/1"

PREVIEW_NOTE = ("Policy preview only - not a decision and not an authorization. It shows "
                "what the policy engine would answer if the Commander requested this action "
                "on the state as of the plan; the real decision is made by the Core at "
                "request time.")
DISCLAIMER = ("This response plan is advisory. It proposes actions; it does not request, "
              "approve, authorize or execute anything. Every action still goes through the "
              "Core: request, policy decision, human approval where required, Commander.")

__all__ = ["DISCLAIMER", "PLAN_SCHEMA", "PREVIEW_NOTE", "AttackRef", "DecisionPoint",
           "PlanNote", "PlanStep", "PolicyPreview", "PreviewRule", "ResponsePlan",
           "SuccessCriterion", "Target", "Task", "Untrusted", "untrusted"]


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AttackRef(_Frozen):
    """A MITRE ATT&CK label for the rule that triggered a step (static table,
    rule-level - a label for the analyst, not an inference)."""
    tactic_id: str
    tactic: str
    technique_id: str | None = None
    technique: str | None = None


class PreviewRule(_Frozen):
    rule: str
    effect: str                      # deny | require_approval | require_signoff
    satisfied: bool
    reason: Untrusted                # may quote veto/approval text written by others


class PolicyPreview(_Frozen):
    kind: Literal["policy_preview"] = "policy_preview"
    authorizes: Literal[False] = False
    as_of: str
    hypothetical_requester: Literal["agent/commander"] = "agent/commander"
    # The asset id the engine evaluated. The Core stores action targets as asset
    # ids (a foreign key to the inventory), so ip/account targets can only be
    # requested - and are previewed - with no asset id.
    evaluated_asset_id: str | None = None
    outcome_if_requested: Literal["ALLOW", "REQUIRE_APPROVAL", "DENY"]
    unmet_rules: tuple[str, ...] = ()
    rule_results: tuple[PreviewRule, ...] = ()
    policy_version: str
    snapshot_hash: str
    note: Literal[PREVIEW_NOTE] = PREVIEW_NOTE


class Target(_Frozen):
    kind: Literal["host", "ip", "account", "none"]
    value: str | None = None
    # inventory: an asset the Core knows; evidence: a value read from evidence and
    # validated by targets.py; plan: a plan constant (e.g. a stakeholder group).
    source: Literal["inventory", "evidence", "plan"]
    checks: tuple[str, ...] = ()     # validation checks the value passed


class SuccessCriterion(_Frozen):
    """What a later verification phase would check to confirm the action worked.
    Stated, never evaluated here."""
    check: Literal["no_network_activity_from_host", "image_recorded",
                   "no_process_activity", "file_absent", "no_connection_to_indicator",
                   "no_successful_logon_by_account", "notification_recorded"]
    description: str
    subject: str | None = None


class PlanStep(_Frozen):
    step_id: str
    order: int
    phase: Literal["notify", "contain", "preserve", "eradicate"]
    action: str
    tier: int
    reversible: bool
    target: Target
    params: dict[str, Untrusted] = Field(default_factory=dict)
    recipients: tuple[str, ...] = ()
    after: tuple[str, ...] = ()
    rationale: str
    trigger_rules: tuple[str, ...]
    detection_ids: tuple[str, ...]
    finding_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...]
    attack: tuple[AttackRef, ...] = ()
    success_criteria: tuple[SuccessCriterion, ...] = ()
    cautions: tuple[str, ...] = ()
    preview: PolicyPreview

    @model_validator(mode="after")
    def _proposal_only(self) -> PlanStep:
        spec = get_action(self.action)
        if spec is None:
            raise ValueError(f"{self.action!r} is not a catalogue action")
        if spec.tier not in (ActionTier.LOW, ActionTier.CONTAINMENT) or spec.destructive:
            raise ValueError(f"{self.action} is tier {int(spec.tier)}; only tier-1/2, "
                             "non-destructive actions may be plan steps")
        if self.tier != int(spec.tier) or self.reversible != spec.reversible:
            raise ValueError(f"{self.action}: tier/reversibility differ from the catalogue")
        if not self.evidence_ids:
            raise ValueError("a plan step must cite evidence")
        if self.step_id in self.after:
            raise ValueError("a step cannot depend on itself")
        return self


class DecisionPoint(_Frozen):
    decision_id: str
    action: str
    tier: int
    reason_code: Literal["tier3", "protected_target"]
    target: Target
    question: str
    rationale: str
    regulations: tuple[str, ...] = ()
    prerequisites: tuple[str, ...] = ()      # step ids that should come first
    trigger_rules: tuple[str, ...]
    detection_ids: tuple[str, ...]
    finding_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...]
    attack: tuple[AttackRef, ...] = ()
    preview: PolicyPreview

    @model_validator(mode="after")
    def _cited(self) -> DecisionPoint:
        spec = get_action(self.action)
        if spec is None:
            raise ValueError(f"{self.action!r} is not a catalogue action")
        if self.tier != int(spec.tier):
            raise ValueError(f"{self.action}: tier differs from the catalogue")
        if not self.evidence_ids:
            raise ValueError("a decision point must cite evidence")
        return self


class Task(_Frozen):
    task_id: str
    gap_code: Literal["G1", "G2", "G3", "G4", "G5", "G6"]
    host: str | None = None
    title: str
    description: str
    evidence_ids: tuple[str, ...] = ()
    refs: tuple[str, ...] = ()


class PlanNote(_Frozen):
    code: str
    description: str
    refs: tuple[str, ...] = ()


class ResponsePlan(_Frozen):
    plan_schema: Literal["cyberrescue.response-plan/1"] = PLAN_SCHEMA
    plan_id: str
    incident_id: str
    aliases: tuple[str, ...]
    as_of: str
    case_id: str
    case_sha256: str
    ruleset_version: str
    playbook_version: str
    attack_map_version: str
    policy_version: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    disclaimer: Literal[DISCLAIMER] = DISCLAIMER
    steps: tuple[PlanStep, ...] = ()
    decision_points: tuple[DecisionPoint, ...] = ()
    tasks: tuple[Task, ...] = ()
    notes: tuple[PlanNote, ...] = ()
    plan_sha256: str = ""

    @model_validator(mode="after")
    def _consistent(self) -> ResponsePlan:
        ids = [s.step_id for s in self.steps]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate step ids")
        known = set(ids)
        for s in self.steps:
            if set(s.after) - known:
                raise ValueError(f"{s.step_id} depends on unknown steps")
        for d in self.decision_points:
            if set(d.prerequisites) - known:
                raise ValueError(f"{d.decision_id} has unknown prerequisites")
        return self

    def content(self) -> dict[str, Any]:
        """Everything except the self-hash."""
        return self.model_dump(mode="json", exclude={"plan_sha256"})

    def to_json(self) -> str:
        return canonical_json(self.model_dump(mode="json"))

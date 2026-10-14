"""Record a simulated run in the Core - the ONLY writer in ``cyberrescue.execution``.

``record_plan`` (used by ``simulate --record``):

1. simulates the plan on a READ-ONLY connection, exactly like a dry run;
2. opens the Core and, for every step that run SIMULATED (SUCCEEDED or
   FAILED), calls ``CoreService.record_simulated_execution`` - the single Core
   method that records executions, which re-checks everything itself
   (executor actor, authorization, incident, target, plan step, age, evidence,
   current policy, replay) and writes ACTION_EXECUTED / ACTION_VERIFIED and the
   append-only execution record, mode ``simulated``.

Blocked, unsupported and decision-point items are never recorded. Each step
is its own Core transaction: a refusal (e.g. the authorization expired by the
Core's clock) is reported and the other steps are unaffected. A second
``--record`` run finds every recorded step ``already_executed`` and records
nothing - recording is idempotent.

Nothing here executes anything; there is no real-execution mode to choose.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from cyberrescue.core.audit import canonical_json
from cyberrescue.core.service import CoreService, ExecutionError
from cyberrescue.execution.executor import parse_plan, simulate_plan
from cyberrescue.execution.model import ExecutionReport
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.model import PlanStep
from cyberrescue.response.targets import ProtectedAccounts

# What identifies a step independently of policy state (the preview changes as
# approvals arrive; the step itself must not).
STEP_HASH_FIELDS = frozenset({"step_id", "order", "phase", "action", "tier", "reversible",
                              "target", "params", "recipients", "after", "trigger_rules",
                              "detection_ids", "evidence_ids", "success_criteria"})


def step_sha256(step: PlanStep) -> str:
    return hashlib.sha256(canonical_json(
        step.model_dump(mode="json", include=set(STEP_HASH_FIELDS))).encode()).hexdigest()


@dataclass
class RecordOutcome:
    step_id: str
    recorded: bool
    record_id: str | None = None
    reason: str = ""


@dataclass
class RecordResult:
    report: ExecutionReport
    outcomes: list[RecordOutcome] = field(default_factory=list)

    @property
    def recorded(self) -> list[RecordOutcome]:
        return [o for o in self.outcomes if o.recorded]

    @property
    def refused(self) -> list[RecordOutcome]:
        return [o for o in self.outcomes if not o.recorded]


def record_plan(db_path: str | Path | None, plan_json: str, *, recorder_actor_id: str,
                protected: ProtectedAccounts | None = None) -> RecordResult:
    with open_readonly(db_path) as ro:
        report = simulate_plan(ro, plan_json, protected=protected)
    plan = parse_plan(plan_json)
    steps = {s.step_id: s for s in plan.steps}
    result = RecordResult(report=report)
    simulated = [r for r in report.steps if "SIMULATED" in r.path]
    if not simulated:
        return result
    svc = CoreService.open(db_path)
    try:
        for r in simulated:
            step = steps[r.step_id]
            try:
                rec = svc.record_simulated_execution(
                    report.incident_id, request_id=r.authorization.request_id,
                    recorder_actor_id=recorder_actor_id, action=step.action,
                    asset_id=step.target.value if step.target.kind == "host" else None,
                    plan_id=plan.plan_id, plan_sha256=plan.plan_sha256, step_id=step.step_id,
                    step_sha256=step_sha256(step), report_sha256=report.report_sha256,
                    evidence_fingerprint=plan.inputs.get("evidence_fingerprint", ""),
                    environment_sha256=report.state["environment_sha256"],
                    outcome=r.status.lower(),
                    criteria=[{"check": c.check, "satisfied": c.satisfied}
                              for c in r.criteria] or
                    [{"check": "effect_applied", "satisfied": False}],
                    source="simulated_executor")
                result.outcomes.append(RecordOutcome(r.step_id, True, rec.id))
            except (ExecutionError, PermissionError) as e:
                result.outcomes.append(RecordOutcome(r.step_id, False, reason=str(e)))
    finally:
        svc.conn.close()
    return result

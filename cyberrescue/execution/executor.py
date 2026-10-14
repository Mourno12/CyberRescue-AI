"""Simulate a Phase 4 response plan - read-only, deterministic, simulation only.

``simulate_plan(core, plan_json)``:

1. **Plan integrity.** The document parses as a ``ResponsePlan`` (no extra
   fields - a forged ``"approved": true`` is rejected), its ``plan_sha256``
   matches its content, the protected-accounts list is the one it used, and
   the database still supports it: same evidence fingerprint and rule /
   playbook / ATT&CK versions, and audit chain and evidence verify. Policy
   state may have changed since the plan was made (that is how approvals
   arrive), so the plan is compared item by item with a plan rebuilt now.
2. **Each step**, in plan order, ``PENDING -> CHECKING`` and then, stopping at
   the first failure:
   * integrity  - the rebuilt plan has this exact step (action, target,
                  parameters, citations, criteria); the catalogue agrees it is
                  a tier-1/2, non-destructive action;
   * target     - re-validated now (inventory, address, protected accounts);
   * dependency - every step it comes ``after`` SUCCEEDED in this run, or has a
                  succeeded Core execution record for this plan (Phase 6);
   * support    - a simulated handler exists (else UNSUPPORTED);
   * authorization - the Core already authorized it (``authorization.py``);
   * policy     - no current DENY and no unconsidered veto;
   then ``SIMULATED`` on the in-memory environment, and ``SUCCEEDED`` only if
   the effect applied and every success criterion of the plan holds, else
   ``FAILED``.
3. **Decision points** are never simulated: BLOCKED (``legal_hold`` when an
   active hold is among the unmet rules, else ``human_decision``), or
   UNSUPPORTED if the Core has authorized such an action (tier-3 simulation is
   out of scope).

Nothing is written anywhere. No wall clock: ``as_of`` is the incident's last
audit event. The same database and plan always give a byte-identical report,
so repeated runs are idempotent by construction.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field

from cyberrescue.core.audit import canonical_json
from cyberrescue.core.catalog import get_action
from cyberrescue.core.models import ActionTier
from cyberrescue.detection.engine import load_view
from cyberrescue.detection.model import digest
from cyberrescue.core.policy import PolicyConfig
from cyberrescue.execution.authorization import core_authorizations, recheck, select_authorization
from cyberrescue.execution.environment import SimEnvironment
from cyberrescue.execution.handlers import HANDLERS, evaluate_criteria
from cyberrescue.execution.model import CheckResult, DecisionResult, ExecutionReport, StepResult
from cyberrescue.investigation.readonly import ReadOnlyCore
from cyberrescue.response.model import PlanStep, ResponsePlan
from cyberrescue.response.planner import build_plan
from cyberrescue.response.preview import Previewer, readonly_snapshot
from cyberrescue.response.targets import (
    ProtectedAccounts,
    check_account,
    check_host,
    check_ip,
    load_protected_accounts,
)

_STEP_FIELDS = ("action", "tier", "reversible", "phase", "target", "params", "recipients",
                "after", "trigger_rules", "detection_ids", "evidence_ids", "success_criteria")


def _plan_sha(plan: ResponsePlan) -> str:
    return hashlib.sha256(canonical_json(plan.content()).encode()).hexdigest()


def _report_sha(report: ExecutionReport) -> str:
    return hashlib.sha256(canonical_json(report.content()).encode()).hexdigest()


def parse_plan(plan_json: str) -> ResponsePlan:
    try:
        return ResponsePlan.model_validate(json.loads(plan_json))
    except ValueError as e:
        raise ValueError(f"not a valid response plan: {str(e)[:200]}") from None


def _same_step(a: PlanStep, b: PlanStep) -> bool:
    return a.model_dump(mode="json", include=set(_STEP_FIELDS)) == \
        b.model_dump(mode="json", include=set(_STEP_FIELDS))


def _plan_checks(core, plan: ResponsePlan, fresh: ResponsePlan, iid: str,
                 protected: ProtectedAccounts) -> list[CheckResult]:
    audit, evidence = core.audit.verify(iid), core.evidence.verify(iid)
    pairs = [
        ("plan_hash", _plan_sha(plan) == plan.plan_sha256,
         "plan_sha256 matches the document" if _plan_sha(plan) == plan.plan_sha256
         else "plan_sha256 does not match the document (edited plan)"),
        ("protected_accounts", plan.inputs.get("protected_accounts_sha256") == protected.sha256,
         "the protected-accounts list is the one the plan used"),
        ("evidence_unchanged", plan.inputs.get("evidence_fingerprint")
         == fresh.inputs.get("evidence_fingerprint"), "the incident's evidence is unchanged"),
        ("versions", (plan.ruleset_version, plan.playbook_version, plan.attack_map_version)
         == (fresh.ruleset_version, fresh.playbook_version, fresh.attack_map_version),
         "detection rules, playbook and ATT&CK map are the plan's versions"),
        ("audit_chain", audit.ok, "the incident's audit chain verifies"),
        ("evidence_integrity", evidence.ok, "the incident's evidence verifies"),
    ]
    return [CheckResult(check=c, passed=ok, detail=d) for c, ok, d in pairs]


@dataclass
class _Run:
    core: ReadOnlyCore
    plan: ResponsePlan
    fresh: dict[str, PlanStep]
    plan_ok: bool
    view: object
    env: SimEnvironment
    previewer: Previewer
    protected: ProtectedAccounts
    records: list
    as_of: str = ""
    max_age_minutes: int = 60
    # Phase 6: steps with a SUCCEEDED Core execution record satisfy dependants.
    recorded_ok: frozenset[str] = frozenset()
    used: set[str] = field(default_factory=set)
    status: dict[str, str] = field(default_factory=dict)

    def _target(self, step: PlanStep):
        t = step.target
        if t.kind == "host":
            return check_host(t.value, self.view.assets)
        if t.kind == "ip":
            return check_ip(t.value, self.view)
        if t.kind == "account":
            return check_account(t.value, self.protected)
        return None

    def step(self, step: PlanStep) -> StepResult:
        checks: list[CheckResult] = []
        base = {"step_id": step.step_id, "order": step.order, "action": step.action,
                "tier": step.tier, "target": step.target, "params": step.params,
                "evidence_ids": step.evidence_ids}

        def stop(status, category, reason, **extra) -> StepResult:
            self.status[step.step_id] = status
            return StepResult(**base, status=status, path=("PENDING", "CHECKING", status),
                              block_category=category, reason=reason, checks=tuple(checks),
                              **extra)

        def check(name, ok, detail) -> bool:
            checks.append(CheckResult(check=name, passed=ok, detail=detail))
            return ok

        spec = get_action(step.action)
        fresh = self.fresh.get(step.step_id)
        if not check("plan_integrity", self.plan_ok, "the plan document and the database "
                     "agree" if self.plan_ok else "plan-level integrity checks failed"):
            return stop("BLOCKED", "integrity", "the plan failed its integrity checks")
        if not check("step_supported_by_database", fresh is not None and _same_step(step, fresh),
                     "the database still produces this exact step"):
            return stop("BLOCKED", "integrity", "the database no longer produces this step "
                        "unchanged")
        if not check("catalogue_tier", spec is not None and int(spec.tier) == step.tier
                     and spec.tier in (ActionTier.LOW, ActionTier.CONTAINMENT)
                     and not spec.destructive, "a tier-1/2, non-destructive catalogue action"):
            return stop("BLOCKED", "integrity", "the step's action is not a tier-1/2 "
                        "non-destructive catalogue action")
        tc = self._target(step)
        if not check("target", tc is None or tc.ok,
                     "target re-validated" if tc is None or tc.ok else tc.reason):
            return stop("BLOCKED", "target", f"target refused: {tc.reason}")
        pending = [a for a in step.after if self.status.get(a) != "SUCCEEDED"
                   and a not in self.recorded_ok]
        if not check("dependencies", not pending, "every prerequisite step succeeded"
                     if not pending else f"{len(pending)} prerequisite step(s) did not succeed"):
            return stop("BLOCKED", "dependency", "a prerequisite step did not succeed in this "
                        "run: " + ", ".join(pending))
        handler = HANDLERS.get(step.action)
        if not check("simulator", handler is not None, "a simulated handler exists"
                     if handler else "no safe simulation exists for this action"):
            return stop("UNSUPPORTED", None, "no safe simulation exists for this action")
        auth, why, category = select_authorization(
            self.records, step.step_id, step.action, step.target, self.used,
            as_of=self.as_of, max_age_minutes=self.max_age_minutes)
        preview = self.previewer.preview(step.action, step.target.value, kind=step.target.kind)
        if not check("core_authorization", auth is not None, why):
            needs = f" (policy now: {preview.outcome_if_requested}" + \
                (f" [{', '.join(preview.unmet_rules)}])" if preview.unmet_rules else ")")
            return stop("BLOCKED", category, why + needs, current_policy=preview)
        auth_rules = next(a.decision_rules for a in self.records
                          if a.request_id == auth.request_id)
        category, reason, preview = recheck(self.previewer, step.action, step.target,
                                            auth_rules)
        if not check("current_policy", category is None, reason):
            return stop("BLOCKED", category, reason, authorization=auth,
                        current_policy=preview)

        self.env, effect = handler(self.env, step)
        criteria = evaluate_criteria(self.env, step)
        ok = effect.applied and bool(criteria) and all(c.satisfied for c in criteria)
        status = "SUCCEEDED" if ok else "FAILED"
        self.status[step.step_id] = status
        reason = "simulated; every success criterion holds" if ok else (
            "simulated, but the effect could not be applied" if not effect.applied
            else "simulated, but a success criterion does not hold")
        return StepResult(**base, status=status, path=("PENDING", "CHECKING", "SIMULATED",
                                                       status),
                          reason=reason, checks=tuple(checks), authorization=auth,
                          current_policy=preview, effect=effect, criteria=criteria)

    def decision(self, d) -> DecisionResult:
        preview = self.previewer.preview(d.action, d.target.value, kind=d.target.kind)
        asset = d.target.value if d.target.kind == "host" else None
        authorized = [a for a in self.records if a.action == d.action and a.asset_id == asset
                      and a.plan_step in (None, d.decision_id)]
        path = ("PENDING", "CHECKING")
        if authorized:
            return DecisionResult(
                decision_id=d.decision_id, action=d.action, tier=d.tier, target=d.target,
                status="UNSUPPORTED", path=(*path, "UNSUPPORTED"), current_policy=preview,
                reason="the Core has authorized this action, but decision points (tier-3 "
                       "and protected targets) are not simulated in this phase")
        held = "P8" in preview.unmet_rules
        return DecisionResult(
            decision_id=d.decision_id, action=d.action, tier=d.tier, target=d.target,
            status="BLOCKED", path=(*path, "BLOCKED"),
            block_category="legal_hold" if held else "human_decision",
            current_policy=preview,
            reason=("an active legal hold blocks this action; only a human approval that "
                    "overrides the hold, then a Core authorization, could change that"
                    if held else "a human decision point: not authorized by the Core, and "
                                 "never simulated"))


def simulate_plan(core: ReadOnlyCore, plan_json: str, *,
                  protected: ProtectedAccounts | None = None) -> ExecutionReport:
    plan = parse_plan(plan_json)
    iid = core.resolve(plan.incident_id)
    protected = protected or load_protected_accounts()
    fresh = build_plan(core, iid, protected=protected)
    plan_checks = _plan_checks(core, plan, fresh, iid, protected)
    view = load_view(core, iid)
    env = SimEnvironment.from_view(view, [a.asset_id for a in core.store.list_assets()])
    run = _Run(core=core, plan=plan, fresh={s.step_id: s for s in fresh.steps},
               plan_ok=all(c.passed for c in plan_checks), view=view, env=env,
               previewer=Previewer(readonly_snapshot(core, iid, fresh.as_of), as_of=fresh.as_of),
               protected=protected, records=core_authorizations(core, iid),
               as_of=fresh.as_of,
               max_age_minutes=PolicyConfig.from_env().approval_ttl_minutes,
               recorded_ok=frozenset(r.step_id for r in core.store.execution_records(iid)
                                     if r.outcome == "succeeded"
                                     and r.plan_sha256 == plan.plan_sha256))
    steps = tuple(run.step(s) for s in sorted(plan.steps, key=lambda s: s.order))
    decisions = tuple(run.decision(d) for d in plan.decision_points)

    counts = Counter(s.status for s in steps)
    counts.update(f"blocked_{s.block_category}" for s in steps if s.block_category)
    counts.update(f"decision_{d.status.lower()}" for d in decisions)
    report = ExecutionReport(
        run_id="RUN-" + digest(plan.plan_sha256, fresh.plan_sha256, env.fingerprint(),
                               fresh.as_of, *sorted(run.used))[:16],
        incident_id=iid, plan_id=plan.plan_id, plan_sha256=plan.plan_sha256,
        plan_integrity=tuple(plan_checks), as_of=fresh.as_of,
        state={"current_plan_sha256": fresh.plan_sha256, "case_sha256": fresh.case_sha256,
               "environment_sha256": env.fingerprint(),
               "authorizations_available": len(run.records),
               "authorizations_used": len(run.used)},
        steps=steps, decisions=decisions, summary=dict(sorted(counts.items())))
    return report.model_copy(update={"report_sha256": _report_sha(report)})


@dataclass
class ReportVerifyResult:
    ok: bool
    errors: list[str] = field(default_factory=list)


def verify_report(core: ReadOnlyCore, report_json: str, plan_json: str, *,
                  protected: ProtectedAccounts | None = None) -> ReportVerifyResult:
    errors: list[str] = []
    try:
        report = ExecutionReport.model_validate(json.loads(report_json))
    except ValueError as e:
        return ReportVerifyResult(False, [f"not a valid execution report: {str(e)[:200]}"])
    if _report_sha(report) != report.report_sha256:
        errors.append("report_sha256 does not match the document content (edited report)")
    fresh = simulate_plan(core, plan_json, protected=protected)
    if fresh.plan_sha256 != report.plan_sha256:
        errors.append("the report was produced from a different plan")
    elif fresh.report_sha256 != report.report_sha256:
        errors.append("the database and plan no longer produce this report (authorizations, "
                      "policy state or evidence changed)")
    return ReportVerifyResult(not errors, errors)

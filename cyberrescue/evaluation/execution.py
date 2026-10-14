"""Evaluation of the Phase 5 simulated executor (EVALUATION ONLY).

For each scenario, in a throw-away Core, build the Phase 4 plan and simulate
it under two regimes, creating authorizations only through the Core's normal
path:

* ``commander_only``  - the Commander requests every step (``request_action``
                        with ``params.plan_step``); no human approves anything;
* ``with_approvals``  - additionally a CISO approves every step whose policy
                        preview requires a human approval (never a tier-3
                        decision point), and the Commander requests again.

Outcomes are COUNTED per category, never folded together - ``blocked`` is not
``failed``:

    succeeded | blocked_authorization | blocked_policy | blocked_legal_hold |
    blocked_human_decision | blocked_dependency | blocked_other | failed_criteria |
    unsupported      (and a check whose ground truth is silent is not_evaluated)

and checked against the ground truth:

* fp_nothing_simulated        - a false positive simulates nothing
* destructive_never_simulated - no decision point is ever simulated
* eradication_held            - eradication of the patient-zero host is blocked by
                                a legal hold iff a PII host is affected
* simulated_steps_succeed     - every simulated step meets its criteria (n/n)
* approval_gated_not_simulated - (commander_only) no step whose plan preview needs a
                                human approval is simulated before one exists
* containment_complete        - (with_approvals) isolation simulated exactly for
                                the compromised hosts
* c2_blocked                  - (with_approvals) block_ip simulated exactly for
                                the C2 addresses actually contacted

The executor never sees the ground truth; only this module reads it.
"""

from __future__ import annotations

import tempfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cyberrescue.core.service import CoreService
from cyberrescue.evaluation.investigation import CaseCheck, _check
from cyberrescue.execution.executor import simulate_plan
from cyberrescue.execution.model import ExecutionReport
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.model import ResponsePlan
from cyberrescue.response.planner import build_plan
from cyberrescue.telemetry.catalog import DEFAULT_ROOT, ground_truth_relpath, scenario_info
from cyberrescue.telemetry.ground_truth import GroundTruth, load_ground_truth
from cyberrescue.telemetry.importer import import_scenario

CATEGORIES = ("succeeded", "blocked_authorization", "blocked_policy", "blocked_legal_hold",
              "blocked_human_decision", "blocked_dependency", "blocked_other",
              "failed_criteria", "unsupported")


def outcome_counts(report: ExecutionReport) -> dict[str, int]:
    """Steps AND decision points, one category each."""
    c: Counter = Counter({k: 0 for k in CATEGORIES})
    for item in (*report.steps, *report.decisions):
        if item.status == "SUCCEEDED":
            c["succeeded"] += 1
        elif item.status == "FAILED":
            c["failed_criteria"] += 1
        elif item.status == "UNSUPPORTED":
            c["unsupported"] += 1
        elif item.block_category in ("authorization", "policy", "legal_hold",
                                     "human_decision", "dependency"):
            c[f"blocked_{item.block_category}"] += 1
        else:
            c["blocked_other"] += 1
    return dict(c)


@dataclass
class ExecutionEvaluation:
    scenario: str
    incident_id: str
    outcomes: dict[str, dict[str, int]] = field(default_factory=dict)
    checks: list[CaseCheck] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _request_all(svc: CoreService, plan, commander) -> None:
    for s in plan.steps:
        asset = s.target.value if s.target.kind == "host" else None
        svc.request_action(plan.incident_id, s.action, asset, commander.id,
                           params={"plan_step": s.step_id}, source="evaluation")


def run_execution(key: str, *, root: str | Path | None = None
                  ) -> tuple[dict[str, ExecutionReport], GroundTruth, ResponsePlan]:
    from shared.mock_data import load_alert
    info = scenario_info(key)
    reports: dict[str, ExecutionReport] = {}
    with tempfile.TemporaryDirectory(prefix="cyberrescue-exec-eval-") as tmp:
        path = Path(tmp) / "eval.db"
        svc = CoreService.open(path)
        try:
            svc.seed_assets_from_mock()
            collector = svc.register_actor("system", "collector", "evaluation")
            alert = load_alert(info.incident_alias)
            svc.open_incident(alert["incident_id"], title=alert["title"],
                              primary_asset_id=alert["asset_id"])
            import_scenario(svc, info.key, collector_id=collector.id, root=root)
            commander = svc.register_actor("agent", "commander", "evaluation commander")
            ciso = svc.register_actor("human", "ciso", "evaluation ciso")
        finally:
            svc.conn.close()
        with open_readonly(path) as ro:
            plan = build_plan(ro, info.incident_alias)
        plan_json = plan.to_json()

        svc = CoreService.open(path)
        try:
            _request_all(svc, plan, commander)
        finally:
            svc.conn.close()
        with open_readonly(path) as ro:
            reports["commander_only"] = simulate_plan(ro, plan_json)

        svc = CoreService.open(path)
        try:
            for s in plan.steps:
                if "P5" in s.preview.unmet_rules:
                    svc.grant_approval(plan.incident_id, action=s.action,
                                       asset_id=s.target.value, approver_actor_id=ciso.id,
                                       reason="evaluation: approve proposed containment")
            _request_all(svc, plan, commander)
        finally:
            svc.conn.close()
        with open_readonly(path) as ro:
            reports["with_approvals"] = simulate_plan(ro, plan_json)
    gt = load_ground_truth(Path(root or DEFAULT_ROOT) / ground_truth_relpath(info))
    return reports, gt, plan


def _simulated(report: ExecutionReport, action: str) -> list[str]:
    return sorted({s.target.value for s in report.steps
                   if s.action == action and "SIMULATED" in s.path})


def evaluate_execution(reports: dict[str, ExecutionReport], gt: GroundTruth,
                       plan: ResponsePlan) -> ExecutionEvaluation:
    facts, fp = gt.facts, gt.verdict == "false_positive"
    first, full = reports["commander_only"], reports["with_approvals"]
    ev = ExecutionEvaluation(scenario=gt.scenario, incident_id=gt.incident_id,
                             outcomes={k: outcome_counts(r) for k, r in reports.items()})
    simulated = [s for r in reports.values() for s in r.steps if "SIMULATED" in s.path]
    needs = {s.step_id for s in plan.steps if "P5" in s.preview.unmet_rules}
    early = [s for s in first.steps if s.step_id in needs and "SIMULATED" in s.path]
    patient = facts.get("patient_zero")
    wipes = [d for d in full.decisions if d.action == "wipe_host" and d.target.value == patient]
    pii = facts.get("pii_host_affected")
    if facts.get("c2_contact") is True:
        c2 = sorted(facts.get("c2_ips", []))
    elif fp or facts.get("c2_contact") is False:
        c2 = []
    else:
        c2 = None
    ev.checks += [
        _check("fp_nothing_simulated", 0 if fp else None, len(simulated)),
        _check("destructive_never_simulated", 0,
               sum(1 for r in reports.values() for d in r.decisions if "SIMULATED" in d.path)),
        _check("eradication_held", (pii if wipes else None) if not fp else None,
               bool(wipes) and all(d.block_category == "legal_hold" for d in wipes)),
        _check("simulated_steps_succeed", f"{len(simulated)}/{len(simulated)}",
               f"{sum(1 for s in simulated if s.status == 'SUCCEEDED')}/{len(simulated)}"),
        _check("approval_gated_not_simulated", f"0/{len(needs)}" if needs else None,
               f"{len(early)}/{len(needs)}"),
        _check("containment_complete", sorted(facts.get("compromised_hosts", [] if fp
                                                        else None) or [])
               if (fp or "compromised_hosts" in facts) else None,
               _simulated(full, "isolate_host")),
        _check("c2_blocked", c2, _simulated(full, "block_ip")),
    ]
    return ev

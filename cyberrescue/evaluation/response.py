"""Plan-level evaluation of the Phase 4 response planner (EVALUATION ONLY).

Builds each scenario's ResponsePlan in a throw-away Core (read-only access,
dry-run detection, nothing persisted) and compares it with what the ground
truth implies a responder should and should not do:

* isolated_hosts               - isolation proposed exactly for compromised hosts
* blocked_c2                   - block_ip proposed exactly for C2 IPs actually contacted
* disabled_accounts            - the abused account, when it authenticated laterally
* quarantined_malware          - the malware path, when the ground truth names one
* regulator_decision           - a notify_regulator decision iff a PII host is affected
* eradication_after_preservation - every wipe/restore decision waits for imaging
* benign_hosts_untouched       - no step on hosts that only show benign-explained activity
* steps_cite_malicious_evidence - every non-notification step cites a malicious event
* no_tier3_steps               - tier-3 actions never appear as steps
* false_positive_quiet         - a false positive yields no steps

The planner never sees the ground truth; it is read here only. A check whose
ground truth says nothing is "not_evaluated", never passed.
"""

from __future__ import annotations

import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cyberrescue.core.service import CoreService
from cyberrescue.evaluation.investigation import CaseCheck, _check
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.model import ResponsePlan
from cyberrescue.response.planner import build_plan
from cyberrescue.telemetry.catalog import DEFAULT_ROOT, ground_truth_relpath, scenario_info
from cyberrescue.telemetry.ground_truth import GroundTruth, load_ground_truth
from cyberrescue.telemetry.importer import import_scenario

CONTAINMENT_ACTIONS = frozenset({"isolate_host", "kill_process", "quarantine_file",
                                 "preserve_disk_image"})


@dataclass
class PlanEvaluation:
    scenario: str
    incident_id: str
    plan_id: str
    steps: int
    decision_points: int
    tasks: int
    checks: list[CaseCheck] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class PlanRun:
    plan: ResponsePlan
    ground_truth: GroundTruth
    refs: dict[str, str]                 # evidence id -> telemetry event id
    hosts: dict[str, str | None]         # telemetry event id -> host


def run_plan(key: str, *, root: str | Path | None = None) -> PlanRun:
    from shared.mock_data import load_alert
    info = scenario_info(key)
    with tempfile.TemporaryDirectory(prefix="cyberrescue-plan-eval-") as tmp:
        path = Path(tmp) / "eval.db"
        svc = CoreService.open(path)
        try:
            svc.seed_assets_from_mock()
            collector = svc.register_actor("system", "collector", "evaluation")
            alert = load_alert(info.incident_alias)
            svc.open_incident(alert["incident_id"], title=alert["title"],
                              primary_asset_id=alert["asset_id"])
            import_scenario(svc, info.key, collector_id=collector.id, root=root)
        finally:
            svc.conn.close()
        with open_readonly(path) as ro:
            plan = build_plan(ro, info.incident_alias)
            evidence = ro.list_evidence(info.incident_alias)
    gt = load_ground_truth(Path(root or DEFAULT_ROOT) / ground_truth_relpath(info))
    return PlanRun(plan=plan, ground_truth=gt, refs={e.id: e.source_ref for e in evidence},
                   hosts={e.source_ref: e.host for e in evidence})


def _targets(plan: ResponsePlan, action: str) -> list[Any]:
    return sorted({s.target.value for s in plan.steps if s.action == action})


def evaluate_plan(run: PlanRun) -> PlanEvaluation:
    plan, gt = run.plan, run.ground_truth
    facts, fp = gt.facts, gt.verdict == "false_positive"
    no_lateral = fp or facts.get("lateral_movement_attempted") is False
    succeeded = facts.get("lateral_auth_succeeded")
    compromised = facts.get("compromised_hosts", [] if fp else None)
    malicious = {i for i, ref in run.refs.items() if ref in set(gt.malicious_event_ids)}
    benign_hosts = {run.hosts.get(x) for b in gt.benign_explanations for x in b.event_ids}
    benign_hosts -= set(compromised or []) | set(succeeded or []) | {None}

    if facts.get("c2_contact") is True:
        c2 = sorted(facts.get("c2_ips", []))
    elif fp or facts.get("c2_contact") is False:
        c2 = []
    else:
        c2 = None
    if succeeded:
        accounts = [str(facts["abused_account"]).lower()] if facts.get("abused_account") \
            else None
    else:
        accounts = [] if no_lateral or succeeded == [] else None
    malware = [facts["malware_path"]] if facts.get("malware_path") else ([] if fp else None)
    pii = facts.get("pii_host_affected")

    acting = [s for s in plan.steps if s.action != "notify_stakeholders"]
    by_id = {s.step_id: s for s in plan.steps}
    eradication = [d for d in plan.decision_points
                   if d.action in ("wipe_host", "restore_from_backup")]

    ev = PlanEvaluation(scenario=gt.scenario, incident_id=gt.incident_id, plan_id=plan.plan_id,
                        steps=len(plan.steps), decision_points=len(plan.decision_points),
                        tasks=len(plan.tasks))
    ev.checks += [
        _check("isolated_hosts", sorted(compromised) if compromised is not None else None,
               _targets(plan, "isolate_host")),
        _check("blocked_c2", c2, _targets(plan, "block_ip")),
        _check("disabled_accounts", accounts, _targets(plan, "disable_account")),
        _check("quarantined_malware", malware,
               sorted({s.params["path"].untrusted for s in plan.steps
                       if s.action == "quarantine_file"})),
        _check("regulator_decision", pii,
               any(d.action == "notify_regulator" for d in plan.decision_points)),
        _check("eradication_after_preservation", True if compromised else None,
               all(any(p in by_id and by_id[p].action == "preserve_disk_image"
                       and by_id[p].target.value == d.target.value for p in d.prerequisites)
                   for d in eradication) and bool(eradication)),
        _check("benign_hosts_untouched", 0 if benign_hosts else None,
               sum(1 for s in plan.steps if s.action in CONTAINMENT_ACTIONS
                   and s.target.value in benign_hosts)),
        _check("steps_cite_malicious_evidence", f"{len(acting)}/{len(acting)}",
               f"{sum(1 for s in acting if set(s.evidence_ids) & malicious)}/{len(acting)}"),
        _check("no_tier3_steps", 0, sum(1 for s in plan.steps if s.tier == 3)),
        _check("false_positive_quiet", 0 if fp else None, len(plan.steps)),
    ]
    return ev

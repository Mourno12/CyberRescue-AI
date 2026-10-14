"""Evaluation of Phase 6 execution accountability (EVALUATION ONLY).

For each scenario, in a throw-away Core: build the plan; the Commander requests
every step (``params.plan_step``); a CISO approves the steps whose preview needs
a human; the Commander requests again; then

1. ``record``  - ``record_plan`` simulates and records through the Core;
2. ``replay``  - the same recording is attempted again;
3. ``after``   - a dry run after recording;
4. ``verify``  - ``verify_recorded`` cross-checks report, records and audit chain.

Checks (ground truth read only here; a silent ground truth is not_evaluated):

* records_match_simulated     - every simulated step got exactly one record
* no_refusals                 - the Core refused no record of a fresh run
* replay_records_nothing      - a second recording writes nothing
* recorded_now_already_executed - the dry run after recording reports each
                                recorded step already_executed
* recorded_run_verifies       - report, records, events and chain agree
* records_simulated_only      - every record is mode "simulated" and tier 1/2
* fp_nothing_recorded         - a false positive records nothing
* isolation_recorded          - isolation recorded exactly for the compromised hosts
"""

from __future__ import annotations

import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cyberrescue.core.catalog import get_action
from cyberrescue.core.service import CoreService
from cyberrescue.evaluation.investigation import CaseCheck, _check
from cyberrescue.execution.executor import simulate_plan
from cyberrescue.execution.recorder import record_plan
from cyberrescue.execution.records import verify_recorded
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.planner import build_plan
from cyberrescue.telemetry.catalog import DEFAULT_ROOT, ground_truth_relpath, scenario_info
from cyberrescue.telemetry.ground_truth import GroundTruth, load_ground_truth
from cyberrescue.telemetry.importer import import_scenario


@dataclass
class AccountabilityEvaluation:
    scenario: str
    incident_id: str
    recorded: int = 0
    refused: int = 0
    replayed: int = 0
    checks: list[CaseCheck] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AccountabilityRun:
    record: object
    replay: object
    after: object
    verify: object
    records: list
    ground_truth: GroundTruth


def run_accountability(key: str, *, root: str | Path | None = None) -> AccountabilityRun:
    from shared.mock_data import load_alert
    info = scenario_info(key)
    with tempfile.TemporaryDirectory(prefix="cyberrescue-acc-eval-") as tmp:
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
            executor = svc.register_actor("system", "executor", "evaluation executor")
        finally:
            svc.conn.close()
        with open_readonly(path) as ro:
            plan = build_plan(ro, info.incident_alias)
        svc = CoreService.open(path)
        try:
            for s in plan.steps:
                if "P5" in s.preview.unmet_rules:
                    svc.grant_approval(plan.incident_id, action=s.action,
                                       asset_id=s.target.value, approver_actor_id=ciso.id,
                                       reason="evaluation: approve proposed containment")
            for s in plan.steps:
                asset = s.target.value if s.target.kind == "host" else None
                svc.request_action(plan.incident_id, s.action, asset, commander.id,
                                   params={"plan_step": s.step_id}, source="evaluation")
        finally:
            svc.conn.close()
        plan_json = plan.to_json()
        first = record_plan(path, plan_json, recorder_actor_id=executor.id)
        replay = record_plan(path, plan_json, recorder_actor_id=executor.id)
        with open_readonly(path) as ro:
            after = simulate_plan(ro, plan_json)
            verify = verify_recorded(ro, first.report.to_json(), plan_json)
            records = ro.store.execution_records(plan.incident_id)
    gt = load_ground_truth(Path(root or DEFAULT_ROOT) / ground_truth_relpath(info))
    return AccountabilityRun(first, replay, after, verify, records, gt)


def evaluate_accountability(run: AccountabilityRun) -> AccountabilityEvaluation:
    gt, facts = run.ground_truth, run.ground_truth.facts
    fp = gt.verdict == "false_positive"
    simulated = [s for s in run.record.report.steps if "SIMULATED" in s.path]
    recorded_ids = {o.step_id for o in run.record.recorded}
    already = [s for s in run.after.steps if s.step_id in recorded_ids
               and s.block_category == "already_executed"]
    isolated = sorted({r.asset_id for r in run.records if r.action == "isolate_host"})
    ev = AccountabilityEvaluation(scenario=gt.scenario, incident_id=gt.incident_id,
                                  recorded=len(run.record.recorded),
                                  refused=len(run.record.refused),
                                  replayed=len(run.replay.recorded))
    ev.checks += [
        _check("records_match_simulated", f"{len(simulated)}/{len(simulated)}",
               f"{len(recorded_ids & {s.step_id for s in simulated})}/{len(simulated)}"),
        _check("no_refusals", 0, len(run.record.refused)),
        _check("replay_records_nothing", 0, len(run.replay.recorded)),
        _check("recorded_now_already_executed", f"{len(recorded_ids)}/{len(recorded_ids)}",
               f"{len(already)}/{len(recorded_ids)}"),
        _check("recorded_run_verifies", True if run.records else None, bool(run.verify.ok)),
        _check("records_simulated_only", True if run.records else None,
               all(r.mode == "simulated" and int(get_action(r.action).tier) in (1, 2)
                   for r in run.records)),
        _check("fp_nothing_recorded", 0 if fp else None, len(run.records)),
        _check("isolation_recorded", sorted(facts.get("compromised_hosts", []))
               if (fp or "compromised_hosts" in facts) else None, isolated),
    ]
    return ev

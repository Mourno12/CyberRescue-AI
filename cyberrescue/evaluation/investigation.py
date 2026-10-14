"""Case-level evaluation of the Phase 3 investigation layer (EVALUATION ONLY).

Builds each scenario's Case in a throw-away Core (read-only access, dry-run
detection — nothing persisted) and checks it against the ground truth:

* scope_compromised / scope_accessed / scope_targeted  vs ground-truth facts
* malicious_events_in_timeline  — malicious events annotated by a detection
* stage_order                   — ground-truth stages appear in the timeline in order
* benign_never_detected         — benign-explained events carry no detection
* lateral_code_execution        — derived from gap G1 vs the fact of that name
* false_positive_quiet          — a false positive yields no detections

A check whose ground truth says nothing is "not_evaluated", never passed.
"""

from __future__ import annotations

import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cyberrescue.core.service import CoreService
from cyberrescue.investigation.builder import build_case
from cyberrescue.investigation.model import Case, Gap
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.telemetry.catalog import DEFAULT_ROOT, ground_truth_relpath, scenario_info
from cyberrescue.telemetry.ground_truth import GroundTruth, load_ground_truth
from cyberrescue.telemetry.importer import import_scenario


@dataclass(frozen=True)
class CaseCheck:
    check: str
    expected: Any
    observed: Any
    status: str                       # match | mismatch | not_evaluated


@dataclass
class CaseEvaluation:
    scenario: str
    incident_id: str
    case_id: str
    checks: list[CaseCheck] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def lateral_code_execution_observed(accessed_hosts, gaps: list[Gap]) -> bool:
    """False when no accessed host exists or every accessed host has a G1 gap
    (authenticated access with no observed activity afterwards)."""
    unverified = {g.host for g in gaps if g.code == "G1"}
    return any(h not in unverified for h in accessed_hosts)


def run_case(key: str, *, root: str | Path | None = None
             ) -> tuple[Case, GroundTruth, dict[str, str]]:
    from shared.mock_data import load_alert
    info = scenario_info(key)
    with tempfile.TemporaryDirectory(prefix="cyberrescue-case-eval-") as tmp:
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
            case = build_case(ro, info.incident_alias)
            refs = {e.id: e.source_ref for e in ro.list_evidence(info.incident_alias)}
    gt = load_ground_truth(Path(root or DEFAULT_ROOT) / ground_truth_relpath(info))
    return case, gt, refs


def _check(name: str, expected: Any, observed: Any) -> CaseCheck:
    if expected is None:
        return CaseCheck(name, None, observed, "not_evaluated")
    return CaseCheck(name, expected, observed, "match" if expected == observed else "mismatch")


def evaluate_case(case: Case, gt: GroundTruth, refs: dict[str, str]) -> CaseEvaluation:
    facts, fp = gt.facts, gt.verdict == "false_positive"
    no_lateral = fp or facts.get("lateral_movement_attempted") is False
    succeeded = facts.get("lateral_auth_succeeded")
    targets = facts.get("lateral_auth_targets")
    by_ref = {refs[i]: i for i in refs}
    detected = {i for e in case.timeline.entries if e.detection_rules for i in e.evidence_ids}
    first_seen = {}
    for e in case.timeline.entries:
        if e.detection_rules:
            for i in e.evidence_ids:
                first_seen.setdefault(i, e.start)
    malicious = [by_ref[x] for x in gt.malicious_event_ids if x in by_ref]
    stage_first = [(min((first_seen[by_ref[x]] for x in s.event_ids
                         if x in by_ref and by_ref[x] in first_seen), default=None), s.stage)
                   for s in gt.attack_chain]
    benign = {by_ref[x] for b in gt.benign_explanations for x in b.event_ids if x in by_ref}

    ev = CaseEvaluation(scenario=gt.scenario, incident_id=gt.incident_id, case_id=case.case_id)
    ev.checks += [
        _check("scope_compromised", facts.get("compromised_hosts", [] if fp else None),
               list(case.scope.compromised_hosts)),
        _check("scope_accessed", succeeded if succeeded is not None else
               ([] if no_lateral else None), list(case.scope.accessed_hosts)),
        _check("scope_targeted", sorted(set(targets) - set(succeeded or []))
               if targets is not None else ([] if no_lateral else None),
               list(case.scope.targeted_hosts)),
        _check("malicious_events_in_timeline", f"{len(malicious)}/{len(malicious)}",
               f"{len(set(malicious) & detected)}/{len(malicious)}"),
        _check("stage_order", [s.stage for s in gt.attack_chain] or None,
               [stage for t, stage in sorted((t, s) for t, s in stage_first if t)]),
        _check("benign_never_detected", 0, len(benign & detected)),
        _check("lateral_code_execution", facts.get("lateral_code_execution_observed",
                                                   False if no_lateral else None),
               lateral_code_execution_observed(case.scope.accessed_hosts, list(case.gaps))),
        _check("false_positive_quiet", 0 if fp else None, len(case.detections)),
    ]
    return ev

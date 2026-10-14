"""Verify a RECORDED simulated run against the Core - read-only.

After ``simulate --record`` the Core holds, per recorded step, an
``execution_records`` row and its ACTION_EXECUTED / ACTION_VERIFIED events. A
re-simulation would now (correctly) report those steps ``already_executed``,
so a recorded report is verified by cross-checking instead of re-running:

* the report's own ``report_sha256`` and the plan's ``plan_sha256``;
* every Core record that cites this report: same plan, step (and the step's
  policy-independent hash), request, outcome and criteria as the report's
  SIMULATED step, mode ``simulated``;
* every simulated step of the report has such a record (a step the Core
  refused to record is reported, not hidden);
* each record against its two audit events (payload, links, recorder) - a
  row edited behind the triggers' back no longer matches its hash-chained
  events;
* incident-wide: every ACTION_EXECUTED / ACTION_VERIFIED event belongs to a
  record (``verify_accountability``) - this guards the tail of the chain that
  case/plan identities are deliberately anchored before;
* the incident's audit chain verifies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from cyberrescue.core.audit import canonical_json
from cyberrescue.core.models import EventType, LinkRelation
from cyberrescue.execution.executor import _plan_sha, _report_sha, parse_plan
from cyberrescue.execution.model import ExecutionReport
from cyberrescue.execution.recorder import step_sha256
from cyberrescue.investigation.readonly import ReadOnlyCore

_EXECUTED_FIELDS = ("action", "asset_id", "plan_id", "plan_sha256", "step_id", "step_sha256",
                    "report_sha256", "evidence_fingerprint", "environment_sha256",
                    "audit_head_hash")


@dataclass
class RecordsVerifyResult:
    ok: bool
    records: int
    errors: list[str] = field(default_factory=list)


def recorded_for(core: ReadOnlyCore, report: ExecutionReport) -> list:
    return [r for r in core.store.execution_records(report.incident_id)
            if r.report_sha256 == report.report_sha256]


def verify_recorded(core: ReadOnlyCore, report_json: str, plan_json: str
                    ) -> RecordsVerifyResult:
    errors: list[str] = []
    try:
        report = ExecutionReport.model_validate(json.loads(report_json))
    except ValueError as e:
        return RecordsVerifyResult(False, 0, [f"not a valid execution report: {str(e)[:200]}"])
    plan = parse_plan(plan_json)
    if _report_sha(report) != report.report_sha256:
        errors.append("report_sha256 does not match the document content (edited report)")
    if _plan_sha(plan) != plan.plan_sha256 or plan.plan_sha256 != report.plan_sha256:
        errors.append("the plan is not the one this report was produced from")
    steps = {s.step_id: s for s in plan.steps}
    simulated = {s.step_id: s for s in report.steps if "SIMULATED" in s.path}
    records = recorded_for(core, report)
    seen: set[str] = set()
    for rec in records:
        s = simulated.get(rec.step_id)
        if s is None or rec.step_id in seen:
            errors.append(f"record {rec.id} does not correspond to a simulated step of the "
                          "report")
            continue
        seen.add(rec.step_id)
        expected = {"mode": "simulated", "plan_id": plan.plan_id,
                    "plan_sha256": plan.plan_sha256,
                    "step_sha256": step_sha256(steps[rec.step_id])
                    if rec.step_id in steps else None,
                    "action_request_id": s.authorization.request_id,
                    "outcome": s.status.lower(), "action": s.action,
                    "criteria": [{"check": c.check, "satisfied": c.satisfied}
                                 for c in s.criteria]
                    or [{"check": "effect_applied", "satisfied": False}]}
        actual = {"mode": rec.mode, "plan_id": rec.plan_id, "plan_sha256": rec.plan_sha256,
                  "step_sha256": rec.step_sha256, "action_request_id": rec.action_request_id,
                  "outcome": rec.outcome, "action": rec.action, "criteria": rec.criteria}
        for k in expected:
            if expected[k] != actual[k]:
                errors.append(f"record {rec.id}: {k} differs from the report")
    for step_id in sorted(set(simulated) - seen):
        errors.append(f"simulated step {step_id} has no Core execution record")
    errors += verify_accountability(core, report.incident_id)
    audit = core.audit.verify(report.incident_id)
    if not audit.ok:
        errors.append("the incident's audit chain does not verify")
    return RecordsVerifyResult(not errors, len(records), errors)


def verify_accountability(core: ReadOnlyCore, incident_id: str) -> list[str]:
    """Incident-wide: every ACTION_EXECUTED / ACTION_VERIFIED event belongs to an
    execution record and every record matches its events. Case/plan identities
    are anchored BEFORE trailing accountability events (Phase 3 builder), so this
    check - with the audit chain - is what protects that tail: an extra,
    correctly hash-chained accountability event without a record is reported."""
    errors: list[str] = []
    records = core.store.execution_records(incident_id)
    owned = {r.executed_event_uid for r in records} | {r.verified_event_uid for r in records}
    for e in core.audit.events(incident_id):
        if e.event_type in (EventType.ACTION_EXECUTED.value, EventType.ACTION_VERIFIED.value) \
                and e.uid not in owned:
            errors.append(f"{e.event_type} event {e.uid} has no execution record")
    for rec in records:
        errors += _against_events(core, rec)
    return errors


def _against_events(core: ReadOnlyCore, rec) -> list[str]:
    errors = []
    executed = core.audit.get(rec.executed_event_uid)
    verified = core.audit.get(rec.verified_event_uid)
    if executed is None or executed.event_type != EventType.ACTION_EXECUTED.value \
            or verified is None or verified.event_type != EventType.ACTION_VERIFIED.value:
        return [f"record {rec.id}: its audit events are missing"]
    p = executed.payload
    if p.get("mode") != "simulated" or p.get("execution_id") != rec.id \
            or p.get("request_id") != rec.action_request_id \
            or any(p.get(k) != getattr(rec, k) for k in _EXECUTED_FIELDS):
        errors.append(f"record {rec.id} does not match its ACTION_EXECUTED event")
    v = verified.payload
    if v.get("mode") != "simulated" or v.get("execution_id") != rec.id \
            or v.get("outcome") != rec.outcome \
            or canonical_json(v.get("criteria")) != canonical_json(rec.criteria):
        errors.append(f"record {rec.id} does not match its ACTION_VERIFIED event")
    links_e = {(LinkRelation(lk.relation), lk.target_uid) for lk in executed.links}
    links_v = {(LinkRelation(lk.relation), lk.target_uid) for lk in verified.links}
    if links_e != {(LinkRelation.EXECUTES, rec.authorized_event_uid)} \
            or links_v != {(LinkRelation.VERIFIES, executed.uid)}:
        errors.append(f"record {rec.id}: audit links are not executes/verifies as recorded")
    if not (executed.actor_id == verified.actor_id == rec.recorded_by):
        errors.append(f"record {rec.id}: recorder differs from the audit events")
    return errors

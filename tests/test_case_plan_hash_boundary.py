"""CyberRescue Phase 6 — the case/plan identity boundary.

A Phase 3 case is anchored at the last audit event that is not a trailing
post-plan accountability event (ACTION_EXECUTED / ACTION_VERIFIED). Recording a
simulated execution therefore leaves case_sha256 and plan_sha256 unchanged,
while every tampering path is still detected:

* case/plan content       - by verify_case / verify_plan (self-hash + rebuild);
* evidence                - by the rebuild (fingerprint, integrity);
* the anchored audit prefix and the whole chain - audit_chain_ok covers the
  entire chain, so edits anywhere flip it and change the case;
* execution records and the accountability tail - by verify_accountability /
  verify_recorded and the audit chain.
"""

import json
import sqlite3

import pytest

from cyberrescue.core.models import EventType
from cyberrescue.core.service import CoreService
from cyberrescue.execution.executor import simulate_plan
from cyberrescue.execution.recorder import record_plan
from cyberrescue.execution.records import verify_accountability, verify_recorded
from cyberrescue.investigation.builder import build_case, case_anchor, verify_case
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.planner import build_plan, verify_plan
from tests._execution_factory import approve, plans_of, request
from tests._response_factory import authority_core, writable_copy

INC = "INC-A-2026-0039"


@pytest.fixture(scope="module")
def base(tmp_path_factory):
    path = authority_core(tmp_path_factory.mktemp("bound") / "core.db")
    svc = CoreService.open(path)
    svc.register_actor("system", "executor", "e", "test:executor")
    svc.conn.close()
    plan = plans_of(path)["INC-A"]
    request(path, plan)
    return path


@pytest.fixture
def db(base, tmp_path):
    return writable_copy(base, tmp_path / "core.db")


def docs(path, ref="INC-A"):
    with open_readonly(path) as ro:
        return build_case(ro, ref), build_plan(ro, ref)


def executor(path):
    svc = CoreService.open(path)
    try:
        return svc.store.find_actor("test:executor").id
    finally:
        svc.conn.close()


def append(path, event_type, payload):
    """Core-internal append (tests only): a correctly hash-chained event."""
    svc = CoreService.open(path)
    try:
        return svc.store.audit.append(event_type, incident_id=INC, source="test",
                                      payload=payload)
    finally:
        svc.conn.close()


def raw(path, *sql, drop=()):
    conn = sqlite3.connect(path)
    try:
        for t in drop:
            conn.execute(f"DROP TRIGGER {t}")
        for s in sql:
            conn.execute(s)
        conn.commit()
    finally:
        conn.close()


def verified(path, case, plan):
    with open_readonly(path) as ro:
        return verify_case(ro, case.to_json()), verify_plan(ro, plan.to_json())


# --- 1-3: stability -------------------------------------------------------------------------

def test_case_hash_is_stable_after_action_executed_and_action_verified(db):
    case, plan = docs(db)
    append(db, EventType.ACTION_EXECUTED, {"mode": "simulated"})
    after_executed, plan_e = docs(db)
    assert after_executed.case_sha256 == case.case_sha256            # 1
    append(db, EventType.ACTION_VERIFIED, {"mode": "simulated"})
    after_verified, plan_v = docs(db)
    assert after_verified.case_sha256 == case.case_sha256            # 2
    assert plan_e.plan_sha256 == plan_v.plan_sha256 == plan.plan_sha256


def test_case_and_plan_hashes_are_stable_after_a_real_recording(db):
    case, plan = docs(db)
    res = record_plan(db, plan.to_json(), recorder_actor_id=executor(db))
    assert len(res.recorded) == 5
    case2, plan2 = docs(db)
    print(f"\ncase_sha256 before={case.case_sha256} after={case2.case_sha256}"
          f"\nplan_sha256 before={plan.plan_sha256} after={plan2.plan_sha256}")
    assert (case2.case_sha256, plan2.plan_sha256) == (case.case_sha256, plan.plan_sha256)
    assert case2.to_json() == case.to_json() and plan2.to_json() == plan.to_json()
    vc, vp = verified(db, case, plan)                                # 3: still verify
    assert vc.ok and vp.ok, (vc.errors, vp.errors)
    with open_readonly(db) as ro:
        assert ro.verify_audit(INC).ok
        assert verify_recorded(ro, res.report.to_json(), plan.to_json()).ok


def test_the_anchor_skips_only_trailing_accountability_events(db):
    case, _ = docs(db)
    record_plan(db, docs(db)[1].to_json(), recorder_actor_id=executor(db))
    with open_readonly(db) as ro:
        events = ro.audit.events(INC)
    anchor = case_anchor(events)
    assert events[-1].event_type == "ACTION_VERIFIED"
    assert anchor.uid != events[-1].uid and anchor.ts == case.as_of
    assert case.integrity["audit_events"] == anchor.seq < len(events)
    assert case.integrity["audit_head_hash"] == anchor.hash


def test_any_other_audited_event_still_moves_the_case(db):
    case, plan = docs(db)
    record_plan(db, plan.to_json(), recorder_actor_id=executor(db))
    approve(db, INC, "wipe_host", "ws-eng-014")                      # a case-relevant event
    case2, plan2 = docs(db)
    assert case2.case_sha256 != case.case_sha256 and plan2.plan_sha256 != plan.plan_sha256
    with open_readonly(db) as ro:                                    # anchored prefix now
        events = ro.audit.events(INC)                                # includes the records
        assert case_anchor(events).uid == events[-1].uid
    vc, vp = verified(db, case, plan)
    assert not vc.ok and not vp.ok


# --- 4-5: execution records and the audit chain -----------------------------------------------

def test_execution_record_tampering_is_still_detected(db):
    case, plan = docs(db)
    res = record_plan(db, plan.to_json(), recorder_actor_id=executor(db))
    raw(db, "UPDATE execution_records SET outcome = 'failed' WHERE rowid = 1",
        drop=("execution_records_no_update",))
    with open_readonly(db) as ro:
        errors = verify_accountability(ro, INC)
        assert any("does not match its ACTION_VERIFIED event" in e for e in errors)
        assert not verify_recorded(ro, res.report.to_json(), plan.to_json()).ok


def test_tampering_with_execution_events_breaks_the_chain_and_the_case(db):
    case, plan = docs(db)
    record_plan(db, plan.to_json(), recorder_actor_id=executor(db))
    raw(db, "UPDATE audit_events SET payload = replace(payload, 'succeeded', 'failed') "
            "WHERE event_type = 'ACTION_VERIFIED'", drop=("audit_events_no_update",))
    with open_readonly(db) as ro:
        assert not ro.verify_audit(INC).ok                            # 5
    vc, vp = verified(db, case, plan)                                # whole chain covered
    assert not vc.ok and any("audit/evidence verification" in e for e in vc.errors)
    assert not vp.ok


def test_tampering_inside_the_anchored_prefix_is_detected(db):
    case, plan = docs(db)
    record_plan(db, plan.to_json(), recorder_actor_id=executor(db))
    raw(db, "UPDATE audit_events SET payload = replace(payload, 'ws-eng-014', 'ws-fin-007') "
            "WHERE event_type = 'ACTION_AUTHORIZED'", drop=("audit_events_no_update",))
    vc, vp = verified(db, case, plan)
    assert not vc.ok and not vp.ok


def test_a_forged_trailing_accountability_event_is_caught_by_accountability(db):
    """By design the case does not move for trailing accountability events; a
    correctly chained but forged one is caught on the accountability side."""
    case, plan = docs(db)
    record_plan(db, plan.to_json(), recorder_actor_id=executor(db))
    append(db, EventType.ACTION_EXECUTED, {"mode": "real", "request_id": "forged"})
    assert docs(db)[0].case_sha256 == case.case_sha256
    with open_readonly(db) as ro:
        assert ro.verify_audit(INC).ok                               # validly chained...
        errors = verify_accountability(ro, INC)
    assert any("has no execution record" in e for e in errors)       # ...but has no record


# --- 6-7: case / plan / evidence tampering ------------------------------------------------------

def test_case_content_and_evidence_tampering_are_detected(db):
    case, plan = docs(db)
    record_plan(db, plan.to_json(), recorder_actor_id=executor(db))
    doc = json.loads(case.to_json())
    doc["scope"]["compromised_hosts"] = []
    with open_readonly(db) as ro:
        res = verify_case(ro, json.dumps(doc))
    assert not res.ok and any("edited export" in e for e in res.errors)
    raw(db, "UPDATE evidence SET data = replace(data, 'InvoiceViewer', 'Notepad') "
            f"WHERE incident_id = '{INC}'", drop=("evidence_no_update",))
    vc, vp = verified(db, case, plan)
    assert not vc.ok and not vp.ok


def test_plan_content_and_new_evidence_are_detected(db):
    case, plan = docs(db)
    record_plan(db, plan.to_json(), recorder_actor_id=executor(db))
    doc = json.loads(plan.to_json())
    doc["steps"][1]["target"]["value"] = "ws-fin-007"
    with open_readonly(db) as ro:
        res = verify_plan(ro, json.dumps(doc))
    assert not res.ok and any("edited export" in e for e in res.errors)
    from cyberrescue.telemetry.importer import import_events
    svc = CoreService.open(db)
    try:
        col = svc.store.find_actor("collector:synthetic")
        import_events(svc, INC, [{"dataset": "late", "event_id": "late-1", "vendor": "X",
                                  "sensor": "edr", "timestamp": "2026-06-13T14:59:00Z",
                                  "category": "log", "action": "syslog",
                                  "host": "ws-eng-014", "message": "late", "fields": {}}],
                      collector_id=col.id)
    finally:
        svc.conn.close()
    vc, vp = verified(db, case, plan)
    assert not vc.ok and not vp.ok


# --- 8: Phase 5 -------------------------------------------------------------------------------

def test_phase5_dry_runs_are_unaffected_by_another_incidents_records(db):
    plans = plans_of(db)
    request(db, plans["INC-C"])
    with open_readonly(db) as ro:
        before = simulate_plan(ro, plans["INC-A"].to_json()).to_json()
    record_plan(db, plans["INC-C"].to_json(), recorder_actor_id=executor(db))
    with open_readonly(db) as ro:
        assert simulate_plan(ro, plans["INC-A"].to_json()).to_json() == before

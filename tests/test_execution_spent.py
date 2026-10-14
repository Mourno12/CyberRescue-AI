"""CyberRescue Phase 6 — dry runs see spent and expired authorizations (and change nothing)."""

from datetime import datetime, timedelta

import pytest

from cyberrescue.core.service import CoreService
from cyberrescue.execution.executor import simulate_plan
from cyberrescue.investigation.readonly import STORE_READS, open_readonly
from tests._execution_factory import COMMANDER, plans_of, request
from tests._response_factory import authority_core, writable_copy
from tests.test_investigation_security import db_state

HEX = "b" * 64


@pytest.fixture(scope="module")
def base(tmp_path_factory):
    return authority_core(tmp_path_factory.mktemp("spent") / "core.db")


@pytest.fixture
def db(base, tmp_path):
    return writable_copy(base, tmp_path / "core.db")


def sim(path, plan):
    with open_readonly(path) as ro:
        return simulate_plan(ro, plan.to_json())


def record(path, plan, step, request_id, clock=None):
    svc = CoreService.open(path, **({"clock": clock} if clock else {}))
    try:
        ex = svc.store.find_actor("test:executor") or svc.register_actor(
            "system", "executor", "e", "test:executor")
        return svc.record_simulated_execution(
            plan.incident_id, request_id=request_id, recorder_actor_id=ex.id,
            action=step.action, asset_id=step.target.value if step.target.kind == "host"
            else None, plan_id=plan.plan_id, plan_sha256=plan.plan_sha256,
            step_id=step.step_id, step_sha256=HEX, report_sha256=HEX,
            evidence_fingerprint=svc.store.evidence_fingerprint(plan.incident_id),
            environment_sha256=HEX, outcome="succeeded",
            criteria=[{"check": c.check, "satisfied": True} for c in step.success_criteria])
    finally:
        svc.conn.close()


def test_readonly_facade_exposes_execution_reads_only():
    assert {"execution_records", "execution_record_for", "evidence_fingerprint",
            "chain_head"} <= STORE_READS
    assert "add_execution_record" not in STORE_READS


def test_a_recorded_step_is_already_executed_in_the_next_dry_run(db):
    plan = plans_of(db)["INC-A"]
    outs = request(db, plan)
    first = sim(db, plan)
    assert [s.status for s in first.steps] == ["SUCCEEDED"] * 5
    notify = plan.steps[0]
    rec = record(db, plan, notify, outs[0].request.id)
    before = db_state(db)
    again = sim(db, plan)
    assert db_state(db) == before                         # dry runs still write nothing
    n = again.steps[0]
    assert (n.status, n.block_category) == ("BLOCKED", "already_executed")
    assert rec.id in n.reason
    assert [s.status for s in again.steps[1:]] == ["SUCCEEDED"] * 4
    assert sim(db, plan).to_json() == again.to_json()     # idempotent


def test_a_new_authorization_after_a_record_is_usable_again(db):
    plan = plans_of(db)["INC-A"]
    outs = request(db, plan, plan.steps[:1])
    record(db, plan, plan.steps[0], outs[0].request.id)
    request(db, plan, plan.steps[:1])                       # a fresh Core authorization
    assert sim(db, plan).steps[0].status == "SUCCEEDED"


def test_authorizations_older_than_the_lifetime_are_expired_at_as_of(db):
    plan = plans_of(db)["INC-A"]
    svc = CoreService.open(db)
    try:
        t0 = datetime.fromisoformat(svc.audit.events(plan.incident_id)[-1].ts)
    finally:
        svc.conn.close()
    svc = CoreService.open(db, clock=lambda: t0 + timedelta(minutes=1))
    try:
        cmd = svc.store.find_actor(COMMANDER)
        s = plan.steps[0]
        svc.request_action(plan.incident_id, s.action, None, cmd.id, source="test",
                           params={"plan_step": s.step_id})
    finally:
        svc.conn.close()
    assert sim(db, plan).steps[0].status == "SUCCEEDED"
    svc = CoreService.open(db, clock=lambda: t0 + timedelta(minutes=62))
    try:                                                   # any later Core event moves as_of
        svc.register_actor("human", "observer", "o", "test:observer")
        svc.audit.append("HUMAN_MESSAGE", incident_id=plan.incident_id, source="test",
                         payload={"text": "later"})
    finally:
        svc.conn.close()
    n = sim(db, plan).steps[0]
    assert (n.status, n.block_category) == ("BLOCKED", "expired")
    assert "older than 60 minutes" in n.reason


def test_phase5_results_are_unchanged_without_records(base, tmp_path):
    db = writable_copy(base, tmp_path / "p5.db")
    plans = plans_of(db)
    for p in plans.values():
        request(db, p)
    cats = {s.block_category for p in plans.values() for s in sim(db, p).steps}
    assert not cats & {"already_executed", "expired"}

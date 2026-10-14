"""CyberRescue Phase 6 — `simulate --record`: the recorder writes only through the Core."""

import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import cyberrescue.execution as execution_pkg
from cyberrescue.core.models import ActionStatus
from cyberrescue.core.service import CoreService
from cyberrescue.execution.cli import main
from cyberrescue.execution.recorder import record_plan, step_sha256
from tests._execution_factory import COMMANDER, plans_of, request
from tests._response_factory import authority_core, writable_copy
from tests.test_investigation_security import AUTHORITY, db_state


@pytest.fixture(scope="module")
def base(tmp_path_factory):
    path = authority_core(tmp_path_factory.mktemp("rec") / "core.db")
    svc = CoreService.open(path)
    svc.register_actor("system", "executor", "simulated executor", "test:executor")
    svc.conn.close()
    return path


@pytest.fixture
def db(base, tmp_path):
    return writable_copy(base, tmp_path / "core.db")


def executor_id(path):
    svc = CoreService.open(path)
    try:
        return svc.store.find_actor("test:executor").id
    finally:
        svc.conn.close()


def core(path, fn):
    svc = CoreService.open(path)
    try:
        return fn(svc)
    finally:
        svc.conn.close()


def counts(path):
    return core(path, lambda svc: (
        svc.conn.execute("SELECT COUNT(*) FROM execution_records").fetchone()[0],
        svc.conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type IN "
                         "('ACTION_EXECUTED','ACTION_VERIFIED')").fetchone()[0]))


def test_inc_a_records_every_simulated_step(db):
    plan = plans_of(db)["INC-A"]
    request(db, plan)
    res = record_plan(db, plan.to_json(), recorder_actor_id=executor_id(db))
    assert len(res.recorded) == 5 and not res.refused
    recs = core(db, lambda svc: svc.execution_records(plan.incident_id))
    by_step = {s.step_id: s for s in plan.steps}
    assert {r.step_id for r in recs} == set(by_step)
    for r in recs:
        assert r.mode == "simulated" and r.outcome == "succeeded"
        assert r.plan_id == plan.plan_id and r.plan_sha256 == plan.plan_sha256
        assert r.step_sha256 == step_sha256(by_step[r.step_id])
        assert r.report_sha256 == res.report.report_sha256
        assert r.evidence_fingerprint == plan.inputs["evidence_fingerprint"]
    assert counts(db) == (5, 10)
    assert core(db, lambda svc: svc.verify_audit(plan.incident_id).ok)
    assert all(q.status == ActionStatus.AUTHORIZED for q in core(
        db, lambda svc: svc.store.action_requests(plan.incident_id)))


def test_recording_is_idempotent(db):
    plan = plans_of(db)["INC-A"]
    request(db, plan)
    record_plan(db, plan.to_json(), recorder_actor_id=executor_id(db))
    before = db_state(db)
    again = record_plan(db, plan.to_json(), recorder_actor_id=executor_id(db))
    assert again.outcomes == [] and db_state(db) == before
    assert {s.block_category for s in again.report.steps} == {"already_executed"}


def test_inc_c_records_only_what_was_simulated(db):
    plan = plans_of(db)["INC-C"]
    request(db, plan)
    res = record_plan(db, plan.to_json(), recorder_actor_id=executor_id(db))
    recorded = {o.step_id for o in res.recorded}
    simulated = {s.step_id for s in res.report.steps if "SIMULATED" in s.path}
    assert recorded == simulated and len(recorded) == 4
    actions = {r.action for r in core(db, lambda svc: svc.execution_records(plan.incident_id))}
    assert "isolate_host" not in actions and not actions & {"wipe_host", "restore_from_backup"}


def test_false_positive_records_nothing(db):
    plan = plans_of(db)["INC-B"]
    before = db_state(db)
    res = record_plan(db, plan.to_json(), recorder_actor_id=executor_id(db))
    assert res.outcomes == [] and db_state(db) == before


def test_only_the_executor_actor_can_record(db):
    plan = plans_of(db)["INC-A"]
    request(db, plan)
    cmd = core(db, lambda svc: svc.store.find_actor(COMMANDER).id)
    res = record_plan(db, plan.to_json(), recorder_actor_id=cmd)
    assert not res.recorded and len(res.refused) == 5
    assert all("is not the executor" in o.reason for o in res.refused)
    assert counts(db) == (0, 0)


def test_authorizations_expired_by_the_core_clock_are_refused(db):
    plan = plans_of(db)["INC-A"]
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    svc = CoreService.open(db, clock=lambda: past)
    try:
        cmd = svc.store.find_actor(COMMANDER)
        for s in plan.steps:
            asset = s.target.value if s.target.kind == "host" else None
            svc.request_action(plan.incident_id, s.action, asset, cmd.id, source="test",
                               params={"plan_step": s.step_id})
    finally:
        svc.conn.close()
    res = record_plan(db, plan.to_json(), recorder_actor_id=executor_id(db))
    assert not res.recorded and all("older than 60 minutes" in o.reason for o in res.refused)
    assert counts(db) == (0, 0)


def test_the_recorder_writes_only_through_record_simulated_execution():
    src = (Path(execution_pkg.__file__).parent / "recorder.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "record_simulated_execution" in attrs
    assert not attrs & (AUTHORITY - {"CoreService"})
    assert not attrs & {"audit", "store", "execute", "executescript", "add_execution_record",
                        "grant_approval", "request_action", "register_actor"}
    others = [p.stem for p in Path(execution_pkg.__file__).parent.glob("*.py")
              if p.stem != "recorder" and "record_simulated_execution" in {
                  n.attr for n in ast.walk(ast.parse(p.read_text(encoding="utf-8")))
                  if isinstance(n, ast.Attribute)}]
    assert others == []


def test_cli_record(db, tmp_path, capsys):
    plan = plans_of(db)["INC-A"]
    request(db, plan)
    f = tmp_path / "plan.json"
    f.write_text(plan.to_json(), encoding="utf-8")
    ex = executor_id(db)
    argv = ["--db", str(db), "simulate", "--plan", str(f), "--record", "--recorder", ex]
    assert main(argv) == 0
    err = capsys.readouterr().err
    assert "recorded 5 simulated execution(s)" in err and "SIMULATION ONLY" in err
    assert main(argv) == 0
    assert "recorded 0 simulated execution(s)" in capsys.readouterr().err
    assert main(["--db", str(db), "simulate", "--plan", str(f), "--record"]) == 2
    assert "--recorder" in capsys.readouterr().err
    cmd = core(db, lambda svc: svc.store.find_actor(COMMANDER).id)
    request(db, plan, plan.steps[:1])
    assert main(["--db", str(db), "simulate", "--plan", str(f), "--record",
                 "--recorder", cmd]) == 1                     # refused record -> exit 1
    capsys.readouterr()


def test_dry_run_is_still_the_default(db, tmp_path, capsys):
    plan = plans_of(db)["INC-A"]
    request(db, plan)
    f = tmp_path / "plan.json"
    f.write_text(plan.to_json(), encoding="utf-8")
    before = db_state(db)
    assert main(["--db", str(db), "simulate", "--plan", str(f)]) == 0
    capsys.readouterr()
    assert db_state(db) == before

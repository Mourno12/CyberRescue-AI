"""CyberRescue Phase 5 — the executor simulates only what the Core authorized."""

import json

import pytest

from cyberrescue.execution import handlers
from cyberrescue.execution.executor import simulate_plan, verify_report
from cyberrescue.execution.model import SimEffect
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.planner import _sha
from tests._execution_factory import approve, plans_of, request
from tests._response_factory import authority_core, writable_copy
from tests.test_investigation_security import db_state


@pytest.fixture(scope="module")
def base(tmp_path_factory):
    return authority_core(tmp_path_factory.mktemp("exec") / "core.db")


@pytest.fixture(scope="module")
def plans(base):
    return plans_of(base)


@pytest.fixture
def db(base, tmp_path):
    return writable_copy(base, tmp_path / "core.db")


def run(db, plan, **kw):
    with open_readonly(db) as ro:
        return simulate_plan(ro, plan if isinstance(plan, str) else plan.to_json(), **kw)


def table(report):
    return [(s.action, s.target.value, s.status, s.block_category) for s in report.steps]


def decisions(report):
    return sorted((d.action, d.target.value, d.status, d.block_category)
                  for d in report.decisions)


# --- nothing authorized ------------------------------------------------------------------

@pytest.mark.parametrize("ref", ["INC-A", "INC-C"])
def test_a_plan_alone_authorizes_nothing(db, plans, ref):
    r = run(db, plans[ref])
    assert r.steps and not [s for s in r.steps if "SIMULATED" in s.path]
    assert {s.block_category for s in r.steps} <= {"authorization", "dependency"}
    assert r.state["authorizations_used"] == 0


def test_false_positive_has_nothing_to_execute(db, plans):
    r = run(db, plans["INC-B"])
    assert r.steps == () and r.decisions == () and r.summary == {}


# --- the Commander requests every step through the Core -----------------------------------

def test_inc_a_permitted_steps_succeed_and_wipe_needs_a_human(db, plans):
    request(db, plans["INC-A"])
    r = run(db, plans["INC-A"])
    assert [s.status for s in r.steps] == ["SUCCEEDED"] * 5
    assert decisions(r) == [("wipe_host", "ws-eng-014", "BLOCKED", "human_decision")]
    assert all(s.authorization and s.authorization.binding == "plan_step" for s in r.steps)


def test_inc_c_approval_gated_steps_are_blocked(db, plans):
    request(db, plans["INC-C"])
    r = run(db, plans["INC-C"])
    assert table(r) == [
        ("notify_stakeholders", None, "SUCCEEDED", None),
        ("isolate_host", "srv-db-01", "BLOCKED", "authorization"),
        ("block_ip", "185.220.101.47", "SUCCEEDED", None),
        ("disable_account", "svc_sqlbackup", "SUCCEEDED", None),
        ("preserve_disk_image", "srv-app-01", "SUCCEEDED", None),
        ("preserve_disk_image", "srv-db-01", "BLOCKED", "dependency"),
        ("kill_process", "srv-db-01", "BLOCKED", "dependency"),
        ("quarantine_file", "srv-db-01", "BLOCKED", "dependency")]
    iso = r.steps[1]
    assert "P5" in iso.reason and iso.current_policy.unmet_rules == ("P5",)
    assert decisions(r) == [("notify_regulator", None, "BLOCKED", "human_decision"),
                            ("restore_from_backup", "srv-db-01", "BLOCKED", "legal_hold"),
                            ("wipe_host", "srv-db-01", "BLOCKED", "legal_hold")]


def test_inc_c_after_human_approvals_all_steps_succeed(db, plans):
    plan = plans["INC-C"]
    for action in ("isolate_host", "kill_process", "quarantine_file"):
        approve(db, plan.incident_id, action, "srv-db-01")
    request(db, plan)
    r = run(db, plan)
    assert [s.status for s in r.steps] == ["SUCCEEDED"] * 8
    iso = r.steps[1]
    assert iso.authorization.approval_id is not None
    assert {d.block_category for d in r.decisions} == {"legal_hold", "human_decision"}


def test_destructive_actions_are_never_simulated_even_when_authorized(db, plans):
    plan = plans["INC-C"]
    approve(db, plan.incident_id, "wipe_host", "srv-db-01", overrides_hold=True,
            reason="GC signed off")
    wipe = next(d for d in plan.decision_points if d.action == "wipe_host")
    [out] = request(db, plan, [wipe])
    assert out.authorized                                  # the Core did authorize it
    r = run(db, plan)
    [w] = [d for d in r.decisions if d.action == "wipe_host"]
    assert w.status == "UNSUPPORTED" and "SIMULATED" not in w.path


# --- integrity ----------------------------------------------------------------------------

def test_an_edited_plan_blocks_every_step(db, plans):
    request(db, plans["INC-A"])
    doc = json.loads(plans["INC-A"].to_json())
    doc["steps"][1]["rationale"] = "edited"
    r = run(db, json.dumps(doc))
    assert not next(c for c in r.plan_integrity if c.check == "plan_hash").passed
    assert {s.block_category for s in r.steps} == {"integrity"}


def test_a_rehashed_forged_step_is_not_supported_by_the_database(db, plans):
    plan = plans["INC-A"]
    request(db, plan)
    iso = next(s for s in plan.steps if s.action == "isolate_host")
    forged_step = iso.model_copy(update={"target": iso.target.model_copy(
        update={"value": "ws-fin-007"})})
    forged = plan.model_copy(update={"steps": tuple(forged_step if s is iso else s
                                                    for s in plan.steps)})
    forged = forged.model_copy(update={"plan_sha256": _sha(forged)})
    r = run(db, forged)
    [x] = [s for s in r.steps if s.step_id == iso.step_id]
    assert x.status == "BLOCKED" and x.block_category == "integrity"


def test_forged_fields_make_the_plan_invalid(db, plans):
    doc = json.loads(plans["INC-A"].to_json())
    doc["steps"][0]["approved"] = True
    with pytest.raises(ValueError, match="not a valid response plan"):
        run(db, json.dumps(doc))
    doc = json.loads(plans["INC-A"].to_json())
    doc["steps"][0]["preview"]["authorizes"] = True
    with pytest.raises(ValueError):
        run(db, json.dumps(doc))


# --- simulator outcomes --------------------------------------------------------------------

def test_a_failed_effect_is_a_failure_and_blocks_dependants(db, plans, monkeypatch):
    plan = plans["INC-A"]
    request(db, plan)
    monkeypatch.setitem(handlers.HANDLERS, "isolate_host",
                        lambda env, step: (env, SimEffect(applied=False, description="fault")))
    r = run(db, plan)
    st = {s.action: s for s in r.steps}
    assert st["isolate_host"].status == "FAILED"
    assert not all(c.satisfied for c in st["isolate_host"].criteria)
    assert st["preserve_disk_image"].block_category == "dependency"


def test_an_unsupported_action_is_never_a_success(db, plans, monkeypatch):
    plan = plans["INC-A"]
    request(db, plan)
    monkeypatch.delitem(handlers.HANDLERS, "notify_stakeholders")
    r = run(db, plan)
    [n] = [s for s in r.steps if s.action == "notify_stakeholders"]
    assert n.status == "UNSUPPORTED" and n.authorization is None
    assert r.state["authorizations_used"] == 4            # its authorization stays unused


# --- determinism, read-only, verification ----------------------------------------------------

def test_runs_are_deterministic_idempotent_and_write_nothing(db, plans):
    request(db, plans["INC-C"])
    before = db_state(db)
    first, second = run(db, plans["INC-C"]), run(db, plans["INC-C"])
    assert first.to_json() == second.to_json() and first.run_id == second.run_id
    assert db_state(db) == before


def test_verify_report(db, plans):
    plan = plans["INC-A"]
    request(db, plan)
    rep = run(db, plan)
    with open_readonly(db) as ro:
        assert verify_report(ro, rep.to_json(), plan.to_json()).ok
        doc = json.loads(rep.to_json())
        doc["steps"][0]["reason"] = "edited"
        res = verify_report(ro, json.dumps(doc), plan.to_json())
        assert not res.ok and any("edited report" in e for e in res.errors)
        assert not verify_report(ro, "{", plan.to_json()).ok
    approve(db, plan.incident_id, "wipe_host", "ws-eng-014")
    with open_readonly(db) as ro:
        res = verify_report(ro, rep.to_json(), plan.to_json())
    assert not res.ok and any("no longer produce" in e for e in res.errors)

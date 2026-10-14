"""CyberRescue Phase 6 — recorded runs are verified against the Core; tampering shows."""

import json
import sqlite3

import pytest

from cyberrescue.execution.cli import main
from cyberrescue.execution.recorder import record_plan
from cyberrescue.execution.records import verify_recorded
from cyberrescue.investigation.readonly import open_readonly
from tests._execution_factory import plans_of, request
from tests._response_factory import writable_copy
from tests.test_execution_recorder import base, executor_id  # noqa: F401 (fixture)


@pytest.fixture
def run(base, tmp_path):  # noqa: F811
    db = writable_copy(base, tmp_path / "core.db")
    plan = plans_of(db)["INC-A"]
    request(db, plan)
    res = record_plan(db, plan.to_json(), recorder_actor_id=executor_id(db))
    assert len(res.recorded) == 5
    return db, plan, res.report


def check(db, report, plan):
    with open_readonly(db) as ro:
        return verify_recorded(ro, report if isinstance(report, str) else report.to_json(),
                               plan.to_json())


def tamper(db, *sql, drop=()):
    conn = sqlite3.connect(db)
    try:
        for t in drop:
            conn.execute(f"DROP TRIGGER {t}")
        for s in sql:
            conn.execute(s)
        conn.commit()
    finally:
        conn.close()


def test_a_recorded_run_verifies(run):
    db, plan, report = run
    res = check(db, report, plan)
    assert res.ok and res.records == 5, res.errors


def test_cli_verifies_recorded_runs(run, tmp_path, capsys):
    db, plan, report = run
    r, p = tmp_path / "r.json", tmp_path / "p.json"
    r.write_text(report.to_json(), encoding="utf-8")
    p.write_text(plan.to_json(), encoding="utf-8")
    assert main(["--db", str(db), "verify", "--report", str(r), "--plan", str(p)]) == 0
    assert "recorded run (5 Core execution record(s)) VERIFIED" in capsys.readouterr().out


def test_an_edited_report_is_detected(run):
    db, plan, report = run
    doc = json.loads(report.to_json())
    doc["steps"][0]["reason"] = "executed for real"
    res = check(db, json.dumps(doc), plan)
    assert not res.ok and any("edited report" in e for e in res.errors)


def test_a_different_plan_is_detected(run):
    db, _, report = run
    other = plans_of(db)["INC-C"]
    res = check(db, report, other)
    assert not res.ok and any("not the one this report" in e for e in res.errors)


@pytest.mark.parametrize("column,value", [("outcome", "failed"), ("step_sha256", "c" * 64),
                                          ("criteria", "[]"), ("plan_id", "PLAN-x")])
def test_a_tampered_record_is_detected(run, column, value):
    db, plan, report = run
    tamper(db, f"UPDATE execution_records SET {column} = '{value}' WHERE rowid = 1",
           drop=("execution_records_no_update",))
    res = check(db, report, plan)
    assert not res.ok and any("differs from the report" in e or "does not match its" in e
                              for e in res.errors)


def test_a_deleted_record_is_detected(run):
    db, plan, report = run
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        tamper(db, "DELETE FROM execution_records")
    tamper(db, "DELETE FROM execution_records WHERE rowid = 1",
           drop=("execution_records_no_delete",))
    res = check(db, report, plan)
    assert not res.ok and any("has no Core execution record" in e for e in res.errors)


def test_tampered_audit_events_break_the_chain(run):
    db, plan, report = run
    tamper(db, "UPDATE audit_events SET payload = replace(payload, '\"succeeded\"', "
               "'\"failed\"') WHERE event_type = 'ACTION_VERIFIED'",
           drop=("audit_events_no_update",))
    res = check(db, report, plan)
    assert not res.ok and "the incident's audit chain does not verify" in res.errors


def test_unrecorded_reports_still_use_the_phase5_check(base, tmp_path, capsys):  # noqa: F811
    db = writable_copy(base, tmp_path / "core.db")
    plan = plans_of(db)["INC-A"]
    request(db, plan)
    r, p = tmp_path / "r.json", tmp_path / "p.json"
    p.write_text(plan.to_json(), encoding="utf-8")
    assert main(["--db", str(db), "simulate", "--plan", str(p), "--out", str(r)]) == 0
    assert main(["--db", str(db), "verify", "--report", str(r), "--plan", str(p)]) == 0
    out = capsys.readouterr().out
    assert "report VERIFIED" in out and "recorded run" not in out

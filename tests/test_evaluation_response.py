"""CyberRescue Phase 4 — plan-level evaluation against ground truth (evaluation only)."""

import json
from dataclasses import replace

import pytest

from cyberrescue.evaluation.cli import main
from cyberrescue.evaluation.response import evaluate_plan, run_plan


@pytest.fixture(scope="module")
def runs():
    return {k: run_plan(k) for k in "ABC"}


def status(ev):
    return {c.check: c.status for c in ev.checks}


@pytest.mark.parametrize("key", list("ABC"))
def test_no_plan_check_mismatches(runs, key):
    ev = evaluate_plan(runs[key])
    assert not [c for c in ev.checks if c.status == "mismatch"], ev.checks


def test_scenario_a_is_fully_evaluated(runs):
    st = status(evaluate_plan(runs["A"]))
    assert st.pop("false_positive_quiet") == "not_evaluated"
    assert set(st.values()) == {"match"}


def test_unknowable_checks_are_not_evaluated_not_passed(runs):
    st = status(evaluate_plan(runs["C"]))
    assert st["quarantined_malware"] == "not_evaluated"      # ground truth names no path
    assert st["benign_hosts_untouched"] == "not_evaluated"   # no benign activity in C
    assert status(evaluate_plan(runs["B"]))["eradication_after_preservation"] == \
        "not_evaluated"


def test_false_positive_is_quiet(runs):
    ev = evaluate_plan(runs["B"])
    assert (ev.steps, ev.decision_points) == (0, 0) and \
        status(ev)["false_positive_quiet"] == "match"


def _mutated(run, steps=None, decisions=None):
    plan = run.plan.model_copy(update={
        "steps": run.plan.steps if steps is None else steps,
        "decision_points": run.plan.decision_points if decisions is None else decisions})
    return replace(run, plan=plan)


def test_a_missing_isolation_is_a_mismatch(runs):
    run = runs["A"]
    st = status(evaluate_plan(_mutated(run, steps=tuple(
        s for s in run.plan.steps if s.action != "isolate_host"))))
    assert st["isolated_hosts"] == "mismatch"


def test_a_step_on_a_benign_host_is_a_mismatch(runs):
    run = runs["A"]
    iso = next(s for s in run.plan.steps if s.action == "isolate_host")
    bad = iso.model_copy(update={"step_id": "STEP-bad", "target": iso.target.model_copy(
        update={"value": "srv-dc-01"})})
    st = status(evaluate_plan(_mutated(run, steps=(*run.plan.steps, bad))))
    assert st["benign_hosts_untouched"] == "mismatch" and st["isolated_hosts"] == "mismatch"


def test_eradication_without_imaging_is_a_mismatch(runs):
    run = runs["A"]
    decisions = tuple(d.model_copy(update={"prerequisites": ()})
                      for d in run.plan.decision_points)
    assert status(evaluate_plan(_mutated(run, decisions=decisions)))[
        "eradication_after_preservation"] == "mismatch"


def test_a_step_without_malicious_evidence_is_a_mismatch(runs):
    run = runs["A"]
    benign = next(i for i, ref in run.refs.items()
                  if ref not in set(run.ground_truth.malicious_event_ids))
    steps = tuple(s.model_copy(update={"evidence_ids": (benign,)})
                  if s.action == "block_ip" else s for s in run.plan.steps)
    assert status(evaluate_plan(_mutated(run, steps=steps)))[
        "steps_cite_malicious_evidence"] == "mismatch"


def test_cli_response_flag_and_json_shape(capsys):
    assert main(["run", "--scenario", "B", "--response", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert set(doc) == {"detection", "response"}
    assert doc["response"][0]["scenario"] == "B" and doc["response"][0]["steps"] == 0
    assert main(["run", "--scenario", "B", "--json"]) == 0      # unchanged default shape
    assert isinstance(json.loads(capsys.readouterr().out), list)
    assert main(["run", "--scenario", "C", "--response"]) == 0
    assert "== Response plan" in capsys.readouterr().out

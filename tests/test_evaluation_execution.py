"""CyberRescue Phase 5 — evaluation of the simulated executor (evaluation only)."""

import json

import pytest

from cyberrescue.evaluation.cli import main
from cyberrescue.evaluation.execution import (
    CATEGORIES,
    evaluate_execution,
    outcome_counts,
    run_execution,
)


@pytest.fixture(scope="module")
def runs():
    return {k: run_execution(k) for k in "ABC"}


def status(ev):
    return {c.check: c.status for c in ev.checks}


@pytest.mark.parametrize("key", list("ABC"))
def test_no_execution_check_mismatches(runs, key):
    ev = evaluate_execution(*runs[key])
    assert not [c for c in ev.checks if c.status == "mismatch"], ev.checks


def test_scenario_a_outcomes_by_category(runs):
    ev = evaluate_execution(*runs["A"])
    assert ev.outcomes["commander_only"] == {
        "succeeded": 4, "blocked_authorization": 1, "blocked_policy": 0,
        "blocked_legal_hold": 2, "blocked_human_decision": 1, "blocked_dependency": 3,
        "blocked_other": 0, "failed_criteria": 0, "unsupported": 0}
    assert ev.outcomes["with_approvals"]["succeeded"] == 8
    assert ev.outcomes["with_approvals"]["blocked_legal_hold"] == 2
    assert status(ev)["approval_gated_not_simulated"] == "match"


def test_false_positive_simulates_nothing(runs):
    ev = evaluate_execution(*runs["B"])
    assert all(v == 0 for o in ev.outcomes.values() for v in o.values())
    assert status(ev)["fp_nothing_simulated"] == "match"


def test_commodity_malware_wipe_is_a_human_decision_not_a_hold(runs):
    ev = evaluate_execution(*runs["C"])
    assert ev.outcomes["commander_only"]["succeeded"] == 5
    assert ev.outcomes["commander_only"]["blocked_human_decision"] == 1
    assert status(ev)["eradication_held"] == "match"


def test_blocked_is_not_failure(runs):
    reports, _, _ = runs["A"]
    counts = outcome_counts(reports["commander_only"])
    assert counts["failed_criteria"] == 0 and counts["blocked_authorization"] == 1
    assert set(counts) == set(CATEGORIES)


def test_a_failed_criterion_is_counted_and_detected(runs):
    reports, gt, plan = runs["A"]
    full = reports["with_approvals"]
    iso = next(s for s in full.steps if s.action == "isolate_host")
    bad_crit = tuple(c.model_copy(update={"satisfied": False}) for c in iso.criteria)
    broken = iso.model_copy(update={"status": "FAILED",
                                    "path": (*iso.path[:-1], "FAILED"), "criteria": bad_crit})
    tampered = full.model_copy(update={"steps": tuple(broken if s is iso else s
                                                      for s in full.steps)})
    ev = evaluate_execution({**reports, "with_approvals": tampered}, gt, plan)
    assert ev.outcomes["with_approvals"]["failed_criteria"] == 1
    st = status(ev)
    assert st["simulated_steps_succeed"] == "mismatch"


def test_a_simulated_destructive_action_would_be_detected(runs):
    reports, gt, plan = runs["A"]
    full = reports["with_approvals"]
    d = full.decisions[0]
    forged = d.model_construct(**{**dict(d), "path": ("PENDING", "CHECKING", "SIMULATED",
                                                      "SUCCEEDED")})
    tampered = full.model_copy(update={"decisions": (forged, *full.decisions[1:])})
    ev = evaluate_execution({**reports, "with_approvals": tampered}, gt, plan)
    assert status(ev)["destructive_never_simulated"] == "mismatch"


def test_cli_execution_flag(capsys):
    assert main(["run", "--scenario", "B", "--execution", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert set(doc) == {"detection", "execution"} and doc["execution"][0]["scenario"] == "B"
    assert main(["run", "--scenario", "C", "--execution"]) == 0
    assert "SIMULATION ONLY" in capsys.readouterr().out

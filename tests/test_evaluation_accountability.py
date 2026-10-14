"""CyberRescue Phase 6 — evaluation of execution accountability (evaluation only)."""

import json
from dataclasses import replace

import pytest

from cyberrescue.evaluation.accountability import evaluate_accountability, run_accountability
from cyberrescue.evaluation.cli import main
from cyberrescue.execution.recorder import RecordOutcome, RecordResult


@pytest.fixture(scope="module")
def runs():
    return {k: run_accountability(k) for k in "ABC"}


def status(ev):
    return {c.check: c.status for c in ev.checks}


@pytest.mark.parametrize("key", list("ABC"))
def test_no_accountability_mismatches(runs, key):
    ev = evaluate_accountability(runs[key])
    assert not [c for c in ev.checks if c.status == "mismatch"], ev.checks


def test_scenario_a_records_every_approved_step_once(runs):
    ev = evaluate_accountability(runs["A"])
    assert (ev.recorded, ev.refused, ev.replayed) == (8, 0, 0)
    assert status(ev)["recorded_run_verifies"] == "match"
    assert {r.action for r in runs["A"].records} >= {"isolate_host", "kill_process",
                                                     "quarantine_file", "block_ip",
                                                     "disable_account"}
    assert not {r.action for r in runs["A"].records} & {"wipe_host", "restore_from_backup",
                                                        "notify_regulator"}


def test_false_positive_records_nothing(runs):
    ev = evaluate_accountability(runs["B"])
    st = status(ev)
    assert ev.recorded == 0 and st["fp_nothing_recorded"] == "match"
    assert st["records_simulated_only"] == st["recorded_run_verifies"] == "not_evaluated"


def test_scenario_c_records_its_five_steps(runs):
    ev = evaluate_accountability(runs["C"])
    assert (ev.recorded, ev.refused, ev.replayed) == (5, 0, 0)


def test_a_replay_that_records_is_a_mismatch(runs):
    run = runs["A"]
    leaky = RecordResult(report=run.replay.report,
                         outcomes=[RecordOutcome("STEP-x", True, "X")])
    assert status(evaluate_accountability(replace(run, replay=leaky)))[
        "replay_records_nothing"] == "mismatch"


def test_a_refused_record_is_a_mismatch(runs):
    run = runs["A"]
    refused = RecordResult(report=run.record.report, outcomes=[
        *run.record.outcomes[1:], RecordOutcome(run.record.outcomes[0].step_id, False,
                                                reason="expired")])
    st = status(evaluate_accountability(replace(run, record=refused)))
    assert st["no_refusals"] == "mismatch" and st["records_match_simulated"] == "mismatch"


def test_cli_accountability_flag(capsys):
    assert main(["run", "--scenario", "B", "--accountability", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert set(doc) == {"detection", "accountability"}
    assert doc["accountability"][0]["recorded"] == 0
    assert main(["run", "--scenario", "C", "--accountability"]) == 0
    assert "5 recorded, 0 refused, 0 on replay" in capsys.readouterr().out

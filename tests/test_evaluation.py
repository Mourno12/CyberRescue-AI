"""CyberRescue Phase 2C — evaluation layer (detection output + ground truth)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cyberrescue.evaluation.cli import main
from cyberrescue.evaluation.harness import run_scenario
from cyberrescue.evaluation.metrics import evaluate

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def runs():
    return {k: run_scenario(k) for k in ("A", "B", "C")}


@pytest.fixture(scope="module")
def evals(runs):
    return {k: evaluate(r) for k, r in runs.items()}


def facts(ev):
    return {f.fact: f.status for f in ev.facts}


def test_a_every_stage_detected_with_full_evidence_coverage(evals):
    ev = evals["A"]
    assert ev.missed_stages == [] and ev.unexpected_findings == []
    assert {s.stage: (s.supported, s.events) for s in ev.stages} == {
        "execution": (2, 2), "inhibit_recovery": (1, 1), "command_and_control": (2, 2),
        "lateral_movement_attempt": (12, 12), "impact": (41, 41)}
    assert (ev.malicious_supported, ev.malicious_events) == (58, 58)
    assert all(s.type_agreement for s in ev.stages)
    assert all(f.malicious_supporting == f.supporting for f in ev.findings)   # precision 1


def test_b_false_positive_has_no_findings(evals):
    ev = evals["B"]
    assert ev.verdict == "false_positive" and ev.findings == [] and ev.stages == []
    assert ev.observations == [("ALERT-001", "uncorroborated_alert"),
                               ("IOC-002", "indicator_observed"),
                               ("NET-001", "suppressed"), ("NET-001", "suppressed")]


def test_c_contained_malware_coverage(evals):
    ev = evals["C"]
    assert ev.missed_stages == [] and ev.unexpected_findings == []
    stages = {s.stage: s for s in ev.stages}
    assert (stages["initial_access"].supported, stages["initial_access"].context_only) == \
        (1, 1)                                    # dropper as support, phishing mail as context
    assert (ev.malicious_supported, ev.malicious_cited_any) == (5, 6)


@pytest.mark.parametrize("key", ["A", "B", "C"])
def test_facts_match_or_are_explicitly_not_evaluated(evals, key):
    statuses = facts(evals[key])
    assert "mismatch" not in statuses.values()
    assert set(statuses.values()) <= {"match", "not_evaluated"}


def test_unevaluable_facts_are_reported_not_passed(evals, runs):
    # Phase 3 (Q6): closed through the investigation layer's gap G1.
    assert facts(evals["A"])["lateral_code_execution_observed"] == "match"
    run = runs["A"]
    unknown = run.ground_truth.model_copy(update={
        "facts": run.ground_truth.facts | {"attacker_motive": "money"}})
    ev = evaluate(run.__class__(**{**run.__dict__, "ground_truth": unknown}))
    assert facts(ev)["attacker_motive"] == "not_evaluated"


def test_metrics_detect_a_regression_against_labels(runs):
    """If the labels disagreed with detection, evaluation must say so."""
    run = runs["A"]
    lat = next(s for s in run.ground_truth.attack_chain if s.stage == "lateral_movement_attempt")
    altered = run.ground_truth.model_copy(update={
        "malicious_event_ids": [i for i in run.ground_truth.malicious_event_ids
                                if i not in lat.event_ids],
        "facts": run.ground_truth.facts | {"lateral_auth_succeeded": []}})
    ev = evaluate(run.__class__(**{**run.__dict__, "ground_truth": altered}))
    assert sorted(ev.unexpected_findings) == ["AUTH-001", "AUTH-002"]
    assert facts(ev)["lateral_auth_succeeded"] == "mismatch"


def test_missed_stage_is_reported(runs):
    run = runs["C"]
    empty = run.report.model_copy(update={"detections": ()})
    ev = evaluate(run.__class__(**{**run.__dict__, "report": empty}))
    assert ev.missed_stages == ["initial_access", "execution", "persistence",
                                "command_and_control"]
    assert facts(ev)["lateral_movement_attempted"] == "match"   # absence is still right
    assert facts(ev)["c2_blocked_by_proxy"] == "mismatch"


def test_evaluation_is_deterministic(runs, evals):
    again = evaluate(run_scenario("B"))
    assert again.to_dict() == evals["B"].to_dict()
    assert evaluate(runs["A"]).to_dict() == evals["A"].to_dict()


def test_cli_json_and_exit_status(capsys):
    code = main(["run", "--scenario", "C", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0 and out[0]["scenario"] == "C" and out[0]["unexpected_findings"] == []


def test_evaluation_reads_ground_truth_but_detection_does_not():
    code = ("import sys\n"
            "import cyberrescue.evaluation.metrics, cyberrescue.evaluation.harness\n"
            "print('cyberrescue.telemetry.ground_truth' in sys.modules)\n")
    res = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True,
                         text=True, check=True)
    assert res.stdout.strip() == "True"
    import cyberrescue.detection.engine as engine
    assert "ground_truth" not in Path(engine.__file__).read_text(encoding="utf-8")

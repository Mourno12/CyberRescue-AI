"""CyberRescue Phase 3 — case-level evaluation against ground truth (evaluation only)."""

import json

import pytest

from cyberrescue.evaluation.cli import main
from cyberrescue.evaluation.investigation import (
    evaluate_case,
    lateral_code_execution_observed,
    run_case,
)
from cyberrescue.investigation.model import Gap


@pytest.fixture(scope="module")
def runs():
    return {k: run_case(k) for k in ("A", "B", "C")}


def checks(ev):
    return {c.check: c for c in ev.checks}


@pytest.mark.parametrize("key", ["A", "B", "C"])
def test_no_case_check_mismatches(runs, key):
    statuses = {c.status for c in evaluate_case(*runs[key]).checks}
    assert "mismatch" not in statuses


def test_a_case_checks(runs):
    c = checks(evaluate_case(*runs["A"]))
    assert (c["scope_compromised"].observed, c["scope_accessed"].observed,
            c["scope_targeted"].observed) == (["srv-db-01"], ["srv-app-01"], ["srv-dc-01"])
    assert c["malicious_events_in_timeline"].observed == "58/58"
    assert c["stage_order"].status == "match"
    assert c["lateral_code_execution"].observed is False
    assert c["false_positive_quiet"].status == "not_evaluated"


def test_b_case_is_quiet(runs):
    c = checks(evaluate_case(*runs["B"]))
    assert c["false_positive_quiet"].status == "match"
    assert c["stage_order"].status == "not_evaluated"
    assert all(c[k].observed == [] for k in ("scope_compromised", "scope_accessed",
                                             "scope_targeted"))


def test_c_stage_order_includes_the_phishing_delivery(runs):
    c = checks(evaluate_case(*runs["C"]))
    assert c["stage_order"].observed == ["initial_access", "execution", "persistence",
                                         "command_and_control"]
    assert c["malicious_events_in_timeline"].observed == "6/6"


def test_checks_flag_label_disagreement(runs):
    case, gt, refs = runs["A"]
    altered = gt.model_copy(update={
        "facts": gt.facts | {"compromised_hosts": ["srv-app-01"],
                             "lateral_code_execution_observed": True},
        "attack_chain": list(reversed(gt.attack_chain))})
    c = checks(evaluate_case(case, altered, refs))
    assert c["scope_compromised"].status == "mismatch"
    assert c["lateral_code_execution"].status == "mismatch"
    assert c["stage_order"].status == "mismatch"


def test_benign_detection_would_be_flagged(runs):
    case, gt, refs = runs["A"]
    malicious_ref = gt.malicious_event_ids[0]
    from cyberrescue.telemetry.ground_truth import BenignExplanation
    altered = gt.model_copy(update={"benign_explanations": [
        *gt.benign_explanations,
        BenignExplanation(explanation="pretend benign", event_ids=[malicious_ref])]})
    assert checks(evaluate_case(case, altered, refs))["benign_never_detected"].observed == 1


def test_lateral_code_execution_derivation():
    g1 = Gap(gap_id="GAP-1", code="G1", title="t", description="d", host="srv-app-01")
    assert lateral_code_execution_observed((), []) is False
    assert lateral_code_execution_observed(("srv-app-01",), [g1]) is False
    assert lateral_code_execution_observed(("srv-app-01", "srv-dc-01"), [g1]) is True


def test_cli_investigation_flag(capsys):
    code = main(["run", "--scenario", "B", "--investigation", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0 and set(out) == {"detection", "investigation"}
    assert out["investigation"][0]["scenario"] == "B"

"""CyberRescue Phase 5 — the execution report model: explicit states, simulation only."""

import pytest
from pydantic import ValidationError

from cyberrescue.execution.model import (
    SIMULATION_DISCLAIMER,
    TRANSITIONS,
    AuthorizationView,
    CriterionResult,
    DecisionResult,
    ExecutionReport,
    SimEffect,
    StepResult,
    valid_path,
)
from cyberrescue.response.model import PolicyPreview, Target

HOST = Target(kind="host", value="srv-db-01", source="inventory")
AUTH = AuthorizationView(request_id="r", decision_id="d", decision_event_uid="e1",
                         authorized_event_uid="e2", binding="asset",
                         requested_by_role="commander", authorized_at="t")
OK = CriterionResult(check="image_recorded", expected="x", satisfied=True, observed="y")
BAD = OK.model_copy(update={"satisfied": False})
EFFECT = SimEffect(applied=True, description="imaged")
PREVIEW = PolicyPreview(as_of="t", outcome_if_requested="REQUIRE_APPROVAL",
                        policy_version="policy-v2", snapshot_hash="0" * 64)
SIM = ("PENDING", "CHECKING", "SIMULATED")


def result(**kw):
    base = {"step_id": "S", "order": 1, "action": "preserve_disk_image", "tier": 1,
            "target": HOST, "status": "SUCCEEDED", "path": (*SIM, "SUCCEEDED"),
            "reason": "r", "authorization": AUTH, "effect": EFFECT, "criteria": (OK,)}
    return StepResult(**{**base, **kw})


def blocked(**kw):
    return result(**{"status": "BLOCKED", "path": ("PENDING", "CHECKING", "BLOCKED"),
                     "block_category": "authorization", "authorization": None,
                     "effect": None, "criteria": (), **kw})


@pytest.mark.parametrize("path,ok", [
    (("PENDING", "CHECKING", "SIMULATED", "SUCCEEDED"), True),
    (("PENDING", "CHECKING", "SIMULATED", "FAILED"), True),
    (("PENDING", "CHECKING", "BLOCKED"), True),
    (("PENDING", "CHECKING", "UNSUPPORTED"), True),
    (("PENDING", "SUCCEEDED"), False),                       # skipped the checks
    (("PENDING", "CHECKING", "SUCCEEDED"), False),           # success without simulation
    (("PENDING", "CHECKING", "BLOCKED", "SIMULATED", "SUCCEEDED"), False),
    (("CHECKING", "SIMULATED", "SUCCEEDED"), False),
    (("PENDING", "CHECKING", "SIMULATED"), False),           # not terminal
    ((), False)])
def test_state_paths(path, ok):
    assert valid_path(path) is ok


def test_terminal_states_have_no_exits():
    assert not set(TRANSITIONS) & {"SUCCEEDED", "FAILED", "BLOCKED", "UNSUPPORTED"}


def test_valid_results():
    assert result().status == "SUCCEEDED"
    assert result(status="FAILED", path=(*SIM, "FAILED"), criteria=(BAD,)).status == "FAILED"
    assert blocked().block_category == "authorization"


def test_status_must_match_the_path():
    with pytest.raises(ValidationError, match="invalid state path"):
        result(status="SUCCEEDED", path=("PENDING", "CHECKING", "BLOCKED"))


def test_success_requires_every_criterion():
    with pytest.raises(ValidationError, match="every success criterion"):
        result(criteria=(OK, BAD))
    with pytest.raises(ValidationError, match="every success criterion"):
        result(criteria=())


def test_failure_requires_a_reason_to_fail():
    with pytest.raises(ValidationError, match="unmet criterion"):
        result(status="FAILED", path=(*SIM, "FAILED"), criteria=(OK,))
    assert result(status="FAILED", path=(*SIM, "FAILED"), criteria=(OK,),
                  effect=SimEffect(applied=False, description="not found"))


def test_simulation_requires_a_core_authorization():
    with pytest.raises(ValidationError, match="Core authorization"):
        result(authorization=None)


def test_blocked_needs_a_category_and_carries_no_effect():
    with pytest.raises(ValidationError, match="block_category"):
        blocked(block_category=None)
    with pytest.raises(ValidationError, match="only simulated steps"):
        blocked(effect=EFFECT)
    with pytest.raises(ValidationError, match="block_category"):
        result(block_category="policy")


def test_decisions_are_never_simulated():
    d = DecisionResult(decision_id="D", action="wipe_host", tier=3, target=HOST,
                       status="BLOCKED", path=("PENDING", "CHECKING", "BLOCKED"),
                       block_category="legal_hold", reason="r", current_policy=PREVIEW)
    assert d.status == "BLOCKED"
    with pytest.raises(ValidationError):
        DecisionResult(**{**d.model_dump(), "status": "SUCCEEDED",
                          "path": (*SIM, "SUCCEEDED"), "block_category": None})


def test_report_is_simulation_only():
    r = ExecutionReport(run_id="RUN", incident_id="I", plan_id="P", plan_sha256="0",
                        plan_integrity=(), as_of="t")
    assert r.simulation is True and r.disclaimer == SIMULATION_DISCLAIMER
    for field, value in (("simulation", False), ("disclaimer", "Executed for real.")):
        with pytest.raises(ValidationError):
            ExecutionReport(**{**r.model_dump(), field: value})
    with pytest.raises(ValidationError):
        ExecutionReport(**{**r.model_dump(), "approved": True})
    assert "report_sha256" not in r.content()

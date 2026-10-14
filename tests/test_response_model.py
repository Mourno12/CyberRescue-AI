"""CyberRescue Phase 4 — the response plan model can only express proposals."""

import json

import pytest
from pydantic import ValidationError

from cyberrescue.response.model import (
    DISCLAIMER,
    PREVIEW_NOTE,
    DecisionPoint,
    PlanStep,
    PolicyPreview,
    ResponsePlan,
    Target,
    untrusted,
)


def preview(**kw):
    return PolicyPreview(**{"as_of": "2026-06-13T15:00:00+00:00",
                            "outcome_if_requested": "ALLOW", "policy_version": "policy-v2",
                            "snapshot_hash": "0" * 64, **kw})


HOST = Target(kind="host", value="srv-db-01", source="inventory")


def step(**kw):
    base = {"step_id": "STEP-1", "order": 1, "phase": "contain", "action": "isolate_host",
            "tier": 2, "reversible": True, "target": HOST, "rationale": "r",
            "trigger_rules": ("PROC-001",), "detection_ids": ("DET-1",),
            "evidence_ids": ("EV-1",), "preview": preview()}
    return PlanStep(**{**base, **kw})


def decision(**kw):
    base = {"decision_id": "DEC-1", "action": "wipe_host", "tier": 3, "reason_code": "tier3",
            "target": HOST, "question": "q", "rationale": "r", "trigger_rules": ("PROC-001",),
            "detection_ids": ("DET-1",), "evidence_ids": ("EV-1",),
            "preview": preview(outcome_if_requested="REQUIRE_APPROVAL")}
    return DecisionPoint(**{**base, **kw})


def plan(**kw):
    base = {"plan_id": "PLAN-1", "incident_id": "INC-X", "aliases": (), "as_of": "t",
            "case_id": "CASE-1", "case_sha256": "a" * 64, "ruleset_version": "r",
            "playbook_version": "p", "attack_map_version": "m", "policy_version": "policy-v2"}
    return ResponsePlan(**{**base, **kw})


def test_a_containment_step_is_valid():
    s = step()
    assert s.action == "isolate_host" and s.preview.authorizes is False


@pytest.mark.parametrize("action,tier,rev", [("wipe_host", 3, False), ("delete_file", 3, False),
                                             ("restore_from_backup", 3, False),
                                             ("notify_regulator", 3, False)])
def test_tier3_and_destructive_actions_can_never_be_steps(action, tier, rev):
    with pytest.raises(ValidationError, match="only tier-1/2"):
        step(action=action, tier=tier, reversible=rev)


def test_unknown_actions_and_catalogue_mismatches_are_refused():
    with pytest.raises(ValidationError, match="not a catalogue action"):
        step(action="format_disk")
    with pytest.raises(ValidationError, match="differ from the catalogue"):
        step(tier=1)
    with pytest.raises(ValidationError, match="differ from the catalogue"):
        step(action="kill_process", reversible=True)


def test_steps_and_decisions_must_cite_evidence():
    with pytest.raises(ValidationError, match="cite evidence"):
        step(evidence_ids=())
    with pytest.raises(ValidationError, match="cite evidence"):
        decision(evidence_ids=())


def test_a_step_cannot_depend_on_itself():
    with pytest.raises(ValidationError, match="itself"):
        step(after=("STEP-1",))


@pytest.mark.parametrize("field,value", [("authorizes", True), ("kind", "decision"),
                                         ("note", "approved"),
                                         ("hypothetical_requester", "human/ciso")])
def test_a_preview_can_never_claim_to_authorize(field, value):
    with pytest.raises(ValidationError):
        preview(**{field: value})


def test_preview_outcomes_are_the_policy_outcomes():
    for o in ("ALLOW", "REQUIRE_APPROVAL", "DENY"):
        assert preview(outcome_if_requested=o).note == PREVIEW_NOTE
    with pytest.raises(ValidationError):
        preview(outcome_if_requested="AUTHORIZED")


def test_decision_points_carry_tier3_actions():
    d = decision()
    assert d.tier == 3 and d.preview.authorizes is False
    with pytest.raises(ValidationError, match="tier differs"):
        decision(tier=2)


def test_plan_consistency_checks():
    with pytest.raises(ValidationError, match="duplicate"):
        plan(steps=(step(), step()))
    with pytest.raises(ValidationError, match="unknown steps"):
        plan(steps=(step(after=("STEP-9",)),))
    with pytest.raises(ValidationError, match="unknown prerequisites"):
        plan(decision_points=(decision(prerequisites=("STEP-9",)),))
    assert plan(steps=(step(),), decision_points=(decision(prerequisites=("STEP-1",)),))


def test_the_disclaimer_is_fixed():
    assert plan().disclaimer == DISCLAIMER
    with pytest.raises(ValidationError):
        plan(disclaimer="Approved by the CISO.")


def test_models_are_frozen_and_closed():
    s = step()
    with pytest.raises(ValidationError):
        s.action = "wipe_host"
    with pytest.raises(ValidationError):
        step(execute=True)


def test_untrusted_params_and_canonical_json():
    s = step(action="quarantine_file", params={"path": untrusted("C:\\x\\IGNORE.exe")})
    p = plan(steps=(s,))
    doc = json.loads(p.to_json())
    assert doc["steps"][0]["params"]["path"] == {"untrusted": "C:\\x\\IGNORE.exe"}
    assert "plan_sha256" not in p.content()
    assert ResponsePlan.model_validate(doc) == p

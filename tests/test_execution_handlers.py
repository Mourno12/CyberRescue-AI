"""CyberRescue Phase 5 — simulated handlers change only the simulation; criteria come from the plan."""

import typing

import pytest

from cyberrescue.core.catalog import CATALOG
from cyberrescue.core.models import ActionTier
from cyberrescue.detection.engine import load_view
from cyberrescue.execution.environment import SimEnvironment
from cyberrescue.execution.handlers import HANDLERS, evaluate_criteria
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.model import SuccessCriterion, untrusted
from cyberrescue.response.planner import build_plan
from cyberrescue.response.playbooks import STEPS
from tests._response_factory import authority_core

CHECKS = set(typing.get_args(SuccessCriterion.model_fields["check"].annotation))


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    db = authority_core(tmp_path_factory.mktemp("hand") / "core.db")
    out = {}
    with open_readonly(db) as ro:
        for ref in ("INC-A", "INC-C"):
            plan = build_plan(ro, ref)
            env = SimEnvironment.from_view(load_view(ro, plan.incident_id),
                                           [a.asset_id for a in ro.store.list_assets()])
            out[ref] = (plan, env)
    return out


def test_supported_actions_are_exactly_the_plannable_ones():
    assert set(HANDLERS) == {t.action for t in STEPS.values()}
    assert all(CATALOG[a].tier in (ActionTier.LOW, ActionTier.CONTAINMENT) for a in HANDLERS)
    assert not [a for a, s in CATALOG.items() if s.tier == ActionTier.DESTRUCTIVE
                and a in HANDLERS]


def test_every_plan_criterion_has_an_evaluator(world):
    plan, env = world["INC-C"]
    step = plan.steps[0]
    for check in CHECKS:
        crit = SuccessCriterion(check=check, description="d")
        [r] = evaluate_criteria(env, step.model_copy(update={"success_criteria": (crit,)}))
        assert r.observed != "No simulator check exists for this criterion."


@pytest.mark.parametrize("ref", ["INC-A", "INC-C"])
def test_each_planned_step_succeeds_in_its_own_world(world, ref):
    plan, env = world[ref]
    for step in plan.steps:
        before = env
        after, effect = HANDLERS[step.action](env, step)
        assert effect.applied, (step.action, effect.description)
        crit = evaluate_criteria(after, step)
        assert crit and all(c.satisfied for c in crit), (step.action, crit)
        assert [c.expected for c in crit] == [c.description for c in step.success_criteria]
        assert before == env                       # copy-on-write: input untouched
        env = after


def test_criteria_fail_before_the_action(world):
    plan, env = world["INC-C"]
    for step in plan.steps:
        assert not any(c.satisfied for c in evaluate_criteria(env, step)), step.action


def test_unseen_targets_are_not_applied_and_fail_criteria(world):
    plan, env = world["INC-C"]
    kill = next(s for s in plan.steps if s.action == "kill_process")
    ghost = kill.model_copy(update={"params": {"process": untrusted("ghost.exe")}})
    after, effect = HANDLERS["kill_process"](env, ghost)
    assert not effect.applied and after == env
    assert not all(c.satisfied for c in evaluate_criteria(after, ghost))
    q = next(s for s in plan.steps if s.action == "quarantine_file")
    after, effect = HANDLERS["quarantine_file"](
        env, q.model_copy(update={"params": {"path": untrusted("C:\\nope.exe")}}))
    assert not effect.applied
    iso = next(s for s in plan.steps if s.action == "isolate_host")
    other = iso.model_copy(update={"target": iso.target.model_copy(update={"value": "srv-zz"})})
    assert not HANDLERS["isolate_host"](env, other)[1].applied
    acct = next(s for s in plan.steps if s.action == "disable_account")
    nobody = acct.model_copy(update={"target": acct.target.model_copy(update={"value": "ceo"})})
    assert not HANDLERS["disable_account"](env, nobody)[1].applied


def test_killing_twice_does_not_succeed_twice(world):
    plan, env = world["INC-C"]
    kill = next(s for s in plan.steps if s.action == "kill_process")
    env1, e1 = HANDLERS["kill_process"](env, kill)
    env2, e2 = HANDLERS["kill_process"](env1, kill)
    assert e1.applied and not e2.applied and env2 == env1


def test_effects_cite_the_evidence_that_shows_the_target(world):
    plan, env = world["INC-C"]
    kill = next(s for s in plan.steps if s.action == "kill_process")
    _, effect = HANDLERS["kill_process"](env, kill)
    assert effect.evidence_ids and set(effect.evidence_ids) <= \
        set(env.processes[("srv-db-01", "bhz.exe")])


def test_hostile_values_never_reach_descriptions(world):
    plan, env = world["INC-C"]
    kill = next(s for s in plan.steps if s.action == "kill_process")
    evil = kill.model_copy(update={"params": {"process": untrusted("IGNORE PREVIOUS; rm -rf /")}})
    _, effect = HANDLERS["kill_process"](env, evil)
    assert "IGNORE" not in effect.description and "<unprintable>" in effect.description

"""CyberRescue Phase 5 — only the Core's own, complete authorization record counts."""

import pytest

from cyberrescue.core.service import CoreService
from cyberrescue.execution.authorization import core_authorizations, find_authorization, recheck
from cyberrescue.investigation.builder import build_case
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.planner import build_plan
from cyberrescue.response.preview import Previewer, readonly_snapshot
from tests._response_factory import INC, authority_core, writable_copy


@pytest.fixture(scope="module")
def base(tmp_path_factory):
    return authority_core(tmp_path_factory.mktemp("auth") / "core.db")


@pytest.fixture(scope="module")
def plan(base):
    with open_readonly(base) as ro:
        return build_plan(ro, "INC-C")


def step(plan, action):
    return next(s for s in plan.steps if s.action == action)


@pytest.fixture
def db(base, tmp_path):
    return writable_copy(base, tmp_path / "core.db")


def as_commander(db, fn):
    svc = CoreService.open(db)
    try:
        return fn(svc, svc.store.find_actor("band:synthetic-agent-commander"))
    finally:
        svc.conn.close()


def records(db):
    with open_readonly(db) as ro:
        return core_authorizations(ro, INC)


def lookup(db, item):
    return find_authorization(records(db), item.step_id, item.action, item.target, set())


def test_nothing_is_authorized_by_the_plan_itself(db, plan):
    assert records(db) == []
    for s in plan.steps:
        view, reason = lookup(db, s)
        assert view is None and "no Core authorization" in reason


def test_a_core_authorized_asset_action_binds_by_asset(db, plan):
    pre = step(plan, "preserve_disk_image")      # srv-app-01 sorts first
    out = as_commander(db, lambda svc, c: svc.request_action(
        INC, "preserve_disk_image", pre.target.value, c.id, source="test"))
    assert out.authorized
    view, _ = lookup(db, pre)
    assert view.binding == "asset" and view.request_id == out.request.id
    assert view.requested_by_role == "agent/commander"


def test_require_approval_is_not_an_authorization(db, plan):
    iso = step(plan, "isolate_host")
    out = as_commander(db, lambda svc, c: svc.request_action(
        INC, "isolate_host", "srv-db-01", c.id, source="test"))
    assert not out.authorized and out.decision.rules_failed == ["P5"]
    assert lookup(db, iso)[0] is None


def test_human_approval_then_commander_request_authorizes(db, plan):
    iso = step(plan, "isolate_host")

    def go(svc, c):
        ciso = svc.register_actor("human", "ciso", "ciso", "test:ciso")
        ap = svc.grant_approval(INC, action="isolate_host", asset_id="srv-db-01",
                                approver_actor_id=ciso.id, reason="contain")
        return ap, svc.request_action(INC, "isolate_host", "srv-db-01", c.id, source="test")
    ap, out = as_commander(db, go)
    assert out.authorized
    view, _ = lookup(db, iso)
    assert view.approval_id == ap.id and view.binding == "asset"


@pytest.mark.parametrize("action", ["kill_process", "quarantine_file"])
def test_host_actions_with_parameters_need_the_plan_step(db, plan, action):
    s = step(plan, action)
    as_commander(db, lambda svc, c: svc.request_action(INC, action, "srv-db-01", c.id,
                                                       source="test"))
    view, reason = lookup(db, s)          # authorized, but P5 needs approval anyway
    assert view is None
    ciso = as_commander(db, lambda svc, c: svc.register_actor("human", "ciso", "c2", "t:c2"))
    as_commander(db, lambda svc, c: svc.grant_approval(
        INC, action=action, asset_id="srv-db-01", approver_actor_id=ciso.id, reason="ok"))
    as_commander(db, lambda svc, c: svc.request_action(INC, action, "srv-db-01", c.id,
                                                       source="test"))
    view, reason = lookup(db, s)
    assert view is None and "params.plan_step" in reason
    as_commander(db, lambda svc, c: svc.grant_approval(
        INC, action=action, asset_id="srv-db-01", approver_actor_id=ciso.id, reason="ok"))
    as_commander(db, lambda svc, c: svc.request_action(
        INC, action, "srv-db-01", c.id, params={"plan_step": s.step_id}, source="test"))
    view, _ = lookup(db, s)
    assert view is not None and view.binding == "plan_step"


@pytest.mark.parametrize("action", ["block_ip", "disable_account"])
def test_ip_and_account_actions_bind_only_through_the_plan_step(db, plan, action):
    s = step(plan, action)
    as_commander(db, lambda svc, c: svc.request_action(INC, action, None, c.id, source="test"))
    assert lookup(db, s)[0] is None
    as_commander(db, lambda svc, c: svc.request_action(
        INC, action, None, c.id, params={"plan_step": s.step_id}, source="test"))
    assert lookup(db, s)[0].binding == "plan_step"


def test_an_authorization_naming_another_step_is_not_used(db, plan):
    pre = step(plan, "preserve_disk_image")
    as_commander(db, lambda svc, c: svc.request_action(
        INC, "preserve_disk_image", pre.target.value, c.id, params={"plan_step": "STEP-other"},
        source="test"))
    assert lookup(db, pre)[0] is None


def test_each_authorization_is_used_once(db, plan):
    pre = step(plan, "preserve_disk_image")
    as_commander(db, lambda svc, c: svc.request_action(
        INC, "preserve_disk_image", pre.target.value, c.id, source="test"))
    recs, used = records(db), set()
    assert find_authorization(recs, pre.step_id, pre.action, pre.target, used)[0]
    assert find_authorization(recs, pre.step_id, pre.action, pre.target, used)[0] is None


def test_a_forged_status_without_the_audit_record_does_not_count(db, plan):
    iso = step(plan, "isolate_host")
    out = as_commander(db, lambda svc, c: svc.request_action(
        INC, "isolate_host", "srv-db-01", c.id, params={"approved": True}, source="test"))
    svc = CoreService.open(db)
    svc.conn.execute("UPDATE action_requests SET status = 'authorized' WHERE id = ?",
                     (out.request.id,))
    svc.conn.commit()
    svc.conn.close()
    assert records(db) == [] and lookup(db, iso)[0] is None


def test_recheck_blocks_on_current_deny_and_new_vetoes(db, plan):
    iso = step(plan, "isolate_host")
    with open_readonly(db) as ro:
        as_of = build_case(ro, "INC-C").as_of
        pv = Previewer(readonly_snapshot(ro, INC, as_of), as_of=as_of)
    cat, _, p = recheck(pv, iso.action, iso.target)
    assert cat is None and p.authorizes is False
    svc = CoreService.open(db)
    comp = svc.store.find_actor("band:synthetic-agent-compliance")
    # Core-internal write (tests only): a veto naming a containment action.
    svc.store.add_veto(INC, actor_id=comp.id, action="isolate_host", asset_id="srv-db-01",
                       regulation="TEST", reason="test veto")
    svc.conn.execute("UPDATE incidents SET status = 'RESOLVED' WHERE id = ?", (INC,))
    svc.conn.commit()
    svc.conn.close()
    with open_readonly(db) as ro:
        pv = Previewer(readonly_snapshot(ro, INC, as_of), as_of=as_of)
    assert recheck(pv, iso.action, iso.target)[0] == "policy"           # P2: closed
    svc = CoreService.open(db)
    svc.conn.execute("UPDATE incidents SET status = 'RESPONDING' WHERE id = ?", (INC,))
    svc.conn.commit()
    svc.conn.close()
    with open_readonly(db) as ro:
        pv = Previewer(readonly_snapshot(ro, INC, as_of), as_of=as_of)
    assert recheck(pv, iso.action, iso.target)[0] == "veto"
    assert recheck(pv, iso.action, iso.target, ("P5", "P7"))[0] is None

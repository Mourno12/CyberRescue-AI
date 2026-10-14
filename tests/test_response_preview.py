"""CyberRescue Phase 4 — a policy preview is the policy engine's answer, recorded nowhere."""

from datetime import datetime, timedelta

import pytest

from cyberrescue.core.models import IncidentStatus
from cyberrescue.core.service import CoreService
from cyberrescue.investigation.builder import build_case
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.preview import HYPOTHETICAL_COMMANDER, Previewer, readonly_snapshot
from tests._response_factory import INC, authority_core, writable_copy
from tests.test_investigation_security import db_state

ACTIONS = [("isolate_host", "srv-db-01"), ("preserve_disk_image", "srv-db-01"),
           ("wipe_host", "srv-db-01"), ("block_ip", "185.220.101.47"),
           ("disable_account", "svc_sqlbackup"), ("notify_stakeholders", None),
           ("notify_regulator", None), ("kill_process", "srv-db-01"),
           ("preserve_disk_image", "srv-app-01"), ("restore_from_backup", "srv-db-01")]
KIND = {"block_ip": "ip", "disable_account": "account", "notify_stakeholders": "none",
        "notify_regulator": "none"}


@pytest.fixture(scope="module")
def dbp(tmp_path_factory):
    return authority_core(tmp_path_factory.mktemp("preview") / "core.db")


@pytest.fixture(scope="module")
def as_of(dbp):
    with open_readonly(dbp) as ro:
        return build_case(ro, "INC-C").as_of


def previewer(path, as_of):
    with open_readonly(path) as ro:
        return Previewer(readonly_snapshot(ro, INC, as_of), as_of=as_of)


def test_readonly_snapshot_equals_the_core_snapshot(dbp, as_of):
    with open_readonly(dbp) as ro:
        mine = readonly_snapshot(ro, INC, as_of)
    svc = CoreService.open(dbp)
    try:
        theirs = svc.store.snapshot(INC, now=datetime.fromisoformat(as_of))
    finally:
        svc.conn.close()
    assert mine.model_dump() == theirs.model_dump()
    assert mine.signoff_request is not None and mine.holds


@pytest.mark.parametrize("action,target", ACTIONS, ids=lambda x: str(x))
def test_preview_matches_a_live_request_by_the_commander(dbp, as_of, tmp_path, action, target):
    kind = KIND.get(action, "host")
    p = previewer(dbp, as_of).preview(action, target, kind=kind)
    asset = target if kind == "host" else None
    assert p.evaluated_asset_id == asset
    copy = writable_copy(dbp, tmp_path / "live.db")
    svc = CoreService.open(copy, clock=lambda: datetime.fromisoformat(as_of))
    try:
        cmd = svc.store.find_actor("band:synthetic-agent-commander")
        live = svc.request_action(INC, action, asset, cmd.id, source="test",
                                  params={"target": target}).decision
    finally:
        svc.conn.close()
    assert p.outcome_if_requested == live.outcome.value
    assert list(p.unmet_rules) == live.rules_failed
    assert [r.rule for r in p.rule_results] == [r.rule for r in live.rule_results]


def test_expected_previews_on_inc_c(dbp, as_of):
    pv = previewer(dbp, as_of)
    got = {(a, t): (p.outcome_if_requested, p.unmet_rules) for a, t in ACTIONS
           for p in [pv.preview(a, t, kind=KIND.get(a, "host"))]}
    assert got[("wipe_host", "srv-db-01")] == ("REQUIRE_APPROVAL", ("P6", "P8"))
    assert got[("isolate_host", "srv-db-01")] == ("REQUIRE_APPROVAL", ("P5",))
    assert got[("preserve_disk_image", "srv-db-01")] == ("ALLOW", ())
    assert got[("notify_regulator", None)] == ("REQUIRE_APPROVAL", ("P6",))


def test_preview_is_labelled_and_never_authorizes(dbp, as_of):
    p = previewer(dbp, as_of).preview("preserve_disk_image", "srv-db-01")
    assert p.outcome_if_requested == "ALLOW"
    assert p.kind == "policy_preview" and p.authorizes is False
    assert p.hypothetical_requester == "agent/commander" and "not an authorization" in p.note
    assert p.as_of == as_of and p.policy_version == "policy-v2" and len(p.snapshot_hash) == 64


def test_previews_write_nothing_and_register_no_one(dbp, as_of):
    before = db_state(dbp)
    pv = previewer(dbp, as_of)
    for a, t in ACTIONS:
        pv.preview(a, t, kind=KIND.get(a, "host"))
    assert db_state(dbp) == before
    with open_readonly(dbp) as ro:
        assert ro.store.get_actor(HYPOTHETICAL_COMMANDER.id) is None
        assert ro.store.find_actor("hypothetical:commander") is None


def test_preview_reflects_a_human_approval_valid_at_as_of(dbp, as_of, tmp_path):
    copy = writable_copy(dbp, tmp_path / "appr.db")
    t0 = datetime.fromisoformat(as_of)
    svc = CoreService.open(copy, clock=lambda: t0)
    ciso = svc.store.find_actor("band:synthetic-human-ciso") or svc.register_actor(
        "human", "ciso", "ciso", "test:ciso")
    svc.grant_approval(INC, action="wipe_host", asset_id="srv-db-01", approver_actor_id=ciso.id,
                       reason="image verified; GC sign-off", overrides_hold=True, ttl_minutes=30)
    svc.conn.close()
    with open_readonly(copy) as ro:
        later = build_case(ro, "INC-C").as_of           # the approval moved as_of
        now = Previewer(readonly_snapshot(ro, INC, later), as_of=later).preview(
            "wipe_host", "srv-db-01")
        late = (t0 + timedelta(hours=2)).isoformat()
        expired = Previewer(readonly_snapshot(ro, INC, late), as_of=late).preview(
            "wipe_host", "srv-db-01")
    assert now.outcome_if_requested == "ALLOW" and now.authorizes is False
    assert expired.outcome_if_requested == "REQUIRE_APPROVAL"


def test_closed_incident_previews_deny(dbp, as_of, tmp_path):
    copy = writable_copy(dbp, tmp_path / "closed.db")
    svc = CoreService.open(copy)
    svc.conn.execute("UPDATE incidents SET status = ? WHERE id = ?",
                     (IncidentStatus.RESOLVED.value, INC))
    svc.conn.close()
    p = previewer(copy, as_of).preview("isolate_host", "srv-db-01")
    assert p.outcome_if_requested == "DENY" and "P2" in p.unmet_rules


def test_rule_reasons_are_untrusted(dbp, as_of):
    p = previewer(dbp, as_of).preview("wipe_host", "srv-db-01")
    assert p.rule_results and all(set(r.reason.model_dump()) == {"untrusted"}
                                  for r in p.rule_results)


def test_the_core_can_only_record_inventory_targets(dbp, tmp_path):
    """Documents the Core limitation the preview mirrors: an ip/account target
    cannot be stored as an action request's asset id (inventory foreign key)."""
    import sqlite3
    copy = writable_copy(dbp, tmp_path / "fk.db")
    svc = CoreService.open(copy)
    try:
        cmd = svc.store.find_actor("band:synthetic-agent-commander")
        with pytest.raises(sqlite3.IntegrityError):
            svc.request_action(INC, "block_ip", "185.220.101.47", cmd.id, source="test")
    finally:
        svc.conn.close()

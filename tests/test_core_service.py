"""CyberRescue Core — CoreService trust boundary (cyberrescue/core/service.py)."""

from datetime import datetime, timedelta, timezone

import pytest

from cyberrescue.core import db
from cyberrescue.core.models import (
    ActionStatus,
    Actor,
    ActorKind,
    EventType,
    IncidentStatus,
    PolicyOutcome,
)
from cyberrescue.core.policy import PolicyConfig
from cyberrescue.core.service import ApprovalError, CoreError, CoreService


class Clock:
    def __init__(self):
        self.t = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def svc(tmp_path, clock):
    s = CoreService(db.connect(tmp_path / "core.db"), config=PolicyConfig(), clock=clock)
    s.seed_assets_from_mock()
    yield s
    s.conn.close()


@pytest.fixture
def team(svc):
    return {
        "triage": svc.register_actor("agent", "triage", "triage", "band:t"),
        "intel": svc.register_actor("agent", "threat_intel", "intel", "band:ti"),
        "compliance": svc.register_actor("agent", "compliance", "compliance", "band:c"),
        "commander": svc.register_actor("agent", "commander", "commander", "band:cmd"),
        "ciso": svc.register_actor("human", "ciso", "CISO", "band:human-1"),
        "observer": svc.register_actor("human", "observer", "intern", "band:human-2"),
    }


def _inc_c(svc):
    return svc.open_incident("INC-C-2026-0042", title="ransomware",
                             primary_asset_id="srv-db-01",
                             recruited_roles=["threat_intel", "compliance", "commander"])


def _types(svc, iid):
    return [e.event_type for e in svc.audit.events(iid)]


def test_open_incident_places_deterministic_legal_hold(svc):
    inc = _inc_c(svc)
    holds = svc.store.active_holds("srv-db-01")
    assert len(holds) == 1 and holds[0].requires_human_authorization
    assert "LEGAL_HOLD_PLACED" in _types(svc, inc.id)
    ws = svc.open_incident("INC-A-2026-0039", primary_asset_id="ws-eng-014",
                           recruited_roles=["threat_intel", "commander"])
    assert svc.store.active_holds("ws-eng-014") == []
    assert "LEGAL_HOLD_PLACED" not in _types(svc, ws.id)


def test_blocked_request_is_persisted_with_decision_and_links(svc, team):
    inc = _inc_c(svc)
    out = svc.request_action(inc.id, "wipe_host", "srv-db-01", team["commander"])
    assert out.decision.outcome == PolicyOutcome.REQUIRE_APPROVAL and not out.authorized
    assert out.request.status == ActionStatus.REQUIRES_APPROVAL
    assert _types(svc, inc.id)[-3:] == ["ACTION_PROPOSED", "POLICY_DECISION",
                                        "APPROVAL_REQUESTED"]
    dec = svc.audit.get(out.decision.event_uid)
    rels = {(link.relation, link.target_uid) for link in dec.links}
    assert ("evaluates", out.request.event_uid) in rels
    hold_uid = svc.store.active_holds("srv-db-01")[0].event_uid
    assert ("blocked_by", hold_uid) in rels
    assert svc.verify_audit(inc.id).ok


def test_only_a_registered_human_approver_can_grant(svc, team):
    inc = _inc_c(svc)
    kw = dict(action="isolate_host", asset_id="srv-db-01", reason="contain")
    with pytest.raises(ApprovalError, match="not registered"):
        svc.grant_approval(inc.id, approver_actor_id="made-up-id", **kw)
    with pytest.raises(ApprovalError, match="must be a human"):
        svc.grant_approval(inc.id, approver_actor_id=team["commander"].id, **kw)
    with pytest.raises(ApprovalError, match="may not approve"):
        svc.grant_approval(inc.id, approver_actor_id=team["observer"].id, **kw)
    with pytest.raises(ApprovalError, match="reason is required"):
        svc.grant_approval(inc.id, approver_actor_id=team["ciso"].id, action="wipe_host",
                           asset_id="srv-db-01", reason=" ", overrides_hold=True)
    with pytest.raises(CoreError, match="unknown action"):
        svc.grant_approval(inc.id, approver_actor_id=team["ciso"].id, action="nuke",
                           asset_id="srv-db-01", reason="x")
    assert svc.store.unconsumed_approvals(inc.id) == []


def test_fabricated_actor_objects_are_not_trusted(svc, team):
    inc = _inc_c(svc)
    fake = Actor(id="not-in-db", kind=ActorKind.AGENT, role="commander")
    with pytest.raises(ApprovalError, match="not registered"):
        svc.request_action(inc.id, "notify_stakeholders", None, fake)
    # A registered agent whose object is "re-roled" in memory is re-loaded from the DB.
    spoofed = team["intel"].model_copy(update={"role": "commander"})
    out = svc.request_action(inc.id, "notify_stakeholders", None, spoofed)
    assert out.decision.outcome == PolicyOutcome.DENY and "P1" in out.decision.rules_failed


def test_approval_is_single_use_and_expires(svc, team, clock):
    inc = _inc_c(svc)
    svc.record_signoff_request(inc.id, team["commander"], ["isolate_host"])
    svc.record_signoff(inc.id, team["intel"])
    svc.record_signoff(inc.id, team["compliance"])
    ap = svc.grant_approval(inc.id, action="isolate_host", asset_id="srv-db-01",
                            approver_actor_id=team["ciso"].id, reason="contain now")
    assert ap.expires_at == (clock.t + timedelta(minutes=60)).isoformat()
    first = svc.request_action(inc.id, "isolate_host", "srv-db-01", team["commander"])
    assert first.authorized and first.decision.approval_id == ap.id
    assert svc.store.get_approval(ap.id).consumed_by_request_id == first.request.id
    auth = svc.audit.get(first.authorization_event_uid)
    assert ("consumes", ap.event_uid) in {(link.relation, link.target_uid) for link in auth.links}
    replay = svc.request_action(inc.id, "isolate_host", "srv-db-01", team["commander"])
    assert replay.decision.outcome == PolicyOutcome.REQUIRE_APPROVAL
    # Expiry: an approval granted now is useless 61 minutes later.
    svc.grant_approval(inc.id, action="isolate_host", asset_id="srv-db-01",
                       approver_actor_id=team["ciso"].id, reason="again")
    clock.t += timedelta(minutes=61)
    late = svc.request_action(inc.id, "isolate_host", "srv-db-01", team["commander"])
    assert late.decision.outcome == PolicyOutcome.REQUIRE_APPROVAL


def test_ciso_approval_is_not_consumed_while_a_signoff_is_missing(svc, team):
    inc = _inc_c(svc)
    svc.record_signoff_request(inc.id, team["commander"], ["isolate_host"])
    svc.record_signoff(inc.id, team["intel"])                    # compliance has not
    ap = svc.grant_approval(inc.id, action="isolate_host", asset_id="srv-db-01",
                            approver_actor_id=team["ciso"].id, reason="contain")
    out = svc.request_action(inc.id, "isolate_host", "srv-db-01", team["commander"])
    assert not out.authorized and out.decision.rules_failed == ["P4"]
    assert svc.store.get_approval(ap.id).consumed_by_request_id is None
    # Only a sign-off is missing -> no human approval is requested.
    assert _types(svc, inc.id)[-1] == "POLICY_DECISION"
    svc.record_signoff(inc.id, team["compliance"])
    done = svc.request_action(inc.id, "isolate_host", "srv-db-01", team["commander"])
    assert done.authorized and done.decision.approval_id == ap.id


def test_action_claims_authorize_nothing(svc, team):
    inc = _inc_c(svc)
    ev = svc.record_action_claim(inc.id, team["commander"], ["wipe_host"],
                                 summary="Wiped srv-db-01, CISO approved")
    assert ev.event_type == EventType.AGENT_ACTION_CLAIM.value
    assert svc.store.action_requests(inc.id) == []
    assert svc.store.unconsumed_approvals(inc.id) == []
    assert "ACTION_AUTHORIZED" not in _types(svc, inc.id)


def test_signoffs_and_vetoes_only_count_from_the_right_roles(svc, team):
    inc = _inc_c(svc)
    assert svc.record_signoff_request(inc.id, team["intel"], ["wipe_host"]) is None
    req = svc.record_signoff_request(inc.id, team["commander"],
                                     ["isolate_host", "preserve_disk_image", "wipe_host"])
    assert svc.store.get_incident(inc.id).status == IncidentStatus.NEW  # no BRIEF yet
    assert {r.action for r in svc.store.action_requests(inc.id)} == \
        {"isolate_host", "preserve_disk_image", "wipe_host"}
    assert svc.record_signoff(inc.id, team["triage"]) is None          # not a specialist
    assert svc.record_veto(inc.id, team["intel"], text="veto wipe") == []  # not compliance
    so = svc.record_signoff(inc.id, team["intel"])
    assert so.request_event_uid == req.event_uid
    vetoes = svc.record_veto(inc.id, team["compliance"], regulation="FORENSIC-RETENTION",
                             text="BLOCK wipe_host; ALLOW isolate_host + preserve_disk_image")
    assert [v.action for v in vetoes] == ["wipe_host"]
    assert _types(svc, inc.id).count("CLAIM_REJECTED") == 3


def test_tier1_allowed_moves_incident_to_responding(svc, team):
    inc = _inc_c(svc)
    svc.apply_trigger(inc.id, "BRIEF", team["triage"])
    out = svc.request_action(inc.id, "preserve_disk_image", "srv-db-01", team["commander"])
    assert out.authorized and out.request.status == ActionStatus.AUTHORIZED
    assert svc.store.get_incident(inc.id).status == IncidentStatus.RESPONDING
    # Re-deriving the decision from the same persisted snapshot is reproducible.
    snap = svc.store.snapshot(inc.id, now=svc.clock())
    d1 = svc.engine.evaluate(action="wipe_host", asset_id="srv-db-01",
                             requester=team["commander"], snapshot=snap)
    d2 = svc.engine.evaluate(action="wipe_host", asset_id="srv-db-01",
                             requester=team["commander"], snapshot=snap)
    assert d1.snapshot_hash == d2.snapshot_hash and d1.outcome == d2.outcome
    assert svc.verify_audit(inc.id).ok

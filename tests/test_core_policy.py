"""CyberRescue Core — the deterministic policy gate (cyberrescue/core/policy.py).

Snapshots are built in memory: the engine is a pure function, no DB needed.
"""

from datetime import datetime, timedelta, timezone

import pytest

from cyberrescue.core.catalog import match_actions_in_text
from cyberrescue.core.models import (
    Actor,
    ActorKind,
    Approval,
    ApprovalDecision,
    Asset,
    Incident,
    IncidentSnapshot,
    IncidentStatus,
    LegalHold,
    PolicyOutcome,
    SignOff,
    SignOffRequest,
    Veto,
)
from cyberrescue.core.policy import PolicyConfig, PolicyEngine
from shared.mock_data import load_assets

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
ASSETS = {a["asset_id"]: Asset(**{k: v for k, v in a.items() if k in Asset.model_fields})
          for a in load_assets()}

COMMANDER = Actor(id="a-cmd", kind=ActorKind.AGENT, role="commander")
INTEL = Actor(id="a-ti", kind=ActorKind.AGENT, role="threat_intel")
CISO = Actor(id="h-ciso", kind=ActorKind.HUMAN, role="ciso")

ALLOW, REQUIRE, DENY = (PolicyOutcome.ALLOW, PolicyOutcome.REQUIRE_APPROVAL,
                        PolicyOutcome.DENY)


def _incident(iid="INC-C-2026-0042", asset="srv-db-01",
              roles=("threat_intel", "compliance", "commander"),
              status=IncidentStatus.AWAITING_SIGNOFF):
    return Incident(id=iid, status=status, primary_asset_id=asset, recruited_roles=list(roles))


def _approval(action, asset, *, iid="INC-C-2026-0042", kind=ActorKind.HUMAN, role="ciso",
              decision=ApprovalDecision.APPROVE, hold=False, veto=False, reason="ok",
              expires=NOW + timedelta(minutes=60), aid="ap-1"):
    return Approval(id=aid, incident_id=iid, action=action, asset_id=asset,
                    approver_actor_id="h-1", approver_kind=kind, approver_role=role,
                    decision=decision, overrides_hold=hold, overrides_veto=veto,
                    reason=reason, expires_at=expires.isoformat(), event_uid=f"ev-{aid}")


def _signoffs(iid, actions, roles):
    req = SignOffRequest(event_uid="ev-req", incident_id=iid, actions=list(actions))
    sos = [SignOff(id=f"so-{r}", incident_id=iid, actor_id=f"a-{r}", actor_role=r,
                   request_event_uid="ev-req", covered_actions=list(actions),
                   event_uid=f"ev-so-{r}") for r in roles]
    return req, sos


def _hold(asset="srv-db-01"):
    return LegalHold(id="h1", asset_id=asset, rule_ids=["FORENSIC-RETENTION"],
                     requires_human_authorization=True, event_uid="ev-hold")


def _veto(action=None, asset=None, iid="INC-C-2026-0042"):
    return Veto(id="v1", incident_id=iid, actor_id="a-comp", action=action, asset_id=asset,
                regulation="FORENSIC-RETENTION", event_uid="ev-veto")


def _snap(incident, **kw):
    return IncidentSnapshot(incident=incident, assets=ASSETS, now=NOW, **kw)


def _eval(action, asset, snap, requester=COMMANDER, config=None):
    return PolicyEngine(config).evaluate(action=action, asset_id=asset,
                                         requester=requester, snapshot=snap)


# --- hard denies ---------------------------------------------------------------

def test_p0_unknown_action_denied():
    d = _eval("format_c_drive", "srv-db-01", _snap(_incident()))
    assert d.outcome == DENY and d.rules_failed == ["P0"]


def test_p1_only_commander_or_human_operator_may_request():
    snap = _snap(_incident())
    assert _eval("notify_stakeholders", None, snap, INTEL).outcome == DENY
    observer = Actor(id="h-obs", kind=ActorKind.HUMAN, role="observer")
    assert _eval("notify_stakeholders", None, snap, observer).rules_failed == ["P1"]
    assert _eval("notify_stakeholders", None, snap, CISO).outcome == ALLOW


def test_p2_closed_or_missing_incident_denied():
    closed = _incident(status=IncidentStatus.RESOLVED)
    assert _eval("preserve_disk_image", "srv-db-01", _snap(closed)).rules_failed == ["P2"]
    assert _eval("preserve_disk_image", "srv-db-01", _snap(None)).outcome == DENY


def test_p3_unknown_or_missing_host_denied():
    snap = _snap(_incident())
    d = _eval("isolate_host", "srv-nope-99", snap)
    assert d.outcome == DENY and "P3" in d.rules_failed  # other failures reported too
    d = _eval("isolate_host", None, snap)
    assert d.outcome == DENY and "P3" in d.rules_failed


# --- tiers ---------------------------------------------------------------------

def test_tier1_imaging_allowed_even_on_a_held_host():
    snap = _snap(_incident(), holds=[_hold()], vetoes=[_veto()])
    d = _eval("preserve_disk_image", "srv-db-01", snap)
    assert d.outcome == ALLOW and d.rule_results == []


def test_inc_a_isolate_allowed_with_specialist_signoff_on_medium_asset():
    inc = _incident("INC-A-2026-0039", "ws-eng-014", ("threat_intel", "commander"))
    req, sos = _signoffs(inc.id, ["isolate_host"], ["threat_intel"])
    d = _eval("isolate_host", "ws-eng-014", _snap(inc, signoff_request=req, signoffs=sos))
    assert d.outcome == ALLOW
    assert "ev-so-threat_intel" in d.relied_on_event_uids


def test_p4_missing_specialist_signoff_requires_approval():
    inc = _incident("INC-A-2026-0039", "ws-eng-014", ("threat_intel", "commander"))
    assert _eval("isolate_host", "ws-eng-014", _snap(inc)).rules_failed == ["P4"]
    # A sign-off request that does not cover the action does not count either.
    req, sos = _signoffs(inc.id, ["notify_stakeholders"], ["threat_intel"])
    d = _eval("isolate_host", "ws-eng-014", _snap(inc, signoff_request=req, signoffs=sos))
    assert d.outcome == REQUIRE and d.rules_failed == ["P4"]


def test_p5_containment_on_critical_asset_needs_human_even_with_signoffs():
    inc = _incident()
    req, sos = _signoffs(inc.id, ["isolate_host"], ["threat_intel", "compliance"])
    base = dict(signoff_request=req, signoffs=sos)
    d = _eval("isolate_host", "srv-db-01", _snap(inc, **base))
    assert d.outcome == REQUIRE and d.rules_failed == ["P5"]
    d = _eval("isolate_host", "srv-db-01",
              _snap(inc, approvals=[_approval("isolate_host", "srv-db-01")], **base))
    assert d.outcome == ALLOW and d.approval_id == "ap-1"


def test_p5_threshold_is_configurable():
    inc = _incident()
    req, sos = _signoffs(inc.id, ["isolate_host"], ["threat_intel", "compliance"])
    lenient = PolicyConfig(containment_human_approval_criticality=())
    d = _eval("isolate_host", "srv-db-01",
              _snap(inc, signoff_request=req, signoffs=sos), config=lenient)
    assert d.outcome == ALLOW


def test_p6_tier3_always_needs_a_human():
    inc = _incident("INC-A-2026-0039", "ws-eng-014", ("threat_intel", "commander"))
    assert _eval("wipe_host", "ws-eng-014", _snap(inc)).rules_failed == ["P6"]
    d = _eval("wipe_host", "ws-eng-014", _snap(inc, approvals=[
        _approval("wipe_host", "ws-eng-014", iid=inc.id)]))
    assert d.outcome == ALLOW


# --- Decision 1 (Phase 1b): sign-off and human approval are independent -----------

def test_ciso_approval_cannot_substitute_for_a_missing_specialist_signoff():
    inc = _incident()  # srv-db-01 is critical -> P5 also needs a human
    only_intel = _signoffs(inc.id, ["isolate_host"], ["threat_intel"])  # compliance missing
    everything = _approval("isolate_host", "srv-db-01", hold=True, veto=True, reason="all")

    d = _eval("isolate_host", "srv-db-01", _snap(
        inc, signoff_request=only_intel[0], signoffs=only_intel[1], approvals=[everything]))
    assert d.outcome == REQUIRE and d.rules_failed == ["P4"] and d.approval_id is None
    p4, p5 = (next(r for r in d.rule_results if r.rule == k) for k in ("P4", "P5"))
    assert (p4.effect, p4.satisfied) == ("require_signoff", False)
    assert "cannot substitute" in p4.reason
    assert (p5.effect, p5.satisfied) == ("require_approval", True)


def test_signoff_and_approval_are_both_required_for_containment_on_critical_asset():
    inc = _incident()
    full = _signoffs(inc.id, ["isolate_host"], ["threat_intel", "compliance"])
    ap = _approval("isolate_host", "srv-db-01")
    cases = {
        (False, False): ["P4", "P5"],
        (True, False): ["P5"],
        (False, True): ["P4"],
        (True, True): [],
    }
    for (signed, approved), unmet in cases.items():
        kw = dict(signoff_request=full[0], signoffs=full[1]) if signed else {}
        d = _eval("isolate_host", "srv-db-01", _snap(inc, approvals=[ap] if approved else [], **kw))
        assert d.rules_failed == unmet, (signed, approved)
        assert (d.outcome == ALLOW) == (unmet == []), (signed, approved)


def test_applicable_rules_listed_per_tier():
    from cyberrescue.core.policy import applicable_rules
    assert applicable_rules("preserve_disk_image") == ["P0", "P1", "P2", "P3", "P7", "P8", "P9"]
    assert "P4" in applicable_rules("isolate_host") and "P6" not in applicable_rules("isolate_host")
    assert "P6" in applicable_rules("wipe_host") and "P4" not in applicable_rules("wipe_host")
    assert applicable_rules("nope") == ["P0", "P1", "P2", "P3", "P9"]


# --- the INC-C conflict: veto + legal hold ---------------------------------------

def test_inc_c_wipe_needs_an_approval_that_overrides_both_veto_and_hold():
    inc = _incident()
    blocked = dict(holds=[_hold()], vetoes=[_veto()])
    d = _eval("wipe_host", "srv-db-01", _snap(inc, **blocked))
    assert d.outcome == REQUIRE and d.rules_failed == ["P6", "P7", "P8"]
    assert set(d.blocked_by_event_uids) == {"ev-veto", "ev-hold"}

    plain = _approval("wipe_host", "srv-db-01")
    d = _eval("wipe_host", "srv-db-01", _snap(inc, approvals=[plain], **blocked))
    assert d.outcome == REQUIRE
    assert any(r.startswith("P7") and "lacks overrides_veto" in r for r in d.reasons)
    assert any(r.startswith("P8") and "lacks overrides_hold" in r for r in d.reasons)

    hold_only = _approval("wipe_host", "srv-db-01", hold=True, reason="accept evidence risk")
    d = _eval("wipe_host", "srv-db-01", _snap(inc, approvals=[hold_only], **blocked))
    assert d.outcome == REQUIRE

    both = _approval("wipe_host", "srv-db-01", hold=True, veto=True,
                     reason="CISO accepts evidence risk to stop domain compromise")
    d = _eval("wipe_host", "srv-db-01", _snap(inc, approvals=[both], **blocked))
    assert d.outcome == ALLOW and d.approval_id == "ap-1"
    assert d.blocked_by_event_uids == [] and "ev-ap-1" in d.relied_on_event_uids


def test_hold_override_requires_a_written_reason():
    inc = _incident()
    no_reason = _approval("wipe_host", "srv-db-01", hold=True, reason="   ")
    d = _eval("wipe_host", "srv-db-01", _snap(inc, holds=[_hold()], approvals=[no_reason]))
    assert d.outcome == REQUIRE and "P8" in d.rules_failed


def test_unscoped_veto_blocks_destructive_actions_only():
    inc = _incident()
    req, sos = _signoffs(inc.id, ["isolate_host"], ["threat_intel", "compliance"])
    snap = _snap(inc, vetoes=[_veto()], signoff_request=req, signoffs=sos,
                 approvals=[_approval("isolate_host", "srv-db-01")])
    assert _eval("isolate_host", "srv-db-01", snap).outcome == ALLOW
    assert "P7" in _eval("wipe_host", "srv-db-01", snap).rules_failed


# --- approval validity ------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    _approval("wipe_host", "srv-app-01"),                          # other asset
    _approval("isolate_host", "ws-eng-014"),                       # other action
    _approval("wipe_host", "ws-eng-014", iid="INC-B-2026-0041"),   # other incident
    _approval("wipe_host", "ws-eng-014", expires=NOW),              # expired
    _approval("wipe_host", "ws-eng-014", kind=ActorKind.AGENT),     # agent "approver"
    _approval("wipe_host", "ws-eng-014", role="observer"),          # human w/o authority
    _approval("wipe_host", "ws-eng-014").model_copy(update={"consumed_by_request_id": "r0"}),
], ids=["asset", "action", "incident", "expired", "agent", "observer", "consumed"])
def test_invalid_approvals_never_count(bad):
    inc = _incident("INC-A-2026-0039", "ws-eng-014", ("threat_intel", "commander"))
    bad = bad if bad.incident_id != "INC-C-2026-0042" else bad.model_copy(
        update={"incident_id": inc.id})
    d = _eval("wipe_host", "ws-eng-014", _snap(inc, approvals=[bad]))
    assert d.outcome == REQUIRE and d.approval_id is None


def test_p9_explicit_human_denial_is_a_hard_deny():
    inc = _incident("INC-A-2026-0039", "ws-eng-014", ("threat_intel", "commander"))
    denial = _approval("wipe_host", "ws-eng-014", iid=inc.id,
                       decision=ApprovalDecision.DENY, reason="keep it live")
    grant = _approval("wipe_host", "ws-eng-014", iid=inc.id, aid="ap-2")
    d = _eval("wipe_host", "ws-eng-014", _snap(inc, approvals=[denial, grant]))
    assert d.outcome == DENY and "P9" in d.rules_failed


# --- explainability & determinism -------------------------------------------------

def test_every_failing_rule_is_reported_and_decisions_are_deterministic():
    inc = _incident(status=IncidentStatus.RESOLVED)
    snap = _snap(inc, holds=[_hold()], vetoes=[_veto()])
    d1 = _eval("wipe_host", "srv-db-01", snap, requester=INTEL)
    d2 = _eval("wipe_host", "srv-db-01", snap, requester=INTEL)
    assert d1.outcome == DENY
    assert d1.rules_failed == ["P1", "P2", "P6", "P7", "P8"]
    assert d1.model_dump() == d2.model_dump() and len(d1.snapshot_hash) == 64


def test_approval_ttl_default_and_env_override(monkeypatch):
    assert PolicyConfig().approval_ttl_minutes == 60
    monkeypatch.setenv("CYBERRESCUE_APPROVAL_TTL_MINUTES", "15")
    assert PolicyConfig.from_env().approval_ttl_minutes == 15
    monkeypatch.setenv("CYBERRESCUE_APPROVAL_TTL_MINUTES", "0")
    with pytest.raises(ValueError):
        PolicyConfig.from_env()


def test_action_names_extracted_from_veto_and_plan_prose():
    veto = ("BLOCK wipe_host (image does NOT release the hold); "
            "ALLOW isolate_host + preserve_disk_image")
    assert match_actions_in_text(veto) == ["preserve_disk_image", "isolate_host", "wipe_host"]
    assert match_actions_in_text("Proposed: isolate the host, then wipe and reimage") == \
        ["wipe_host", "isolate_host"]
    assert match_actions_in_text("no actions here") == []

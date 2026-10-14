"""CyberRescue Core — Commander action gate, shadow & enforce (cyberrescue/core/gate.py)."""

import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from cyberrescue.core.gate import CommanderGate, GateMode, resolve_mode
from cyberrescue.core.models import ActionStatus, EventType, IncidentStatus
from cyberrescue.core.service import CoreService

FIXED = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
INC = "INC-C-2026-0042"
REQUIRED_FIELDS = {"ts", "mode", "incident", "action", "target_asset", "outcome", "verdict",
                   "would_allow", "proceed", "blocked", "rules_evaluated", "rule_results",
                   "unmet_rules", "reason", "signoffs_considered", "approvals_considered",
                   "policy_version"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    db, log = tmp_path / "core.db", tmp_path / "gate.jsonl"
    monkeypatch.setenv("CYBERRESCUE_DB_PATH", str(db))
    monkeypatch.setenv("CYBERRESCUE_GATE_LOG", str(log))
    svc = CoreService.open(db, clock=lambda: FIXED)
    svc.seed_assets_from_mock()
    svc.open_incident(INC, primary_asset_id="srv-db-01",
                      recruited_roles=["threat_intel", "compliance", "commander"])
    team = SimpleNamespace(
        commander=svc.register_actor("agent", "commander", "cmd", "warroom:commander"),
        intel=svc.register_actor("agent", "threat_intel", "ti", "band:ti"),
        compliance=svc.register_actor("agent", "compliance", "c", "band:c"),
        ciso=svc.register_actor("human", "ciso", "CISO", "band:ciso"))
    yield SimpleNamespace(svc=svc, db=db, log=log, team=team)
    svc.conn.close()


def _gate(env, mode=None):
    return CommanderGate(mode=mode, db_path=env.db, log_path=env.log, clock=lambda: FIXED)


def _log_lines(env):
    return [json.loads(x) for x in env.log.read_text(encoding="utf-8").splitlines() if x]


def _events(env, etype):
    return env.svc.audit.events(INC, event_type=etype)


# --- configuration ---------------------------------------------------------------

def test_default_mode_is_shadow_and_bad_values_never_enforce(monkeypatch):
    monkeypatch.delenv("CYBERRESCUE_GATE_MODE", raising=False)
    assert resolve_mode() == (GateMode.SHADOW, None)
    assert CommanderGate().mode == GateMode.SHADOW
    assert resolve_mode(" ENFORCE ")[0] == GateMode.ENFORCE
    mode, warning = resolve_mode("enforcing")
    assert mode == GateMode.SHADOW and "never enabled" in warning
    monkeypatch.setenv("CYBERRESCUE_GATE_MODE", "enforce")
    assert CommanderGate().mode == GateMode.ENFORCE


# --- shadow --------------------------------------------------------------------------

def test_shadow_records_a_would_deny_decision_with_full_context(env):
    rec = _gate(env).check("wipe_host", {"asset_id": "srv-db-01", "reason": "eradicate"})
    assert REQUIRED_FIELDS <= set(rec)
    assert (rec["mode"], rec["incident"], rec["action"], rec["target_asset"]) == \
        ("shadow", INC, "wipe_host", "srv-db-01")
    assert (rec["outcome"], rec["verdict"], rec["would_allow"]) == \
        ("REQUIRE_APPROVAL", "DENY", False)
    assert (rec["proceed"], rec["blocked"]) == (True, False)       # shadow never blocks
    assert rec["unmet_rules"] == ["P6", "P8"] and "legal hold" in rec["reason"]
    assert rec["rules_evaluated"] == ["P0", "P1", "P2", "P3", "P6", "P7", "P8", "P9"]
    assert rec["ts"] == FIXED.isoformat() and rec["policy_version"] == "policy-v2"
    assert _log_lines(env) == [rec]
    [ev] = _events(env, EventType.GATE_DECISION)
    assert ev.payload["verdict"] == "DENY" and rec["core_event_uid"] == ev.uid
    hold_uid = env.svc.store.active_holds("srv-db-01")[0].event_uid
    assert ("blocked_by", hold_uid) in {(link.relation, link.target_uid) for link in ev.links}


def test_shadow_records_a_hard_deny(env):
    rec = _gate(env).check("isolate_host", {"asset_id": "srv-ghost-99"})
    assert rec["outcome"] == "DENY" and "P3" in rec["unmet_rules"] and rec["proceed"]


def test_shadow_records_an_allow_decision(env):
    rec = _gate(env).check("preserve_disk_image", {"asset_id": "srv-db-01", "reason": "evidence"})
    assert (rec["outcome"], rec["verdict"], rec["would_allow"], rec["proceed"]) == \
        ("ALLOW", "ALLOW", True, True)
    assert rec["unmet_rules"] == [] and rec["reason"] == "all applicable policy rules satisfied"


def test_shadow_reports_signoffs_and_approvals_considered(env):
    svc, t = env.svc, env.team
    svc.record_signoff_request(INC, t.commander, ["isolate_host"])
    svc.record_signoff(INC, t.intel)                                # compliance missing
    ap = svc.grant_approval(INC, action="isolate_host", asset_id="srv-db-01",
                            approver_actor_id=t.ciso.id, reason="contain")
    rec = _gate(env).check("isolate_host", {"asset_id": "srv-db-01"})
    assert rec["unmet_rules"] == ["P4"] and rec["verdict"] == "DENY"   # Decision 1
    assert [s["role"] for s in rec["signoffs_considered"]] == ["threat_intel"]
    assert rec["signoff_request"]["actions"] == ["isolate_host"]
    [a] = rec["approvals_considered"]
    assert a["approval_id"] == ap.id and a["valid_for_this_action"] is True


def test_shadow_changes_no_core_state(env):
    svc, t = env.svc, env.team
    ap = svc.grant_approval(INC, action="wipe_host", asset_id="srv-db-01",
                            approver_actor_id=t.ciso.id, overrides_hold=True, reason="ok")
    rec = _gate(env).check("wipe_host", {"asset_id": "srv-db-01"})
    assert rec["verdict"] == "ALLOW"                      # would be allowed...
    assert svc.store.get_approval(ap.id).consumed_by_request_id is None   # ...not consumed
    assert svc.store.action_requests(INC) == []
    assert svc.store.get_incident(INC).status == IncidentStatus.NEW
    assert _events(env, EventType.ACTION_AUTHORIZED) == []


# --- enforce ---------------------------------------------------------------------------

def test_enforce_blocks_a_prohibited_action(env):
    rec = _gate(env, "enforce").check("wipe_host", {"asset_id": "srv-db-01", "reason": "x"})
    assert (rec["proceed"], rec["blocked"], rec["verdict"]) == (False, True, "DENY")
    req = env.svc.store.get_action_request(rec["request_id"])
    assert req.status == ActionStatus.REQUIRES_APPROVAL and req.params["via"] == "commander_gate"
    [gate_ev] = _events(env, EventType.GATE_DECISION)
    [dec_ev] = _events(env, EventType.POLICY_DECISION)
    assert [(link.relation, link.target_uid) for link in gate_ev.links] == \
        [("concerns", dec_ev.uid)]


def test_enforce_allows_a_properly_approved_action(env):
    svc, t = env.svc, env.team
    ap = svc.grant_approval(INC, action="wipe_host", asset_id="srv-db-01",
                            approver_actor_id=t.ciso.id, overrides_hold=True,
                            reason="accept evidence risk; image preserved")
    rec = _gate(env, "enforce").check("wipe_host", {"asset_id": "srv-db-01"})
    assert (rec["proceed"], rec["verdict"], rec["outcome"]) == (True, "ALLOW", "ALLOW")
    assert svc.store.get_approval(ap.id).consumed_by_request_id == rec["request_id"]
    assert len(_events(env, EventType.ACTION_AUTHORIZED)) == 1
    # Single use: the same action again is blocked.
    again = _gate(env, "enforce").check("wipe_host", {"asset_id": "srv-db-01"})
    assert again["blocked"]


def test_enforce_blocks_containment_when_ciso_approves_but_signoff_missing(env):
    svc, t = env.svc, env.team
    svc.record_signoff_request(INC, t.commander, ["isolate_host"])
    svc.record_signoff(INC, t.intel)
    svc.grant_approval(INC, action="isolate_host", asset_id="srv-db-01",
                       approver_actor_id=t.ciso.id, reason="contain")
    rec = _gate(env, "enforce").check("isolate_host", {"asset_id": "srv-db-01"})
    assert rec["blocked"] and rec["unmet_rules"] == ["P4"]
    svc.record_signoff(INC, t.compliance)
    assert _gate(env, "enforce").check("isolate_host", {"asset_id": "srv-db-01"})["proceed"]


def test_enforce_fails_closed_without_incident_or_on_core_error(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERRESCUE_INCIDENT", raising=False)
    empty = CommanderGate(mode="enforce", db_path=tmp_path / "empty.db",
                          log_path=tmp_path / "g.jsonl", clock=lambda: FIXED)
    rec = empty.check("isolate_host", {"asset_id": "ws-eng-014"})
    assert rec["blocked"] and rec["incident"] is None and "P2" in rec["unmet_rules"]
    assert any("no Core incident bound" in w for w in rec["warnings"])
    broken_db = tmp_path  # a directory, not a database file -> Core error
    for mode, proceeds in (("enforce", False), ("shadow", True)):
        g = CommanderGate(mode=mode, db_path=broken_db, log_path=tmp_path / "g.jsonl")
        rec = g.check("isolate_host", {"asset_id": "ws-eng-014"})
        assert rec["error"] and rec["verdict"] == "DENY" and rec["proceed"] is proceeds


def test_incident_resolution_env_alias_and_legacy_autoopen(tmp_path, monkeypatch):
    g = CommanderGate(db_path=tmp_path / "c.db", log_path=tmp_path / "g.jsonl",
                      clock=lambda: FIXED)
    monkeypatch.setenv("CYBERRESCUE_INCIDENT", "INC-A")
    first = g.check("isolate_host", {"asset_id": "ws-eng-014"})
    assert first["incident"] == "INC-A-2026-0039"
    assert any("opened WarRoom demo incident" in w for w in first["warnings"])
    assert not any("opened" in w for w in g.check("isolate_host",
                                                  {"asset_id": "ws-eng-014"})["warnings"])
    monkeypatch.setenv("CYBERRESCUE_INCIDENT", "INC-20990101-0001")
    rec = g.check("isolate_host", {"asset_id": "ws-eng-014"})
    assert rec["incident"] is None and any("is not a Core incident" in w
                                           for w in rec["warnings"])

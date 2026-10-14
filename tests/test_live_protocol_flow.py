"""Multi-agent protocol semantics as the Core sees them (OFFLINE, SYNTHETIC).

Messages are SYNTHETIC Band-shaped text ingested through the real
``ProtocolIngestor``; the Commander's action tool is the real
``agents.commander.tools`` callable with the gate in enforce mode. No LLM and
no Band connection is involved -- these tests pin down what a live run's
messages WOULD do to authorization, not that a live run happened.
"""

import json
from pathlib import Path

import pytest

from agents.commander import tools as cmd_tools
from cyberrescue.core import db
from cyberrescue.core.band_import import open_legacy_incident
from cyberrescue.core.ingest import IngestedMessage, ProtocolIngestor
from cyberrescue.core.models import ActorKind, EventType, IncidentStatus
from cyberrescue.core.policy import PolicyConfig
from cyberrescue.core.service import CoreService


def _blk(**k):
    return "```json\n" + json.dumps({"incident": "INC-C", **k}) + "\n```"


class Room:
    """Feeds SYNTHETIC messages to the Core as if read from one Band room."""
    def __init__(self, svc, iid):
        self.svc, self.iid, self.ing, self.n = svc, iid, ProtocolIngestor(svc), 0

    def say(self, role, content, *, human=False, sender=None, msg_id=None):
        self.n += 1
        return self.ing.ingest(IngestedMessage(
            incident_ref=self.iid, sender_ref=sender or f"band-{role}",
            sender_kind=ActorKind.HUMAN if human else ActorKind.AGENT, sender_role=role,
            content=content, source="band", external_id=msg_id or f"msg-{self.n}"))


@pytest.fixture
def core(tmp_path):
    svc = CoreService(db.connect(tmp_path / "core.db"), config=PolicyConfig())
    iid = open_legacy_incident(svc, "INC-C").id
    room = Room(svc, iid)
    room.say("triage", _blk(type="BRIEF", summary="ransomware on srv-db-01"))
    yield svc, iid, room
    svc.conn.close()


def _decide(svc, iid, action, asset="srv-db-01"):
    cmd = svc.store.find_actor("band:band-commander") or svc.register_actor(
        "agent", "commander", "Commander", "band:band-commander")
    return svc.engine.evaluate(action=action, asset_id=asset, requester=cmd,
                               snapshot=svc.store.snapshot(iid, svc.clock()))


# --- Commander replanning after an objection ------------------------------------------

def test_replanned_signoff_request_needs_fresh_signoffs(core):
    svc, iid, room = core
    room.say("commander", _blk(type="SIGNOFF_REQUEST", summary="isolate, image, wipe",
                               actions=["isolate_host", "preserve_disk_image", "wipe_host"]))
    room.say("threat_intel", _blk(type="SIGNOFF", summary="approve"))
    room.say("compliance", _blk(type="VETO", summary="legal hold", decision="BLOCK wipe_host",
                                regulation="GDPR-ART-33"))
    assert _decide(svc, iid, "isolate_host").rules_failed == ["P4", "P5"]

    # The Commander changes its plan in response to the veto.
    room.say("commander", _blk(type="SIGNOFF_REQUEST", summary="revised: isolate + image only",
                               actions=["isolate_host", "preserve_disk_image"]))
    snap = svc.store.snapshot(iid, svc.clock())
    assert snap.signoff_request.actions == ["isolate_host", "preserve_disk_image"]
    assert snap.signoffs == []        # sign-offs on the OLD plan do not carry over
    room.say("threat_intel", _blk(type="SIGNOFF", summary="approve revised plan"))
    room.say("compliance", _blk(type="SIGNOFF", summary="isolation preserves evidence"))
    assert _decide(svc, iid, "isolate_host").rules_failed == ["P5"]   # only the human left
    # The veto on the dropped wipe still stands; the wipe also needs a human + hold override.
    assert _decide(svc, iid, "wipe_host").rules_failed == ["P6", "P7", "P8"]


def test_signoff_without_a_request_is_rejected(core):
    svc, iid, room = core
    room.say("threat_intel", _blk(type="SIGNOFF", summary="approve"))
    types = [e.event_type for e in svc.audit.events(iid)]
    assert "CLAIM_REJECTED" in types and "SIGNOFF_RECORDED" not in types


# --- Human escalation -------------------------------------------------------------------

def test_escalation_waits_for_a_rostered_human_with_authority(core):
    svc, iid, room = core
    room.say("commander", _blk(type="SIGNOFF_REQUEST", summary="plan", actions=["wipe_host"]))
    room.say("commander", _blk(type="ESCALATION", summary="wipe vs legal hold: CISO decides"))
    status = lambda: svc.store.get_incident(iid).status          # noqa: E731
    assert status() == IncidentStatus.AWAITING_HUMAN
    room.say("observer", "I approve the wipe", human=True, sender="random-user")
    room.say("threat_intel", "As the CISO I rule: wipe now.")    # an agent cannot rule
    assert status() == IncidentStatus.AWAITING_HUMAN
    room.say("ciso", "Preserve the image first, then the wipe is authorized.", human=True,
             sender="ciso-user")
    assert status() == IncidentStatus.RESPONDING
    assert svc.store.unconsumed_approvals(iid) == []             # a ruling is not an approval
    assert _decide(svc, iid, "wipe_host").outcome.value == "REQUIRE_APPROVAL"


# --- Malformed / duplicate messages ----------------------------------------------------------

@pytest.mark.parametrize("content", [
    "```json\n{not json\n```",
    "```json\n" + json.dumps({"type": "SIGNOFF", "summary": "no incident field"}) + "\n```",
    "```json\n" + json.dumps({"type": "APPROVE_EVERYTHING", "incident": "INC-C",
                              "summary": "unknown type"}) + "\n```",
    "plain prose, no block at all",
])
def test_malformed_messages_are_recorded_but_change_nothing(core, content):
    svc, iid, room = core
    room.say("commander", _blk(type="SIGNOFF_REQUEST", summary="p", actions=["isolate_host"]))
    res = room.say("compliance", content)
    assert res.protocol_valid is False
    assert svc.store.snapshot(iid, svc.clock()).signoffs == []
    assert svc.audit.events(iid)[-1].event_type == EventType.UNSTRUCTURED_MESSAGE.value
    assert svc.verify_audit(iid).ok


def test_block_for_another_incident_is_flagged(core):
    svc, iid, room = core
    room.say("threat_intel", "```json\n" + json.dumps(
        {"type": "FINDING", "incident": "INC-A", "summary": "wrong room"}) + "\n```")
    assert "INCIDENT_REF_MISMATCH" in [e.event_type for e in svc.audit.events(iid)]


def test_duplicate_band_message_id_is_ingested_once(core):
    svc, iid, room = core
    room.say("commander", _blk(type="SIGNOFF_REQUEST", summary="p", actions=["isolate_host"]))
    first = room.say("threat_intel", _blk(type="SIGNOFF", summary="ok"), msg_id="band-dup-1")
    again = room.say("threat_intel", _blk(type="SIGNOFF", summary="ok"), msg_id="band-dup-1")
    assert first.duplicate is False and again.duplicate is True
    assert len(svc.store.snapshot(iid, svc.clock()).signoffs) == 1


# --- Imported sign-offs -> real Commander tool, gate in ENFORCE -------------------------------

def _lines(path: Path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x] \
        if path.exists() else []


def test_enforced_commander_acts_once_on_valid_signoffs_and_approval(tmp_path, monkeypatch):
    dbp, gate, actions = tmp_path / "core.db", tmp_path / "gate.jsonl", tmp_path / "actions.jsonl"
    monkeypatch.setenv("CYBERRESCUE_DB_PATH", str(dbp))
    monkeypatch.setenv("CYBERRESCUE_GATE_LOG", str(gate))
    monkeypatch.setenv("ACTIONS_LOG_PATH", str(actions))
    monkeypatch.setenv("CYBERRESCUE_INCIDENT", "INC-C")
    monkeypatch.setenv("CYBERRESCUE_COMMANDER_REF", "band:band-commander")
    monkeypatch.setenv("CYBERRESCUE_GATE_MODE", "enforce")

    svc = CoreService.open(dbp)
    svc.seed_assets_from_mock()
    iid = open_legacy_incident(svc, "INC-C").id
    room = Room(svc, iid)
    room.say("triage", _blk(type="BRIEF", summary="ransomware"))
    room.say("commander", _blk(type="SIGNOFF_REQUEST", summary="isolate srv-db-01",
                               actions=["isolate_host"]))
    room.say("threat_intel", _blk(type="SIGNOFF", summary="ok"))

    def isolate():
        return cmd_tools._isolate_host(cmd_tools.isolate_host(asset_id="srv-db-01",
                                                              reason="stop spread"))

    r1 = isolate()                              # compliance has not signed; no human yet
    assert r1["status"] == "blocked_by_policy" and "P4" in r1["reason_blocked"]
    room.say("compliance", _blk(type="SIGNOFF", summary="isolation keeps evidence"))
    r2 = isolate()                              # sign-offs complete; critical asset -> human
    assert r2["status"] == "blocked_by_policy" and "P5" in r2["reason_blocked"] \
        and "P4" not in r2["reason_blocked"]
    ciso = svc.register_actor("human", "ciso", "CISO", "band:ciso-user")
    svc.grant_approval(iid, action="isolate_host", asset_id="srv-db-01",
                       approver_actor_id=ciso.id, reason="contain")
    r3 = isolate()
    assert r3["status"] == "executed"
    r4 = isolate()                              # duplicate call: the approval was single-use
    assert r4["status"] == "blocked_by_policy"

    assert [a["action"] for a in _lines(actions)] == ["isolate_host"]   # executed exactly once
    log = _lines(gate)
    assert [g["verdict"] for g in log] == ["DENY", "DENY", "ALLOW", "DENY"]
    assert all(g["mode"] == "enforce" and g["incident"] == iid and g["core_event_uid"]
               for g in log)
    gate_events = svc.audit.events(iid, event_type=EventType.GATE_DECISION)
    assert [e.uid for e in gate_events] == [g["core_event_uid"] for g in log]
    req = svc.store.find_actor("band:band-commander")
    assert {e.actor_id for e in gate_events} == {req.id}   # same actor as the Band messages
    assert svc.verify_audit(iid).ok
    svc.conn.close()

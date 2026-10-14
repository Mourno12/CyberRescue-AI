"""cyberrescue.live roster + Band JSON export -> core import-band round trip.

The Band REST clients here are MOCKED (in-memory fakes returning SYNTHETIC
messages in the agent-context shape); no network is used.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberrescue.core import db
from cyberrescue.core.band_import import Roster, import_band_context
from cyberrescue.core.policy import PolicyConfig
from cyberrescue.core.service import CoreService
from cyberrescue.live.band_export import PAGE_SIZE, collect_room, message_to_dict, write_export
from cyberrescue.live.roster import RosterError, build_roster, parse_human, write_roster
from tests.test_live_preflight import _config

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def svc(tmp_path):
    s = CoreService(db.connect(tmp_path / "core.db"), config=PolicyConfig())
    yield s
    s.conn.close()


# --- roster ------------------------------------------------------------------------

def test_roster_maps_all_five_agents_and_explicit_humans():
    r = build_roster(_config(), {"human-ciso-1": "ciso"})
    assert r["agents"] == {"id-triage": "triage", "id-ti": "threat_intel",
                           "id-comp": "compliance", "id-cmd": "commander",
                           "id-fac": "facilitator"}
    assert r["humans"] == {"human-ciso-1": "ciso"}
    assert "api_key" not in json.dumps(r) and "KEY-SYNTH" not in json.dumps(r)


@pytest.mark.parametrize("cfg,humans,msg", [
    (_config(triage={"agent_id": "REPLACE_WITH_TRIAGE_UUID"}), {}, "placeholder"),
    (_config(threat_intel={"agent_id": "id-triage"}), {}, "share agent_id"),
    (_config(), {"h": "superuser"}, "human role"),
    (_config(), {"id-cmd": "ciso"}, "also an agent id"),
])
def test_roster_rejects_bad_input(cfg, humans, msg):
    with pytest.raises(RosterError, match=msg):
        build_roster(cfg, humans)


def test_parse_human_and_never_overwrite(tmp_path):
    assert parse_human("abc=ciso") == ("abc", "ciso")
    with pytest.raises(RosterError):
        parse_human("abc")
    out = tmp_path / "roster.json"
    write_roster(out, {"agents": {}})
    with pytest.raises(RosterError, match="never overwritten"):
        write_roster(out, {"agents": {}})


# --- export (MOCKED Band clients) -----------------------------------------------------------

def _msg(i, sender, kind="Agent", content="", mtype="text", ts=None):
    return {"id": f"m{i:03d}", "chat_id": "room-1", "sender_id": sender, "sender_type": kind,
            "sender_name": sender, "message_type": mtype, "content": content,
            "inserted_at": ts or f"2026-10-11T10:{i // 60:02d}:{i % 60:02d}Z"}


class FakeClient:
    """MOCK of thenvoi_rest.RestClient.agent_api_context (context endpoint)."""
    def __init__(self, messages, fail=False):
        self.messages, self.fail, self.calls = messages, fail, []
        self.agent_api_context = self

    def get_agent_chat_context(self, chat_id, page, page_size):
        self.calls.append((chat_id, page))
        if self.fail:
            raise ConnectionError("synthetic outage")
        chunk = self.messages[(page - 1) * page_size: page * page_size]
        return SimpleNamespace(data=chunk, meta=None)


def _blk(**k):
    return "```json\n" + json.dumps({"incident": "INC-C-2026-0042", **k}) + "\n```"


def test_views_are_merged_deduplicated_and_sorted():
    a = [_msg(3, "id-ti"), _msg(1, "id-triage")]
    b = [_msg(1, "id-triage"), _msg(2, "id-comp"), {"content": "no id", "sender_id": "x"}]
    doc = collect_room({"threat_intel": FakeClient(a), "compliance": FakeClient(b)}, "room-1")
    assert [m["id"] for m in doc["data"]] == ["m001", "m002", "m003"]
    assert doc["message_count"] == 3 and doc["_provenance"] == "band-live-export"
    assert doc["views"] == {"threat_intel": {"ok": True, "messages": 2},
                            "compliance": {"ok": True, "messages": 3}}


def test_failed_view_is_recorded_not_hidden():
    doc = collect_room({"triage": FakeClient([_msg(1, "id-triage")]),
                        "commander": FakeClient([], fail=True)}, "room-1")
    assert doc["views"]["commander"] == {"ok": False, "error": "ConnectionError"}
    assert doc["message_count"] == 1


def test_pagination_reads_every_page():
    msgs = [_msg(i, "id-ti") for i in range(PAGE_SIZE + 5)]
    client = FakeClient(msgs)
    doc = collect_room({"threat_intel": client}, "room-1")
    assert doc["message_count"] == PAGE_SIZE + 5 and [p for _, p in client.calls] == [1, 2]


def test_tool_calls_are_kept_in_the_export_and_counted():
    doc = collect_room({"triage": FakeClient([
        _msg(1, "id-triage", mtype="tool_call", content='{"event": "on_tool_start"}'),
        _msg(2, "id-triage", mtype="tool_result", content='{"ok": true}'),
        _msg(3, "id-triage", content="hello")])}, "room-1")
    assert doc["message_types"] == {"text": 1, "tool_call": 1, "tool_result": 1}


def test_message_objects_are_normalised():
    obj = SimpleNamespace(id="m1", content="x", sender_id="s", sender_type="Agent",
                          sender_name="n", message_type="text", chat_id="r",
                          inserted_at=__import__("datetime").datetime(2026, 10, 11, 10, 0),
                          updated_at=None, metadata=None)
    d = message_to_dict(obj)
    assert d["inserted_at"] == "2026-10-11T10:00:00" and "updated_at" not in d


def test_export_never_overwrites(tmp_path):
    out = tmp_path / "x.json"
    write_export(out, {"data": []})
    with pytest.raises(FileExistsError):
        write_export(out, {"data": []})


def test_export_round_trips_into_core_import_and_gate_decisions(svc, tmp_path):
    """SYNTHETIC INC-C flow exported via MOCKED clients, imported with a roster
    built from a synthetic agent_config: sign-offs/vetoes reach the policy engine."""
    cmd_view = [
        _msg(1, "human-ciso", "User", "@Triage alert INC-C"),
        _msg(2, "id-triage", content=_blk(type="BRIEF", summary="ransomware",
                                          recruited=["threat_intel", "compliance", "commander"])),
        _msg(3, "id-cmd", content=_blk(type="SIGNOFF_REQUEST", summary="plan",
                                       actions=["isolate_host", "preserve_disk_image",
                                                "wipe_host"])),
        _msg(6, "id-cmd", content=_blk(type="ESCALATION", summary="wipe needs CISO")),
        _msg(7, "human-ciso", "User", "Preserve first, then wipe is authorized."),
    ]
    ti_view = [cmd_view[2], _msg(4, "id-ti", content=_blk(type="SIGNOFF", summary="ok"))]
    comp_view = [cmd_view[2], _msg(5, "id-comp", content=_blk(
        type="VETO", summary="legal hold", decision="BLOCK wipe_host",
        regulation="GDPR-ART-33"))]
    doc = collect_room({"commander": FakeClient(cmd_view), "threat_intel": FakeClient(ti_view),
                        "compliance": FakeClient(comp_view)}, "room-1")
    path = tmp_path / "export.json"
    write_export(path, doc)
    roster = Roster.from_mapping(build_roster(_config(), {"human-ciso": "ciso"}))

    rep = import_band_context(svc, path, incident_ref="INC-C", roster=roster)
    assert (rep.imported, rep.protocol_valid, rep.human, rep.duplicates) == (7, 5, 2, 0)
    iid = rep.incident_id
    assert svc.store.get_incident(iid).status.value == "RESPONDING"   # CISO ruled
    assert svc.store.unconsumed_approvals(iid) == []                   # ruling != approval
    cmd = svc.store.find_actor("band:id-cmd")
    iso = svc.request_action(iid, "isolate_host", "srv-db-01", cmd)
    assert iso.decision.rules_failed == ["P4", "P5"]   # compliance vetoed, didn't sign
    wipe = svc.request_action(iid, "wipe_host", "srv-db-01", cmd)
    assert wipe.decision.rules_failed == ["P6", "P7", "P8"]
    assert svc.request_action(iid, "preserve_disk_image", "srv-db-01", cmd).authorized

    again = import_band_context(svc, path, incident_ref="INC-C", roster=roster)
    assert (again.imported, again.duplicates) == (0, 7)
    assert svc.verify_audit(iid).ok

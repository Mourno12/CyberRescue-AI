"""``cyberrescue.live sync`` -- bounded, fail-safe Band -> Core synchronisation.

The Band room is MOCKED (a callable returning SYNTHETIC export documents in the
``collect_room`` shape); the Core, importer, ingestor, policy engine and the
Commander's action tool are REAL. Clock and sleep are injected. No network.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agents.commander import tools as cmd_tools
from cyberrescue.core.band_import import Roster
from cyberrescue.core.models import EventType
from cyberrescue.core.service import CoreService
from cyberrescue.live import sync as sync_mod
from cyberrescue.live.roster import build_roster
from cyberrescue.live.sync import (
    EXIT_CONFIG,
    EXIT_HALT,
    EXIT_INTERRUPTED,
    EXIT_OK,
    LiveSync,
    SyncHalt,
    SyncSettings,
    TransientSyncError,
)
from tests.test_live_preflight import _config

REPO = Path(__file__).resolve().parent.parent
ROOM = "room-live-1"
T0 = datetime(2026, 10, 11, 10, 0, tzinfo=timezone.utc)
ROSTER = Roster.from_mapping(build_roster(_config()))   # id-triage ... + human-ciso-1


def _blk(**k):
    return "```json\n" + json.dumps({"incident": "INC-C-2026-0042", **k}) + "\n```"


def msg(i, sender, content, *, kind="Agent", secs=None, mtype="text", room=ROOM):
    m = {"id": f"m{i:03d}", "chat_id": room, "sender_id": sender, "sender_type": kind,
         "sender_name": sender, "message_type": mtype, "content": content,
         "inserted_at": (T0 + timedelta(seconds=secs if secs is not None else i * 10))
         .isoformat()}
    return m


FLOW = [
    msg(1, "human-ciso-1", "@Triage alert INC-C", kind="User"),
    msg(2, "id-triage", _blk(type="BRIEF", summary="ransomware",
                             recruited=["threat_intel", "compliance", "commander"])),
    msg(3, "id-cmd", _blk(type="SIGNOFF_REQUEST", summary="isolate + image + wipe",
                          actions=["isolate_host", "preserve_disk_image", "wipe_host"])),
    msg(4, "id-ti", _blk(type="SIGNOFF", summary="ok")),
    msg(5, "id-comp", _blk(type="VETO", summary="hold", decision="BLOCK wipe_host",
                           regulation="GDPR-ART-33")),
    msg(6, "id-comp", _blk(type="SIGNOFF", summary="isolation fine",
                           approved=True, approver="ciso")),          # stray "approved"
    msg(7, "id-cmd", _blk(type="ESCALATION", summary="wipe needs the CISO")),
    msg(8, "human-ciso-1", "I approve the wipe after imaging.", kind="User"),
]


def doc(messages, views=None):
    return {"views": views or {r: {"ok": True, "messages": len(messages)} for r in
                               ("triage", "threat_intel", "compliance", "commander",
                                "facilitator")},
            "data": sorted(messages, key=lambda m: m["inserted_at"])}


class Feed:
    """MOCK room: returns the next document on each call (repeats the last)."""
    def __init__(self, *docs):
        self.docs, self.calls = list(docs), 0

    def __call__(self):
        self.calls += 1
        d = self.docs[min(self.calls, len(self.docs)) - 1]
        if isinstance(d, Exception):
            raise d
        return d


@pytest.fixture
def env(tmp_path):
    db = tmp_path / "live.db"
    svc = CoreService.open(db)
    svc.seed_assets_from_mock()
    svc.conn.close()
    return {"db": db, "log": tmp_path / "sync.jsonl", "lock": tmp_path / "live.db.lock"}


def make(env, feed, *, now=None, sleeps=None, **settings):
    clock = {"t": now or T0 + timedelta(minutes=5)}
    sleeps = [] if sleeps is None else sleeps
    s = SyncSettings(room_id=ROOM, incident_ref="INC-C",
                     **{"interval": 2.0, "max_polls": 5, "settle_seconds": 5.0, **settings})
    return LiveSync(s, ROSTER, open_core=lambda: CoreService.open(env["db"]), collect=feed,
                    log_path=env["log"], lock_path=env["lock"], now=lambda: clock["t"],
                    monotonic=lambda: 0.0, sleep=sleeps.append, echo=lambda _m: None), clock


def core(env):
    return CoreService.open(env["db"])


def log_lines(env):
    return [json.loads(x) for x in env["log"].read_text(encoding="utf-8").splitlines()]


# --- settings bounds ----------------------------------------------------------------------

@pytest.mark.parametrize("kw", [{"interval": 1.0}, {"interval": 601}, {"max_polls": 0},
                                {"max_polls": 10_001}, {"max_minutes": 0},
                                {"max_minutes": 241}, {"settle_seconds": -1},
                                {"max_consecutive_errors": 0}, {"room_id": " "}])
def test_polling_bounds_are_enforced(kw):
    base = {"room_id": ROOM, "incident_ref": "INC-C"}
    with pytest.raises(ValueError):
        SyncSettings(**{**base, **kw}).validate()


# --- import, idempotency, increments ----------------------------------------------------

def test_poll_imports_the_flow_and_records_state(env):
    s, _ = make(env, Feed(doc(FLOW)))
    rec = s.poll_once()
    assert rec["imported"] == 8 and rec["human_messages_imported"] == 2
    assert rec["status"] == "RESPONDING"                       # rostered CISO ruled
    assert rec["signoffs"] == ["compliance", "threat_intel"]
    assert rec["active_vetoes"] == ["wipe_host"]
    assert rec["verified_human_approvals_unconsumed"] == 0     # messages are not approvals
    assert "not approvals" in rec["approval_note"]
    svc = core(env)
    iid = "INC-C-2026-0042"
    head = svc.audit.events(iid)[-1]
    assert rec["chain_head"] == {"seq": head.seq, "hash": head.hash}
    assert {e.external_id for e in svc.audit.events(iid)
            if e.source == "band" and e.external_id} == set(rec["imported_message_ids"])
    assert svc.store.unconsumed_approvals(iid) == []
    types = {e.event_type for e in svc.audit.events(iid)}
    assert not types & {"APPROVAL_GRANTED", "ACTION_AUTHORIZED", "ACTION_EXECUTED"}
    svc.conn.close()


def test_repeated_polls_are_idempotent(env):
    s, _ = make(env, Feed(doc(FLOW)))
    s.poll_once()
    svc = core(env)
    before = [(e.seq, e.hash) for e in svc.audit.events("INC-C-2026-0042")]
    svc.conn.close()
    for _ in range(3):
        rec = s.poll_once()
        assert (rec["new"], rec["imported"], rec["events_appended"]) == (0, 0, 0)
    svc = core(env)
    assert [(e.seq, e.hash) for e in svc.audit.events("INC-C-2026-0042")] == before
    svc.conn.close()


def test_sync_after_a_manual_import_adds_nothing(env, tmp_path):
    from cyberrescue.core.band_import import import_band_context
    svc = core(env)
    import_band_context(svc, doc(FLOW), incident_ref="INC-C", roster=ROSTER)
    svc.conn.close()
    s, _ = make(env, Feed(doc(FLOW)))
    assert s.poll_once()["new"] == 0


def test_growing_room_imports_only_new_messages(env):
    s, _ = make(env, Feed(doc(FLOW[:3]), doc(FLOW[:6]), doc(FLOW)))
    assert [s.poll_once()["imported"] for _ in range(3)] == [3, 3, 2]


def test_young_messages_wait_to_settle(env):
    s, clock = make(env, Feed(doc(FLOW)), now=T0 + timedelta(seconds=52))  # m005 at +50s
    rec = s.poll_once()
    assert (rec["imported"], rec["waiting_to_settle"]) == (4, 4)
    clock["t"] = T0 + timedelta(minutes=5)
    assert s.poll_once()["imported"] == 4


def test_tool_calls_are_counted_not_ingested(env):
    tool = msg(9, "id-ti", '{"event": "on_tool_start"}', mtype="tool_call", secs=35)
    rec = make(env, Feed(doc([*FLOW[:4], tool])))[0].poll_once()
    assert rec["imported"] == 4 and rec["imported_message_ids"] == ["m001", "m002", "m003", "m004"]
    assert [x["id"] for x in rec["skipped"]] == ["m009"]
    assert rec["skipped"][0]["reason"].startswith("non_text:tool_call")


# --- fail-safe halts -------------------------------------------------------------------------

def test_out_of_order_arrival_halts_without_importing(env):
    s, _ = make(env, Feed(doc(FLOW[:2] + FLOW[3:5]), doc(FLOW[:5])))   # m003 shows up late
    s.poll_once()
    with pytest.raises(SyncHalt) as e:
        s.poll_once()
    assert e.value.code == "out_of_order" and e.value.details == ["m003 at 2026-10-11T10:00:30+00:00"]
    assert "operator investigation required" in e.value.reason
    svc = core(env)
    assert svc.audit.find_external("band", "m003") is None            # nothing imported
    svc.conn.close()


@pytest.mark.parametrize("bad,needle", [
    ({"sender_id": ""}, "no sender_id"),
    ({"sender_type": "Bot"}, "sender_type"),
    ({"inserted_at": "yesterday"}, "unparseable"),
    ({"chat_id": "another-room"}, "belongs to room"),
])
def test_invalid_messages_halt_before_import(env, bad, needle):
    broken = dict(FLOW[3], **bad)
    s, _ = make(env, Feed(doc([*FLOW[:3], broken])))
    with pytest.raises(SyncHalt) as e:
        s.poll_once()
    assert e.value.code == "invalid" and needle in e.value.details[0]
    svc = core(env)
    assert svc.store.resolve_incident("INC-C") is None or not [
        x for x in svc.audit.events("INC-C-2026-0042") if x.source == "band"]
    svc.conn.close()


@pytest.mark.parametrize("ref", ["INC-A", "INC-Z-2026-9999", "INC-C-2026-0099"])
def test_blocks_for_another_incident_halt(env, ref):
    other = msg(4, "id-ti", "```json\n" + json.dumps(
        {"type": "FINDING", "incident": ref, "summary": "wrong room"}) + "\n```")
    s, _ = make(env, Feed(doc([*FLOW[:3], other])))
    with pytest.raises(SyncHalt) as e:
        s.poll_once()
    assert e.value.code == "correlation" and ref in e.value.details[0]


def test_incomplete_views_import_nothing_and_halt_after_limit(env):
    partial = doc(FLOW, views={"triage": {"ok": True}, "compliance": {"ok": False,
                                                                       "error": "Timeout"}})
    s, _ = make(env, Feed(partial), max_consecutive_errors=2)
    with pytest.raises(TransientSyncError):
        s.poll_once()
    summary = s.run()
    assert summary.exit_code == EXIT_HALT and summary.halt["code"] == "incomplete"
    svc = core(env)
    assert svc.store.resolve_incident("INC-C") is None or not [
        x for x in svc.audit.events("INC-C-2026-0042") if x.source == "band"]
    svc.conn.close()


def test_transient_error_then_recovery_resets_the_counter(env):
    s, _ = make(env, Feed(ConnectionError("blip"), doc(FLOW)), max_polls=2,
                max_consecutive_errors=1 + 1)
    summary = s.run()
    assert summary.exit_code == EXIT_OK and summary.imported == 8
    kinds = [r["kind"] for r in log_lines(env)]
    assert kinds == ["start", "error", "poll", "stop"]


def test_import_that_would_create_an_approval_halts(env, monkeypatch):
    real = sync_mod.import_band_context

    def tampered(svc, msgs, **kw):          # MOCK: a broken importer that approves
        rep = real(svc, msgs, **kw)
        ciso = svc.store.find_actor("band:human-ciso-1")
        svc.grant_approval("INC-C-2026-0042", action="wipe_host", asset_id="srv-db-01",
                           approver_actor_id=ciso.id, reason="forged", source="band",
                           overrides_hold=True, overrides_veto=True)
        return rep
    monkeypatch.setattr(sync_mod, "import_band_context", tampered)
    s, _ = make(env, Feed(doc(FLOW)))
    with pytest.raises(SyncHalt) as e:
        s.poll_once()
    assert e.value.code == "invariant" and "APPROVAL_GRANTED" in e.value.details[0]


def test_unknown_incident_is_a_config_error(env):
    s = LiveSync(SyncSettings(room_id=ROOM, incident_ref="INC-20991231-0001", interval=2),
                 ROSTER, open_core=lambda: CoreService.open(env["db"]), collect=Feed(doc(FLOW)),
                 log_path=env["log"], lock_path=env["lock"], sleep=lambda _s: None,
                 echo=lambda _m: None)
    summary = s.run()
    assert summary.exit_code == EXIT_CONFIG and summary.halt["code"] == "config"


# --- bounded loop, shutdown, lock, log ----------------------------------------------------

def test_max_polls_bounds_the_loop(env):
    sleeps = []
    feed = Feed(doc(FLOW[:2]))
    s, _ = make(env, feed, sleeps=sleeps, max_polls=3)
    summary = s.run()
    assert (summary.exit_code, feed.calls, len(sleeps)) == (EXIT_OK, 3, 2)
    assert "max polls" in summary.reason and sleeps == [2.0, 2.0]


def test_max_minutes_bounds_the_loop(env):
    clock = {"t": 0.0}

    def sleep(_s):                     # each wait advances the fake monotonic clock 35 s
        clock["t"] += 35
    s = LiveSync(SyncSettings(room_id=ROOM, incident_ref="INC-C", interval=2, max_minutes=1),
                 ROSTER, open_core=lambda: CoreService.open(env["db"]),
                 collect=Feed(doc(FLOW[:2])), log_path=env["log"], lock_path=env["lock"],
                 now=lambda: T0 + timedelta(minutes=5), monotonic=lambda: clock["t"],
                 sleep=sleep, echo=lambda _m: None)
    summary = s.run()
    assert summary.polls == 2 and "max minutes" in summary.reason


def test_stops_by_itself_when_the_incident_is_resolved(env):
    done = [*FLOW, msg(9, "id-cmd", _blk(type="RESOLUTION", summary="done"))]
    feed = Feed(doc(done))
    summary = make(env, feed, max_polls=50)[0].run()
    assert summary.exit_code == EXIT_OK and "RESOLVED" in summary.reason and feed.calls == 1


def test_operator_interrupt_shuts_down_cleanly(env):
    def interrupt(_s):
        raise KeyboardInterrupt
    s, _ = make(env, Feed(doc(FLOW)), sleeps=None)
    s.sleep = interrupt
    summary = s.run()
    assert summary.exit_code == EXIT_INTERRUPTED and summary.imported == 8
    assert not env["lock"].exists()
    last = log_lines(env)[-1]
    assert (last["kind"], last["exit_code"]) == ("interrupted", EXIT_INTERRUPTED)


def test_one_sync_per_database(env):
    env["lock"].write_text("{}", encoding="utf-8")       # another sync is running
    feed = Feed(doc(FLOW))
    summary = make(env, feed)[0].run()
    assert summary.exit_code == EXIT_CONFIG and feed.calls == 0
    assert env["lock"].exists()                           # not ours to delete


def test_halt_releases_lock_and_is_logged(env):
    bad = dict(FLOW[2], chat_id="elsewhere")
    summary = make(env, Feed(doc([FLOW[0], FLOW[1], bad])))[0].run()
    assert summary.exit_code == EXIT_HALT and not env["lock"].exists()
    kinds = [r["kind"] for r in log_lines(env)]
    assert kinds == ["start", "halted"]
    last = log_lines(env)[-1]
    assert last["exit_code"] == EXIT_HALT and last["halt"]["code"] == "invalid"


def test_log_is_consistent_with_the_core(env):
    make(env, Feed(doc(FLOW[:4]), doc(FLOW)), max_polls=2)[0].run()
    polls = [r for r in log_lines(env) if r["kind"] == "poll"]
    svc = core(env)
    events = svc.audit.events("INC-C-2026-0042")
    by_seq = {e.seq: e.hash for e in events}
    for r in polls:
        assert by_seq[r["chain_head"]["seq"]] == r["chain_head"]["hash"]
    imported = [i for r in polls for i in r["imported_message_ids"]]
    assert sorted(imported) == sorted(m["id"] for m in FLOW)
    assert len(imported) == len(set(imported))                  # each message once
    assert svc.verify_audit("INC-C-2026-0042").ok
    svc.conn.close()


def test_sync_source_never_calls_authorizing_apis():
    src = Path(sync_mod.__file__).read_text(encoding="utf-8")
    for api in ("grant_approval(", "request_action(", "record_simulated_execution(",
                "check_commander_action(", "authorize("):
        assert api not in src


# --- end to end: synced sign-offs -> real Commander tool, gate in ENFORCE -------------------

def test_synced_signoffs_reach_the_gate_but_human_approval_is_still_required(env, monkeypatch,
                                                                              tmp_path):
    monkeypatch.setenv("CYBERRESCUE_DB_PATH", str(env["db"]))
    monkeypatch.setenv("CYBERRESCUE_GATE_LOG", str(tmp_path / "gate.jsonl"))
    monkeypatch.setenv("ACTIONS_LOG_PATH", str(tmp_path / "actions.jsonl"))
    monkeypatch.setenv("CYBERRESCUE_INCIDENT", "INC-C")
    monkeypatch.setenv("CYBERRESCUE_COMMANDER_REF", "band:id-cmd")
    monkeypatch.setenv("CYBERRESCUE_GATE_MODE", "enforce")

    def isolate():
        return cmd_tools._isolate_host(cmd_tools.isolate_host(asset_id="srv-db-01",
                                                              reason="contain"))
    s, _ = make(env, Feed(doc(FLOW[:4]), doc(FLOW)))
    s.poll_once()                                   # compliance has not signed yet
    r = isolate()
    assert r["status"] == "blocked_by_policy" and "P4" in r["reason_blocked"]
    s.poll_once()                                   # compliance SIGNOFF + CISO ruling synced
    r = isolate()
    assert r["status"] == "blocked_by_policy" and "P5" in r["reason_blocked"] \
        and "P4" not in r["reason_blocked"]         # the ruling message did NOT approve
    svc = core(env)
    ciso = svc.store.find_actor("band:human-ciso-1")
    svc.grant_approval("INC-C-2026-0042", action="isolate_host", asset_id="srv-db-01",
                       approver_actor_id=ciso.id, reason="core approve by the CISO")
    svc.conn.close()
    assert isolate()["status"] == "executed"
    assert isolate()["status"] == "blocked_by_policy"          # single-use
    assert s.poll_once()["new"] == 0                            # re-sync changes nothing
    svc = core(env)
    assert svc.verify_audit("INC-C-2026-0042").ok
    gate = svc.audit.events("INC-C-2026-0042", event_type=EventType.GATE_DECISION)
    assert [e.payload["verdict"] for e in gate] == ["DENY", "DENY", "ALLOW", "DENY"]
    svc.conn.close()


# --- CLI wiring (MOCKED Band REST clients) ------------------------------------------------

def _cli_env(tmp_path, monkeypatch, db):
    import yaml
    cfg = tmp_path / "agent_config.yaml"
    cfg.write_text(yaml.safe_dump(_config()), encoding="utf-8")
    monkeypatch.setenv("AGENT_CONFIG_PATH", str(cfg))
    monkeypatch.setenv("CYBERRESCUE_DB_PATH", str(db))


def test_cli_refuses_to_sync_with_an_incomplete_set_of_agent_views(tmp_path, monkeypatch):
    from cyberrescue.live import band_export, cli
    _cli_env(tmp_path, monkeypatch, tmp_path / "x.db")
    monkeypatch.setattr(band_export, "real_clients",
                        lambda: ({"triage": object()}, ["compliance"]))
    assert cli.main(["sync", "--room", ROOM, "--incident", "INC-C", "--once"]) == EXIT_CONFIG
    assert not (tmp_path / "x.db").exists()            # refused before touching the Core


def test_cli_once_imports_through_the_real_exporter(tmp_path, monkeypatch, env):
    from cyberrescue.live import band_export, cli
    from tests.test_live_roster_export import FakeClient
    _cli_env(tmp_path, monkeypatch, env["db"])
    views = {r: FakeClient(FLOW) for r in ("triage", "threat_intel", "compliance",
                                           "commander", "facilitator")}
    monkeypatch.setattr(band_export, "real_clients", lambda: (views, []))
    log = tmp_path / "cli_sync.jsonl"
    rc = cli.main(["sync", "--room", ROOM, "--incident", "INC-C", "--once", "--settle", "0",
                   "--log", str(log)])
    assert rc == EXIT_OK
    polls = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()
             if json.loads(x)["kind"] == "poll"]
    assert polls[0]["imported"] == 8 and polls[0]["status"] == "RESPONDING"
    assert not Path(str(env["db"]) + ".live-sync.lock").exists()

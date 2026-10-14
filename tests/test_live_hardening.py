"""Pre-live hardening: sync error handling, placeholder rejection, message
accounting, timestamp normalisation, out-of-order recovery, runtime-artifact
paths, audit checks, exporter truncation, verify-sync.

Band is MOCKED (in-memory feeds / fake REST clients, SYNTHETIC messages); the
Core, importer, ingestor and hash chain are REAL. SQLite lock errors are
SIMULATED by raising ``sqlite3.OperationalError``. No network.
"""

import json
import re
import sqlite3
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from cyberrescue.core.band_import import import_band_context
from cyberrescue.core.service import CoreService
from cyberrescue.live import band_export, cli
from cyberrescue.live import sync as sync_mod
from cyberrescue.live.preflight import FAIL, classify_secret, render, run_preflight
from cyberrescue.live.sync import (
    EXIT_HALT,
    EXIT_INTERRUPTED,
    EXIT_OK,
    LiveSync,
    SyncHalt,
    SyncSettings,
    order_key,
    parse_ts,
)
from cyberrescue.live.verify import verify_sync
from shared.config import (
    HandleConfigError,
    ciso_user_id,
    handles_from_config,
    is_placeholder,
    render_handles,
    render_prompt,
    unresolved_handles,
)
from tests.test_live_preflight import _config
from tests.test_live_sync import FLOW, ROOM, ROSTER, T0, Feed, _blk, doc, msg

REPO = Path(__file__).resolve().parent.parent
RUNBOOK = REPO / "docs" / "ca3" / "07-live-demo-runbook.md"


@pytest.fixture
def env(tmp_path):
    db = tmp_path / "live.db"
    svc = CoreService.open(db)
    svc.seed_assets_from_mock()
    svc.conn.close()
    return {"db": db, "log": tmp_path / "sync.jsonl", "lock": tmp_path / "live.db.lock",
            "tmp": tmp_path}


def make(env, feed, *, open_core=None, monotonic=None, sleep=None, **kw):
    s = SyncSettings(room_id=ROOM, incident_ref="INC-C",
                     **{"interval": 2.0, "max_polls": 3, "settle_seconds": 5.0, **kw})
    return LiveSync(s, ROSTER, open_core=open_core or (lambda: CoreService.open(env["db"])),
                    collect=feed, log_path=env["log"], lock_path=env["lock"],
                    now=lambda: T0 + timedelta(minutes=5),
                    monotonic=monotonic or (lambda: 0.0),
                    sleep=sleep or (lambda _s: None), echo=lambda _m: None)


def records(env):
    return [json.loads(x) for x in env["log"].read_text(encoding="utf-8").splitlines()]


def band_ids(env, incident="INC-C-2026-0042"):
    svc = CoreService.open(env["db"])
    try:
        if svc.store.resolve_incident(incident) is None:
            return []
        return [e.external_id for e in svc.audit.events(incident)
                if e.source == "band" and e.external_id]
    finally:
        svc.conn.close()


def assert_truthful_end(env, summary):
    last = records(env)[-1]
    assert last["exit_code"] == summary.exit_code
    assert (last["kind"] == "stop") == (summary.exit_code == EXIT_OK)
    assert not env["lock"].exists()
    return last


# === Priority 1 — error handling ===========================================================

def locked():
    return sqlite3.OperationalError("database is locked")


def test_db_lock_is_retried_then_succeeds(env):
    calls = {"n": 0}

    def flaky():                                    # SIMULATED: locked twice, then fine
        calls["n"] += 1
        if calls["n"] <= 2:
            raise locked()
        return CoreService.open(env["db"])
    sleeps = []
    summary = make(env, Feed(doc(FLOW)), open_core=flaky, sleep=sleeps.append,
                   max_polls=1).run()
    assert summary.exit_code == EXIT_OK and summary.imported == 8
    poll = [r for r in records(env) if r["kind"] == "poll"][0]
    assert poll["db_lock_retries"] == 2 and sleeps == [0.5, 1.0]
    assert [r["kind"] for r in records(env)].count("db_retry") == 2
    assert_truthful_end(env, summary)


def test_lock_mid_batch_keeps_committed_messages_and_continues(env, monkeypatch):
    real, seen = sync_mod.import_band_context, {"locked": False}

    def flaky(svc, msgs, **kw):                     # SIMULATED lock on the 3rd message, once
        if msgs[0]["id"] == "m003" and not seen["locked"]:
            seen["locked"] = True
            raise locked()
        return real(svc, msgs, **kw)
    monkeypatch.setattr(sync_mod, "import_band_context", flaky)
    summary = make(env, Feed(doc(FLOW)), max_polls=1).run()
    poll = [r for r in records(env) if r["kind"] == "poll"][0]
    assert summary.exit_code == EXIT_OK and poll["db_lock_retries"] == 1
    assert poll["imported_message_ids"] == [m["id"] for m in FLOW]     # each exactly once
    assert sorted(band_ids(env)) == sorted(m["id"] for m in FLOW)


def test_retry_exhaustion_by_attempts_halts_without_importing(env):
    def always():
        raise locked()
    summary = make(env, Feed(doc(FLOW)), open_core=always, db_lock_attempts=3).run()
    assert summary.exit_code == EXIT_HALT and summary.halt["code"] == "db_locked"
    assert "3 attempt(s)" in summary.halt["reason"]
    last = assert_truthful_end(env, summary)
    assert last["kind"] == "halted" and band_ids(env) == []


def test_retry_exhaustion_by_time_limit(env):
    clock = {"t": 0.0}

    def always():
        clock["t"] += 20                            # each attempt "takes" 20 s
        raise locked()
    summary = make(env, Feed(doc(FLOW)), open_core=always, monotonic=lambda: clock["t"],
                   db_lock_attempts=20, db_lock_timeout=30).run()
    assert summary.halt["code"] == "db_locked" and "2 attempt(s)" in summary.halt["reason"]
    assert_truthful_end(env, summary)


def test_non_retryable_sqlite_error_halts_immediately(env):
    calls = {"n": 0}

    def broken():
        calls["n"] += 1
        raise sqlite3.OperationalError("no such table: audit_events")
    summary = make(env, Feed(doc(FLOW)), open_core=broken).run()
    assert calls["n"] == 1 and summary.exit_code == EXIT_HALT
    last = assert_truthful_end(env, summary)
    assert last["halt"]["code"] == "unexpected"
    assert last["halt"]["exception_type"] == "OperationalError"


def test_unexpected_error_log_withholds_details(env, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("payload: CONFIDENTIAL-SYNTHETIC-TEXT")
    monkeypatch.setattr(sync_mod, "import_band_context", boom)
    summary = make(env, Feed(doc(FLOW))).run()
    last = assert_truthful_end(env, summary)
    assert last["kind"] == "halted" and last["halt"]["exception_type"] == "RuntimeError"
    assert "CONFIDENTIAL-SYNTHETIC-TEXT" not in env["log"].read_text(encoding="utf-8")


def test_base_exception_still_writes_a_failed_terminal_record(env):
    def sysexit(_s):
        raise SystemExit(9)
    s = make(env, Feed(doc(FLOW)), sleep=sysexit)
    with pytest.raises(SystemExit):
        s.run()
    last = records(env)[-1]
    assert last["kind"] == "halted" and last["exit_code"] == EXIT_HALT     # fail-safe default
    assert not env["lock"].exists()


def test_clean_shutdown_record_matches_exit_code(env):
    summary = make(env, Feed(doc(FLOW)), max_polls=2).run()
    last = assert_truthful_end(env, summary)
    assert (last["kind"], last["exit_code"], last["outcome"]) == ("stop", 0, "stop")


def test_interrupted_message_import_rolls_back(env, monkeypatch):
    from cyberrescue.core.ingest import ProtocolIngestor
    real = ProtocolIngestor._apply_block

    def interrupt(self, incident_id, actor, block, msg_uid, source):
        if block.type == "SIGNOFF" and "isolation fine" in block.summary:     # m006
            raise KeyboardInterrupt
        return real(self, incident_id, actor, block, msg_uid, source)
    monkeypatch.setattr(ProtocolIngestor, "_apply_block", interrupt)
    summary = make(env, Feed(doc(FLOW))).run()
    assert summary.exit_code == EXIT_INTERRUPTED
    assert sorted(band_ids(env)) == ["m001", "m002", "m003", "m004", "m005"]  # m006 rolled back
    svc = CoreService.open(env["db"])
    assert svc.verify_audit("INC-C-2026-0042").ok
    svc.conn.close()
    assert records(env)[-1]["kind"] == "interrupted"


def test_cli_boundary_turns_unexpected_errors_into_exit_1(monkeypatch, capsys):
    def boom(_args):
        raise RuntimeError("synthetic")
    monkeypatch.setattr(cli, "_cmd_preflight", boom)
    assert cli.main(["preflight"]) == 1
    assert "unexpected error: RuntimeError" in capsys.readouterr().err


# === Priority 2 — placeholder configuration =================================================

@pytest.mark.parametrize("value", ["<uuid>", "<key>", "<ciso band user id>", "REPLACE_WITH_X",
                                   "YOUR_API_KEY", "your-key", "sk-...", "{{api_key}}",
                                   "example-key", "changeme", "TODO", "xxxx"])
def test_placeholders_are_rejected(value):
    assert is_placeholder(value) and classify_secret(value) == "placeholder"
    assert ciso_user_id({"humans": {"ciso": {"user_id": value}}}) is None


@pytest.mark.parametrize("value", ["45101ead-d0e6-4dff-aba3-6aabb9298a42", "band_a_k3yZ9",
                                   "sk-proj-AbCtodoXYZ123", "agt_7781", "human-ciso-1"])
def test_unfamiliar_real_looking_values_are_not_rejected(value):
    assert not is_placeholder(value) and classify_secret(value) == "set"


@pytest.mark.parametrize("handle", ["@you/triage", "@youraccount/triage", "@owner/slug",
                                    "@<primary-account>/triage", "", "@/triage", "triage"])
def test_example_or_malformed_agent_handles_fail(handle):
    with pytest.raises(HandleConfigError, match="agents.triage.handle"):
        handles_from_config(_config(triage={"handle": handle}))


@pytest.mark.parametrize("handle", ["@you", "@youraccount", "@<primary-account>", ""])
def test_example_ciso_handles_fail(handle):
    with pytest.raises(HandleConfigError, match="humans.ciso.handle"):
        handles_from_config(_config(ciso={"handle": handle}))


def _runbook_yaml():
    text = RUNBOOK.read_text(encoding="utf-8")
    section = text[text.index("## 2. Configuration"):text.index("## 3. Preflight")]
    return yaml.safe_load(re.search(r"```yaml\n(.*?)```", section, re.S).group(1))


@pytest.mark.parametrize("source", ["runbook", "example_file"])
def test_documented_example_configurations_fail_preflight(tmp_path, source):
    (tmp_path / "scripts").mkdir()
    if source == "runbook":
        cfg = _runbook_yaml()
    else:
        cfg = yaml.safe_load((REPO / "agent_config.yaml.example").read_text(encoding="utf-8"))
    (tmp_path / "agent_config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    rep = run_preflight(tmp_path, environ={"OPENAI_API_KEY": "<key>",
                                           "ANTHROPIC_API_KEY": "<key>"}, import_agents=False)
    assert not rep.ok()
    fails = {(c.section, c.name) for c in rep.failures}
    for role in ("triage", "threat_intel", "compliance", "commander", "facilitator"):
        assert ("agent_config", role) in fails
    assert ("identities", "handles") in fails
    assert ("identities", "humans.ciso.user_id") in fails
    assert ("credentials", "OPENAI_API_KEY") in fails
    assert "NOT READY" in render(rep)


def test_missing_humans_section_fails_preflight_with_migration_message(tmp_path):
    cfg = _config()
    del cfg["humans"]
    (tmp_path / "agent_config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    rep = run_preflight(tmp_path, environ={}, import_agents=False)
    c = next(c for c in rep.checks if (c.section, c.name) == ("identities", "handles"))
    assert c.status == FAIL and "predates" in c.detail and "agent_config.yaml.example" in c.detail


# === Priority 3 — message accounting ==========================================================

TOOL = msg(9, "id-ti", '{"event": "on_tool_start"}', mtype="tool_call", secs=35)
RESULT = msg(10, "id-ti", '{"ok": true}', mtype="tool_result", secs=36)


def test_skipped_messages_are_reported_once_and_never_as_imported(env):
    s = make(env, Feed(doc([*FLOW, TOOL, RESULT])))
    first, second = s.poll_once(), s.poll_once()
    assert first["imported_message_ids"] == [m["id"] for m in FLOW]
    assert sorted(x["id"] for x in first["skipped"]) == ["m009", "m010"]
    assert all(x["reason"].startswith("non_text:") for x in first["skipped"])
    assert (second["new"], second["imported"], second["skipped"]) == (0, 0, [])


def test_counts_match_database_changes_across_mixed_batches(env):
    s = make(env, Feed(doc([*FLOW[:3], TOOL]), doc([*FLOW, TOOL, RESULT])))
    for _ in range(2):
        before = set(band_ids(env))
        rec = s.poll_once()
        after = set(band_ids(env))
        assert set(rec["imported_message_ids"]) == after - before
        assert rec["imported"] == len(after - before)
        assert not set(x["id"] for x in rec["skipped"]) & after          # skipped not in Core


def test_manual_import_then_sync_with_mixed_batch(env):
    svc = CoreService.open(env["db"])
    import_band_context(svc, doc(FLOW[:4]), incident_ref="INC-C", roster=ROSTER)
    svc.conn.close()
    rec = make(env, Feed(doc([*FLOW, TOOL]))).poll_once()
    assert rec["imported_message_ids"] == ["m005", "m006", "m007", "m008"]
    assert [x["id"] for x in rec["skipped"]] == ["m009"]
    assert sorted(band_ids(env)) == sorted(m["id"] for m in FLOW)


def test_concurrent_import_is_reported_as_duplicate_not_import(env, monkeypatch):
    real = sync_mod.import_band_context

    def racing(svc, msgs, **kw):                    # another process imports m005 first
        if msgs[0]["id"] == "m005":
            other = CoreService.open(env["db"])
            real(other, msgs, **kw)
            other.conn.close()
        return real(svc, msgs, **kw)
    monkeypatch.setattr(sync_mod, "import_band_context", racing)
    rec = make(env, Feed(doc(FLOW))).poll_once()
    assert "m005" not in rec["imported_message_ids"] and rec["duplicate_message_ids"] == ["m005"]
    assert band_ids(env).count("m005") == 1


# === Priority 4 — timestamp normalisation =======================================================

def test_equivalent_timestamps_normalise_to_one_instant():
    forms = ["2026-10-11T10:00:00Z", "2026-10-11T10:00:00+00:00", "2026-10-11T12:00:00+02:00",
             "2026-10-11T10:00:00.000000Z", "2026-10-11T05:30:00-04:30"]
    assert len({parse_ts(f) for f in forms}) == 1
    assert all(parse_ts(f).utcoffset() == timedelta(0) for f in forms)


@pytest.mark.parametrize("bad", ["2026-10-11T10:00:00", "2026-10-11 10:00", "yesterday", "",
                                 None, 1728640800])
def test_timezone_less_or_invalid_timestamps_are_rejected(bad):
    assert parse_ts(bad) is None


def _at(i, sender, content, ts, kind="Agent"):
    m = msg(i, sender, content, kind=kind)
    m["inserted_at"] = ts
    return m


def test_lexical_order_differs_but_import_follows_chronology(env):
    # Lexically "2026-10-11T09:..." < "2026-10-11T11:30:00+02:00", but 11:30+02:00 is
    # 09:30Z, i.e. AFTER 09:20Z. The SIGNOFF_REQUEST is chronologically first but
    # sorts lexically LAST -- a text sort would ingest the SIGNOFF before it.
    batch = [
        _at(1, "id-triage", _blk(type="BRIEF", summary="go"), "2026-10-11T09:00:00Z"),
        _at(2, "id-cmd", _blk(type="SIGNOFF_REQUEST", summary="isolate",
                              actions=["isolate_host"]), "2026-10-11T11:10:00+02:00"),
        _at(3, "id-ti", _blk(type="SIGNOFF", summary="ok"), "2026-10-11T09:20:00.5Z"),
        _at(4, "id-comp", _blk(type="SIGNOFF", summary="ok"), "2026-10-11T09:30:00Z"),
    ]
    lexical = [m["id"] for m in sorted(batch, key=lambda m: m["inserted_at"])]
    chronological = [m["id"] for m in sorted(batch, key=lambda m: parse_ts(m["inserted_at"]))]
    assert lexical != chronological                    # precondition, independent of the sync
    rec = make(env, Feed(doc(batch))).poll_once()
    assert rec["imported_message_ids"] == ["m001", "m002", "m003", "m004"]
    assert rec["signoffs"] == ["compliance", "threat_intel"] and rec["claims_rejected_total"] == 0


def test_equal_instants_are_ordered_by_message_id(env):
    a = _at(7, "id-triage", _blk(type="BRIEF", summary="b"), "2026-10-11T09:00:00+00:00")
    b = _at(3, "id-ti", "note", "2026-10-11T11:00:00+02:00")          # same instant
    assert [m["id"] for m in sorted([a, b], key=order_key)] == ["m003", "m007"]
    assert make(env, Feed(doc([a, b]))).poll_once()["imported_message_ids"] == ["m003", "m007"]


def test_invalid_timestamp_halts_before_any_import(env):
    bad = _at(3, "id-cmd", "x", "2026-10-11T10:00:30")                  # no zone
    with pytest.raises(SyncHalt) as e:
        make(env, Feed(doc([*FLOW[:2], bad]))).poll_once()
    assert e.value.code == "invalid" and "timezone-less" in e.value.details[0]
    assert band_ids(env) == []


def test_core_message_with_ambiguous_timestamp_halts(env):
    svc = CoreService.open(env["db"])
    m = dict(FLOW[0], inserted_at="2026-10-11T10:00:10")              # manual import, naive
    import_band_context(svc, [m], incident_ref="INC-C", roster=ROSTER)
    svc.conn.close()
    with pytest.raises(SyncHalt) as e:
        make(env, Feed(doc(FLOW))).poll_once()
    assert e.value.code == "invalid" and e.value.details == ["m001"]


def test_out_of_order_detected_across_formats(env):
    s = make(env, Feed(doc([FLOW[0], FLOW[1]]),
                       doc([FLOW[0], FLOW[1],
                            _at(3, "id-ti", "late", "2026-10-11T12:00:05+02:00")])))  # 10:00:05Z
    s.poll_once()
    with pytest.raises(SyncHalt) as e:
        s.poll_once()
    assert e.value.code == "out_of_order" and e.value.details[0].startswith("m003 at 2026-10-11T10:00:05")


# === Priority 5 — out-of-order recovery is manual ==============================================

def test_rerun_after_out_of_order_halts_again_and_never_skips(env):
    late = [FLOW[0], FLOW[1], FLOW[3]]
    s = make(env, Feed(doc(late)))
    s.poll_once()
    for _ in range(2):                                 # a re-run does not auto-resume
        again = make(env, Feed(doc(FLOW[:4])))
        summary = again.run()
        assert summary.halt["code"] == "out_of_order" and summary.exit_code == EXIT_HALT
        env["log"].unlink()
    assert "m003" not in band_ids(env)
    assert not hasattr(SyncSettings, "skip") and "--skip" not in RUNBOOK.read_text(encoding="utf-8")


# === Priority 6 — runtime artifacts stay outside the repository =================================

@pytest.mark.parametrize("rel", ["cyberrescue.db", "sub/x.db", "sub/../y.db", "."])
def test_paths_inside_the_repo_are_detected(rel):
    assert cli.inside_repo(REPO / rel)
    assert cli.inside_repo(Path(str(REPO / rel).swapcase())) or not Path("c:/").exists()


def test_paths_outside_the_repo_are_allowed(tmp_path):
    assert not cli.inside_repo(tmp_path / "live.db")
    assert not cli.inside_repo(REPO.parent / (REPO.name + "-other") / "x.db")   # prefix trap


def test_sync_refuses_a_database_inside_the_repo(monkeypatch, tmp_path):
    target = REPO / "tests" / ".." / "cyberrescue-refused-test.db"
    monkeypatch.setenv("CYBERRESCUE_DB_PATH", str(target))
    monkeypatch.setattr(band_export, "real_clients", lambda: pytest.fail("network reached"))
    assert cli.main(["sync", "--room", ROOM, "--incident", "INC-C", "--once"]) == 2
    assert not (REPO / "cyberrescue-refused-test.db").exists()


def test_sync_refuses_a_log_inside_the_repo(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERRESCUE_DB_PATH", str(tmp_path / "ok.db"))
    monkeypatch.setattr(band_export, "real_clients", lambda: pytest.fail("network reached"))
    assert cli.main(["sync", "--room", ROOM, "--incident", "INC-C", "--once",
                     "--log", str(REPO / "live_sync_test.jsonl")]) == 2


@pytest.mark.parametrize("argv", [["roster", "--out"], ["export-band", "--room", "r", "--out"]])
def test_roster_and_export_refuse_repo_paths(monkeypatch, argv):
    monkeypatch.setattr(band_export, "real_clients", lambda: pytest.fail("network reached"))
    out = REPO / "docs" / "accidental.json"
    assert cli.main([*argv, str(out)]) == 2 and not out.exists()


def test_runtime_artifact_names_are_gitignored():
    import subprocess
    for name in ("live_sync_abcd.jsonl", "cyberrescue.db.live-sync.lock", "x/y.live-sync.lock"):
        assert subprocess.run(["git", "-C", str(REPO), "check-ignore", "-q", name]).returncode == 0
    assert subprocess.run(["git", "-C", str(REPO), "check-ignore", "-q",
                           "cyberrescue/live/sync.py"]).returncode == 1


# === Priority 7 — audit checks: prevent vs detect ===============================================

def _tamper(db):
    c = sqlite3.connect(db)
    c.execute("DROP TRIGGER audit_events_no_update")
    c.execute("UPDATE audit_events SET payload = replace(payload, 'ransomware', 'EDITED') "
              "WHERE external_id = 'm002'")
    c.commit()
    c.close()


def test_tampered_chain_halts_before_import(env):
    s = make(env, Feed(doc(FLOW[:2]), doc(FLOW[:4])))
    s.poll_once()
    _tamper(env["db"])
    with pytest.raises(SyncHalt) as e:
        s.poll_once()
    assert e.value.code == "audit_pre" and "content hash mismatch" in e.value.details[0]
    assert "m003" not in band_ids(env)                  # PREVENTED: nothing written


def test_post_import_audit_failure_is_detected_after_the_write(env):
    from cyberrescue.core.audit import VerifyResult
    calls = {"n": 0}

    def opener():
        svc = CoreService.open(env["db"])
        real = svc.verify_audit

        def verify(iid):
            calls["n"] += 1
            return real(iid) if calls["n"] == 1 else VerifyResult(
                ok=False, checked=0, errors=["SIMULATED post-import failure"])
        svc.verify_audit = verify
        return svc
    with pytest.raises(SyncHalt) as e:
        make(env, Feed(doc(FLOW[:3])), open_core=opener).poll_once()
    assert e.value.code == "audit" and "committed" in e.value.reason
    assert sorted(band_ids(env)) == ["m001", "m002", "m003"]     # DETECTED: already written


# === Priority 9 — exporter truncation, handles ===================================================

class FullPages:
    """MOCK: every page is full and no total is ever reported."""
    def __init__(self):
        self.agent_api_context = self

    def get_agent_chat_context(self, chat_id, page, page_size):
        return SimpleNamespace(data=[{"id": f"p{page}-{i}", "chat_id": chat_id}
                                     for i in range(page_size)], meta=None)


def test_truncated_view_is_marked_incomplete(monkeypatch):
    monkeypatch.setattr(band_export, "MAX_PAGES", 2)
    d = band_export.collect_room({"triage": FullPages()}, ROOM)
    assert d["views"]["triage"]["ok"] is False and d["views"]["triage"]["error"] == "TruncatedView"
    assert d["message_count"] == 0


def test_exactly_full_last_page_with_total_is_complete(monkeypatch):
    monkeypatch.setattr(band_export, "MAX_PAGES", 2)

    class Two(FullPages):
        def get_agent_chat_context(self, chat_id, page, page_size):
            r = super().get_agent_chat_context(chat_id, page, page_size)
            r.meta = SimpleNamespace(total_pages=2)
            return r
    d = band_export.collect_room({"triage": Two()}, ROOM)
    assert d["views"]["triage"]["ok"] is True and d["message_count"] == 2 * band_export.PAGE_SIZE


def test_swapped_handles_are_not_rewritten_twice():
    h = {"triage": "@merolavtech/threat-intel", "threat_intel": "@merolavtech/triage",
         "compliance": "@c/compliance", "commander": "@a/commander",
         "facilitator": "@a/facilitator", "ciso": "@a"}
    assert render_handles("@merolavtech/triage|@merolavtech/threat-intel", h) == \
        "@merolavtech/threat-intel|@merolavtech/triage"


def test_unresolved_bare_handles_are_detected(tmp_path):
    h = handles_from_config(_config())
    assert unresolved_handles("ping @stranger, or @mentioning @acme; ops@x.com", h) == ["@stranger"]
    cfg = tmp_path / "agent_config.yaml"
    cfg.write_text(yaml.safe_dump(_config()), encoding="utf-8")
    p = tmp_path / "prompt.md"
    p.write_text("escalate to `@merolavtech` or `@someoneelse`", encoding="utf-8")
    with pytest.raises(HandleConfigError, match="@someoneelse"):
        render_prompt(p, cfg)


# === verify-sync (read-only consistency check) ===================================================

def test_verify_sync_passes_for_a_clean_run_and_flags_problems(env):
    exported = doc([*FLOW, TOOL])
    exported["views"] = {"triage": {"ok": True}}
    export = env["tmp"] / "export.json"
    export.write_text(json.dumps(exported), encoding="utf-8")
    make(env, Feed(exported), max_polls=1).run()
    chk = verify_sync(db=env["db"], export=export, log=env["log"], incident_ref="INC-C")
    assert chk.ok, chk.problems
    assert chk.facts["export_text_messages"] == 8 and chk.facts["core_band_messages"] == 8
    # a message missing from the Core and a dirty end are both reported
    exported["data"].append(msg(11, "id-ti", "never synced", secs=120))
    export.write_text(json.dumps(exported), encoding="utf-8")
    with env["log"].open("a", encoding="utf-8") as f:
        f.write(json.dumps({"kind": "halted", "exit_code": 1}) + "\n")
    chk = verify_sync(db=env["db"], export=export, log=env["log"], incident_ref="INC-C")
    assert not chk.ok
    assert any("m011" in p for p in chk.problems) and any("did not end cleanly" in p
                                                         for p in chk.problems)


def test_verify_sync_is_read_only(env):
    exported = doc(FLOW)
    export = env["tmp"] / "export.json"
    export.write_text(json.dumps(exported), encoding="utf-8")
    make(env, Feed(exported), max_polls=1).run()
    before = env["db"].read_bytes()
    verify_sync(db=env["db"], export=export, log=env["log"], incident_ref="INC-C")
    assert env["db"].read_bytes() == before

"""CyberRescue Phase 7 — external keyed audit anchors: security and regression.

The attacker modelled here can read and write the SQLite database file (drop
triggers, rewrite rows, recompute every SHA-256 hash) but does not hold the
external anchor key. Numbers refer to the Phase 7 security requirements.
"""

import ast
import json
import logging
import re
import sqlite3
from pathlib import Path

import pytest

import cyberrescue.core.anchor as anchor_mod
from cyberrescue.core.anchor import (
    AnchorFormatError,
    AnchorSignatureError,
    build_checkpoint,
    load_key,
    open_signed,
    verify_checkpoint,
)
from cyberrescue.core.cli import main
from cyberrescue.core.db import connect as core_connect
from cyberrescue.core.models import EventType
from cyberrescue.core.service import CoreService
from cyberrescue.execution.recorder import record_plan
from cyberrescue.execution.records import verify_accountability
from cyberrescue.investigation.builder import build_case
from cyberrescue.investigation.readonly import open_readonly
from cyberrescue.response.planner import build_plan
from tests._execution_factory import plans_of, request
from tests._response_factory import authority_core, writable_copy
from tests.test_anchor_checkpoint import HOSTILE_CHAIN
from tests.test_anchor_verify import INC_A, INC_C, raw, rewrite_and_rehash
from tests.test_investigation_security import AUTHORITY, WRITE_SQL, db_state

SQL_KEYWORDS = re.compile(WRITE_SQL.pattern)
ANCHOR_SRC = Path(anchor_mod.__file__)


@pytest.fixture(scope="module")
def base(tmp_path_factory):
    path = authority_core(tmp_path_factory.mktemp("anc") / "core.db")
    svc = CoreService.open(path)
    svc.register_actor("system", "executor", "e", "test:executor")
    svc.conn.close()
    return path


@pytest.fixture
def db(base, tmp_path):
    return writable_copy(base, tmp_path / "core.db")


@pytest.fixture
def keys(tmp_path, capsys):
    out = {}
    for name in ("a", "b"):
        path = tmp_path / "keys" / f"{name}.key"
        assert main(["anchor-keygen", "--out", str(path)]) == 0
        out[name] = (path, path.read_text().splitlines()[1])
    capsys.readouterr()
    return out


def cli(capsys, *argv):
    code = main([str(a) for a in argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def make_anchor(capsys, db, key, out):
    code, _, err = cli(capsys, "--db", db, "anchor", "--out", out, "--key-file", key)
    assert code == 0, err
    return out


def verify(capsys, db, anchor, key, *extra):
    return cli(capsys, "--db", db, "verify", *extra, "--anchor", anchor, "--key-file", key)


def statuses(out):
    return dict(re.findall(r"\[core\]   (\S+): (\w+) \(anchored", out))


# --- 1-5: the database-only attacker ----------------------------------------------------------

def test_01_02_rewritten_prefix_with_recomputed_hashes_and_no_triggers(db, keys, capsys,
                                                                        tmp_path):
    key = keys["a"][0]
    anchor = make_anchor(capsys, db, key, tmp_path / "a.json")
    rewrite_and_rehash(db, INC_C, 3, {"approved": True, "forged": "history"})
    conn = sqlite3.connect(db)
    try:                                               # the attacker left no trigger behind
        assert "audit_events_no_update" not in {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'")}
    finally:
        conn.close()
    code, out, _ = cli(capsys, "--db", db, "verify", "--incident", "INC-C")
    assert code == 0                                   # SHA-256 chain alone is fooled
    code, out, _ = verify(capsys, db, anchor, key)
    assert code == 1 and statuses(out)[INC_C] == "rewritten"


def test_03_tail_truncation_is_detected(db, keys, capsys, tmp_path):
    key = keys["a"][0]
    anchor = make_anchor(capsys, db, key, tmp_path / "a.json")
    raw(db, ("DELETE FROM event_links WHERE from_uid IN (SELECT uid FROM audit_events WHERE "
             "chain = ? AND seq > (SELECT MAX(seq) - 3 FROM audit_events WHERE chain = ?))",
             (INC_C, INC_C)),
        ("DELETE FROM audit_events WHERE chain = ? AND seq > (SELECT MAX(seq) - 3 FROM "
         "audit_events WHERE chain = ?)", (INC_C, INC_C)),
        drop=("audit_events_no_delete", "event_links_no_delete"))
    assert cli(capsys, "--db", db, "verify", "--incident", "INC-C")[0] == 0
    code, out, _ = verify(capsys, db, anchor, key)
    assert code == 1 and statuses(out)[INC_C] == "truncated"


def test_04_truncating_recorded_executions_before_the_anchor_is_detected(db, keys, capsys,
                                                                         tmp_path):
    plan = plans_of(db)["INC-A"]
    request(db, plan)
    svc = CoreService.open(db)
    ex = svc.store.find_actor("test:executor").id
    svc.conn.close()
    assert record_plan(db, plan.to_json(), recorder_actor_id=ex).recorded
    key = keys["a"][0]
    anchor = make_anchor(capsys, db, key, tmp_path / "a.json")
    raw(db, ("DELETE FROM execution_records",),
        ("DELETE FROM event_links WHERE from_uid IN (SELECT uid FROM audit_events WHERE "
         "event_type IN ('ACTION_EXECUTED','ACTION_VERIFIED'))",),
        ("DELETE FROM audit_events WHERE event_type IN ('ACTION_EXECUTED','ACTION_VERIFIED')",),
        drop=("execution_records_no_delete", "audit_events_no_delete",
              "event_links_no_delete"))
    assert cli(capsys, "--db", db, "verify", "--incident", "INC-A")[0] == 0
    code, out, _ = verify(capsys, db, anchor, key)
    assert code == 1 and statuses(out)[INC_A] == "truncated"


def test_05_complete_chain_deletion_is_detected(db, keys, capsys, tmp_path):
    key = keys["a"][0]
    anchor = make_anchor(capsys, db, key, tmp_path / "a.json")
    raw(db, ("DELETE FROM event_links WHERE from_uid IN (SELECT uid FROM audit_events WHERE "
             "chain = ?) OR to_uid IN (SELECT uid FROM audit_events WHERE chain = ?)",
             (INC_A, INC_A)),
        ("DELETE FROM audit_events WHERE chain = ?", (INC_A,)),
        drop=("audit_events_no_delete", "event_links_no_delete"))
    code, out, _ = verify(capsys, db, anchor, key)
    assert code == 1 and statuses(out)[INC_A] == "missing"


# --- 6-8: the anchor itself --------------------------------------------------------------------

def test_06_a_wrong_key_fails(db, keys, capsys, tmp_path):
    anchor = make_anchor(capsys, db, keys["a"][0], tmp_path / "a.json")
    code, out, err = verify(capsys, db, anchor, keys["b"][0])
    assert code == 2 and "HMAC" in err and out == ""


@pytest.mark.parametrize("change", [
    lambda d: d["checkpoint"]["chains"][INC_C].update(seq=1),
    lambda d: d["checkpoint"]["chains"][INC_C].update(hash="0" * 64),
    lambda d: d["checkpoint"].update(created_at="2020-01-01T00:00:00+00:00"),
    lambda d: d.update(hmac_sha256="f" * 64)])
def test_07_a_modified_anchor_fails(db, keys, capsys, tmp_path, change):
    anchor = make_anchor(capsys, db, keys["a"][0], tmp_path / "a.json")
    doc = json.loads(anchor.read_text())
    change(doc)
    anchor.chmod(0o600)
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(doc), encoding="ascii")
    code, out, err = verify(capsys, db, edited, keys["a"][0])
    assert code == 2 and out == ""


@pytest.mark.parametrize("change", [
    lambda c: c.pop(INC_A),
    lambda c: c.update({"INC-Z-2026-0001": {"seq": 1, "hash": "1" * 64}})])
def test_08_adding_or_removing_an_anchored_chain_fails(db, keys, capsys, tmp_path, change):
    anchor = make_anchor(capsys, db, keys["a"][0], tmp_path / "a.json")
    doc = json.loads(anchor.read_text())
    change(doc["checkpoint"]["chains"])
    with pytest.raises(AnchorSignatureError):
        open_signed(json.dumps(doc), load_key(keys["a"][0]))


# --- 9: the key never leaks -------------------------------------------------------------------

def test_09_the_key_never_appears_anywhere(db, keys, capsys, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    key, secret = keys["a"]
    texts = []
    for argv in (("--db", db, "anchor", "--out", tmp_path / "a.json", "--key-file", key),
                 ("--db", db, "verify", "--anchor", tmp_path / "a.json", "--key-file", key),
                 ("--db", db, "verify", "--anchor", tmp_path / "a.json", "--key-file",
                  keys["b"][0]),
                 ("--db", db, "verify", "--anchor", tmp_path / "nope.json", "--key-file", key),
                 ("--db", db, "anchor", "--out", tmp_path / "a.json", "--key-file", key)):
        texts += list(cli(capsys, *argv)[1:])
    texts.append((tmp_path / "a.json").read_text())
    texts += [r.getMessage() for r in caplog.records]
    with open_readonly(db) as ro:                       # reports / exports
        texts += [build_case(ro, "INC-C").to_json(), build_plan(ro, "INC-C").to_json()]
    conn = sqlite3.connect(db)
    try:
        texts.append("\n".join(conn.iterdump()))
    finally:
        conn.close()
    blob = "\n".join(texts)
    for i in range(0, len(secret) - 16, 4):             # no 8-byte window anywhere
        assert secret[i:i + 16] not in blob
    assert repr(load_key(key)) == "AnchorKey(<redacted>)"


# --- 10-13: anchoring changes nothing ------------------------------------------------------------

def test_10_11_anchoring_creates_no_state_and_leaves_chains_byte_identical(db, keys, capsys,
                                                                           tmp_path):
    before = db_state(db)
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY chain, seq").fetchall()
    finally:
        conn.close()
    make_anchor(capsys, db, keys["a"][0], tmp_path / "a.json")
    verify(capsys, db, tmp_path / "a.json", keys["a"][0])
    assert db_state(db) == before                       # approvals, requests, actors, ...
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT * FROM audit_events ORDER BY chain, seq").fetchall() == rows
    finally:
        conn.close()


def test_12_13_case_and_plan_hashes_are_unchanged_by_anchoring(db, keys, capsys, tmp_path):
    with open_readonly(db) as ro:
        before = {r: (build_case(ro, r).case_sha256, build_plan(ro, r).plan_sha256)
                  for r in ("INC-A", "INC-B", "INC-C")}
    make_anchor(capsys, db, keys["a"][0], tmp_path / "a.json")
    assert verify(capsys, db, tmp_path / "a.json", keys["a"][0])[0] == 0
    with open_readonly(db) as ro:
        after = {r: (build_case(ro, r).case_sha256, build_plan(ro, r).plan_sha256)
                 for r in ("INC-A", "INC-B", "INC-C")}
    assert after == before


# --- 14-16: growth, existing checks, accountability ---------------------------------------------

def test_14_legitimate_growth_is_accepted(db, keys, capsys, tmp_path):
    anchor = make_anchor(capsys, db, keys["a"][0], tmp_path / "a.json")
    plan = plans_of(db)["INC-A"]
    request(db, plan)                                   # new requests, decisions, authorizations
    code, out, _ = verify(capsys, db, anchor, keys["a"][0])
    assert code == 0 and statuses(out)[INC_A] == "grown"


def test_15_existing_audit_and_evidence_verification_still_runs(db, keys, capsys, tmp_path):
    anchor = make_anchor(capsys, db, keys["a"][0], tmp_path / "a.json")
    code, out, _ = verify(capsys, db, anchor, keys["a"][0])
    assert "[core] __system__: OK" in out and "[core] evidence INC-C-2026-0042: OK" in out
    raw(db, ("UPDATE evidence SET raw = 'x' WHERE rowid = 1",), drop=("evidence_no_update",))
    code, out, _ = verify(capsys, db, anchor, keys["a"][0])
    assert code == 1 and "TAMPERED" in out and "): OK" in out     # evidence check, not anchor


def test_16_forged_trailing_executions_remain_verify_accountabilitys_job(db, keys, capsys,
                                                                         tmp_path):
    anchor = make_anchor(capsys, db, keys["a"][0], tmp_path / "a.json")
    svc = CoreService.open(db)
    svc.store.audit.append(EventType.ACTION_EXECUTED, incident_id=INC_C, source="attacker",
                           payload={"mode": "real"})
    svc.conn.close()
    code, out, _ = verify(capsys, db, anchor, keys["a"][0])
    assert code == 0 and statuses(out)[INC_C] == "grown"          # growth, by design
    with open_readonly(db) as ro:
        assert any("has no execution record" in e for e in verify_accountability(ro, INC_C))


# --- 17: hostile identifiers -------------------------------------------------------------------

def test_17_hostile_chain_ids_cannot_break_canonical_json(db, keys, capsys, tmp_path):
    raw(db, ("INSERT INTO audit_events(uid, chain, incident_id, seq, ts, event_type, source, "
             "payload, prev_hash, hash) VALUES ('h1', ?, NULL, 1, '2026-10-04T00:00:00+00:00', "
             "'TEST', 'test', '{}', ?, ?)", (HOSTILE_CHAIN, "0" * 64, "e" * 64)),)
    anchor = make_anchor(capsys, db, keys["a"][0], tmp_path / "a.json")
    text = anchor.read_text(encoding="ascii")
    assert text.count("\n") == 1 and text.isascii()
    cp = open_signed(text, load_key(keys["a"][0]))
    assert HOSTILE_CHAIN in cp.chains
    code, out, _ = verify(capsys, db, anchor, keys["a"][0])
    # The anchor section (Phase 7) escapes database-controlled chain ids. The lines
    # before it are the unchanged pre-Phase-7 `verify` report (not asserted here).
    section = out[out.index("[core] anchor "):]
    assert section.isascii() and "\x1b" not in section and "‮" not in section
    assert "INC-\"evil\"\\u000a" in section             # escaped on the terminal


# --- 18-19: keys ---------------------------------------------------------------------------------

@pytest.mark.parametrize("content", [None, "", "garbage", "cyberrescue-anchor-key/1\n" + "00" * 32,
                                     "cyberrescue-anchor-key/1\n" + "ab" * 16])
def test_18_missing_malformed_and_weak_keys_fail_closed(db, capsys, tmp_path, content,
                                                        monkeypatch):
    monkeypatch.delenv("CYBERRESCUE_ANCHOR_KEY_FILE", raising=False)
    key = tmp_path / "bad.key"
    if content is not None:
        key.write_text(content)
    out = tmp_path / "a.json"
    code, stdout, err = cli(capsys, "--db", db, "anchor", "--out", out, "--key-file", key)
    assert code == 2 and not out.exists()
    out.write_text("{}", encoding="ascii")
    code, stdout, err = verify(capsys, db, out, key)
    assert code == 2 and stdout == ""


def test_19_key_overwrite_is_refused(keys, capsys):
    path, secret = keys["a"]
    code, _, err = cli(capsys, "anchor-keygen", "--out", path)
    assert code == 2 and "refusing to overwrite" in err
    assert path.read_text().splitlines()[1] == secret


# --- 20: unchanged behaviour without --anchor ---------------------------------------------------

def test_20_verify_without_anchor_is_unchanged(db, keys, capsys, tmp_path):
    anchor = make_anchor(capsys, db, keys["a"][0], tmp_path / "a.json")
    for extra in ((), ("--incident", "INC-C")):
        code, plain, err = cli(capsys, "--db", db, "verify", *extra)
        code2, anchored, _ = verify(capsys, db, anchor, keys["a"][0], *extra)
        assert code == code2 == 0 and "anchor" not in plain and anchored.startswith(plain)
    raw(db, ("UPDATE audit_events SET payload = '{}' WHERE chain = ? AND seq = 2", (INC_C,)),
        drop=("audit_events_no_update",))
    code, plain, _ = cli(capsys, "--db", db, "verify")
    assert code == 1 and "TAMPERED" in plain and "anchor" not in plain


# --- static guarantees for anchor.py ----------------------------------------------------------

def _tree():
    return ast.parse(ANCHOR_SRC.read_text(encoding="utf-8"))


def test_anchor_module_contains_no_write_sql():
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert not SQL_KEYWORDS.match(node.value), node.value[:40]
            assert not re.search(r"\b(INSERT|UPDATE|DELETE|DROP)\b", node.value), \
                node.value[:60]


def test_anchor_module_calls_no_authority_operation():
    tree = _tree()
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | \
        {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | \
        {a.name.split(".")[-1] for n in ast.walk(tree) if isinstance(n, (ast.Import,
                                                                         ast.ImportFrom))
         for a in n.names}
    assert not names & AUTHORITY, names & AUTHORITY
    for word in ("approval", "approve", "grant", "request_action", "authorize",
                 "executescript", "record_simulated", "commit"):
        assert not [n for n in names if word in n.lower()], word
    # The AuditLog is only ever asked to verify (never to append), and no `.audit` is used.
    log_calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                 and n.func.value.id == "log"}
    assert log_calls == {"verify"} and "audit" not in names
    # Every SQL statement the module runs is a SELECT.
    sql = [a.value for n in ast.walk(tree) if isinstance(n, ast.Call)
           and isinstance(n.func, ast.Attribute) and n.func.attr == "execute"
           for a in n.args[:1] if isinstance(a, ast.Constant) and isinstance(a.value, str)]
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute) and n.func.attr == "execute"]
    assert sql and len(sql) == len(calls) and all(s.lstrip().startswith("SELECT") for s in sql)


def test_anchor_module_writes_only_new_key_files():
    opens = [n for n in ast.walk(_tree()) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == "open"]
    assert len(opens) == 1
    assert [a.value for a in opens[0].args if isinstance(a, ast.Constant)] == ["xb"]
    for n in ast.walk(_tree()):
        if isinstance(n, ast.Attribute):
            assert n.attr not in ("write_text", "write_bytes", "unlink", "rename", "rmdir")


def test_build_and_verify_never_write_even_on_a_writable_connection(db, keys):
    before = db_state(db)
    conn = core_connect(db)
    try:
        from cyberrescue.core.anchor import sign_checkpoint
        key = load_key(keys["a"][0])
        signed = sign_checkpoint(build_checkpoint(conn), key)
        assert verify_checkpoint(conn, signed, key).ok
        with pytest.raises(AnchorFormatError):
            verify_checkpoint(conn, "{}", key)
    finally:
        conn.close()
    assert db_state(db) == before

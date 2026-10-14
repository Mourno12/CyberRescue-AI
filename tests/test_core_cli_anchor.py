"""CyberRescue Phase 7 (7-4) — `core anchor-keygen`, `core anchor`, `core verify --anchor`."""

import json
import sqlite3

import pytest

from cyberrescue.core.anchor import KEY_FILE_ENV, load_key, open_signed
from cyberrescue.core.cli import main
from cyberrescue.core.db import REPO_ROOT
from cyberrescue.core.service import CoreService
from tests.test_anchor_verify import INC_A, INC_C, make_core, raw, rewrite_and_rehash
from tests.test_investigation_security import db_state


@pytest.fixture
def env(tmp_path):
    db = make_core(tmp_path / "core.db")
    keydir = tmp_path / "keys"
    return db, keydir


def run(capsys, *argv):
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def keygen(capsys, path):
    code, out, err = run(capsys, "anchor-keygen", "--out", str(path))
    assert code == 0, err
    return path, path.read_text().splitlines()[1]


def make_anchor(capsys, db, key, out):
    code, stdout, err = run(capsys, "--db", str(db), "anchor", "--out", str(out),
                            "--key-file", str(key))
    assert code == 0, err
    return out


# --- anchor-keygen ----------------------------------------------------------------------------

def test_keygen_writes_a_key_and_never_prints_it(env, capsys):
    _, keydir = env
    code, out, err = run(capsys, "anchor-keygen", "--out", str(keydir / "a.key"))
    secret = (keydir / "a.key").read_text().splitlines()[1]
    assert code == 0 and "never printed" in out
    assert secret not in out + err and len(load_key(keydir / "a.key")) == 32


def test_keygen_refuses_overwrite_and_the_repository(env, capsys):
    _, keydir = env
    path, _ = keygen(capsys, keydir / "a.key")
    before = path.read_bytes()
    assert run(capsys, "anchor-keygen", "--out", str(path))[0] == 2
    assert path.read_bytes() == before
    inside = REPO_ROOT / "anchor-test.key"
    code, _, err = run(capsys, "anchor-keygen", "--out", str(inside))
    assert code == 2 and "inside the repository" in err and not inside.exists()


# --- anchor ---------------------------------------------------------------------------------

def test_anchor_writes_a_signed_checkpoint_and_changes_nothing(env, capsys, tmp_path):
    db, keydir = env
    key, secret = keygen(capsys, keydir / "a.key")
    before = db_state(db)
    out = make_anchor(capsys, db, key, tmp_path / "a.json")
    assert db_state(db) == before                      # no event, no authority state
    text = out.read_text(encoding="ascii")
    cp = open_signed(text, load_key(key))
    assert {INC_C, INC_A, "__system__"} <= set(cp.chains) and cp.schema_version == 3
    assert secret not in text


def test_anchor_takes_the_key_from_the_environment(env, capsys, tmp_path, monkeypatch):
    db, keydir = env
    key, _ = keygen(capsys, keydir / "a.key")
    monkeypatch.setenv(KEY_FILE_ENV, str(key))
    assert run(capsys, "--db", str(db), "anchor", "--out", str(tmp_path / "a.json"))[0] == 0
    code, out, _ = run(capsys, "--db", str(db), "verify", "--anchor", str(tmp_path / "a.json"))
    assert code == 0 and "): OK" in out


def test_anchor_errors_exit_2_without_side_effects(env, capsys, tmp_path, monkeypatch):
    db, keydir = env
    key, _ = keygen(capsys, keydir / "a.key")
    monkeypatch.delenv(KEY_FILE_ENV, raising=False)
    target = tmp_path / "a.json"
    code, _, err = run(capsys, "--db", str(db), "anchor", "--out", str(target))
    assert code == 2 and "no anchor key" in err and not target.exists()
    missing = tmp_path / "none.db"
    code, _, err = run(capsys, "--db", str(missing), "anchor", "--out", str(target),
                       "--key-file", str(key))
    assert code == 2 and "never creates" in err and not missing.exists()
    make_anchor(capsys, db, key, target)
    before = target.read_bytes()
    assert run(capsys, "--db", str(db), "anchor", "--out", str(target),
               "--key-file", str(key))[0] == 2
    assert target.read_bytes() == before                  # never overwritten
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not sqlite" * 100)
    assert run(capsys, "--db", str(junk), "anchor", "--out", str(tmp_path / "j.json"),
               "--key-file", str(key))[0] == 2


def test_anchor_refuses_an_unmigrated_database(env, capsys, tmp_path):
    db, keydir = env
    key, _ = keygen(capsys, keydir / "a.key")
    raw(db, ("UPDATE schema_meta SET value = '2' WHERE key = 'schema_version'",))
    code, _, err = run(capsys, "--db", str(db), "anchor", "--out", str(tmp_path / "a.json"),
                       "--key-file", str(key))
    assert code == 2 and "run `python -m cyberrescue.core init` first" in err


# --- verify ---------------------------------------------------------------------------------

def test_verify_without_anchor_is_unchanged(env, capsys, tmp_path):
    db, keydir = env
    key, _ = keygen(capsys, keydir / "a.key")
    anchor = make_anchor(capsys, db, key, tmp_path / "a.json")
    code, plain, _ = run(capsys, "--db", str(db), "verify")
    assert code == 0 and "anchor" not in plain
    code2, anchored, _ = run(capsys, "--db", str(db), "verify", "--anchor", str(anchor),
                             "--key-file", str(key))
    assert code2 == 0 and anchored.startswith(plain)  # same report, then the anchor section
    code, plain_i, _ = run(capsys, "--db", str(db), "verify", "--incident", "INC-C")
    assert code == 0 and "anchor" not in plain_i


def test_verify_anchor_ok_growth_and_one_incident(env, capsys, tmp_path):
    db, keydir = env
    key, _ = keygen(capsys, keydir / "a.key")
    anchor = make_anchor(capsys, db, key, tmp_path / "a.json")
    svc = CoreService.open(db)
    cmd = svc.store.find_actor("test:commander")
    svc.request_action(INC_C, "notify_stakeholders", None, cmd.id, source="test")
    svc.open_incident("INC-B-2026-0041", primary_asset_id="srv-web-01")
    svc.conn.close()
    code, out, _ = run(capsys, "--db", str(db), "verify", "--anchor", str(anchor),
                       "--key-file", str(key))
    assert code == 0 and "): OK" in out
    assert f"{INC_C}: grown" in out and "INC-B-2026-0041: unanchored" in out
    code, out, _ = run(capsys, "--db", str(db), "verify", "--incident", "INC-C", "--anchor",
                       str(anchor), "--key-file", str(key))
    assert code == 0 and f"{INC_C}: grown" in out and INC_A not in out.split("anchor ")[-1]
    code, _, err = run(capsys, "--db", str(db), "verify", "--incident", "INC-B", "--anchor",
                       str(anchor), "--key-file", str(key))
    assert code == 2 and "does not cover" in err


def test_verify_anchor_detects_a_rehashed_rewrite(env, capsys, tmp_path):
    db, keydir = env
    key, _ = keygen(capsys, keydir / "a.key")
    anchor = make_anchor(capsys, db, key, tmp_path / "a.json")
    rewrite_and_rehash(db, INC_C, 2, {"forged": True})
    assert run(capsys, "--db", str(db), "verify")[0] == 0      # the plain check is fooled
    code, out, _ = run(capsys, "--db", str(db), "verify", "--anchor", str(anchor),
                       "--key-file", str(key))
    assert code == 1 and "MISMATCH" in out and f"{INC_C}: rewritten" in out


def test_verify_anchor_detects_truncation(env, capsys, tmp_path):
    db, keydir = env
    key, _ = keygen(capsys, keydir / "a.key")
    anchor = make_anchor(capsys, db, key, tmp_path / "a.json")
    raw(db, ("DELETE FROM audit_events WHERE chain = ? AND seq = (SELECT MAX(seq) FROM "
             "audit_events WHERE chain = ?)", (INC_A, INC_A)),
        drop=("audit_events_no_delete",))
    code, out, _ = run(capsys, "--db", str(db), "verify", "--anchor", str(anchor),
                       "--key-file", str(key))
    assert code == 1 and f"{INC_A}: truncated" in out


def test_verify_anchor_errors_exit_2_before_any_report(env, capsys, tmp_path):
    db, keydir = env
    key, _ = keygen(capsys, keydir / "a.key")
    other, _ = keygen(capsys, keydir / "b.key")
    anchor = make_anchor(capsys, db, key, tmp_path / "a.json")
    doc = json.loads(anchor.read_text())
    doc["checkpoint"]["chains"][INC_C]["seq"] = 1
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(doc), encoding="ascii")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="ascii")
    binary = tmp_path / "bin.json"
    binary.write_bytes(b"\xff\xfe")
    for anchor_file, keyfile, why in ((anchor, other, "HMAC"), (edited, key, "HMAC"),
                                      (bad, key, "not valid JSON"), (binary, key, "not ASCII"),
                                      (tmp_path / "none.json", key, "cannot be read")):
        code, out, err = run(capsys, "--db", str(db), "verify", "--anchor", str(anchor_file),
                             "--key-file", str(keyfile))
        assert code == 2 and why in err and out == "", (anchor_file, err)


def test_verify_reports_existing_tampering_with_an_anchor_too(env, capsys, tmp_path):
    db, keydir = env
    key, _ = keygen(capsys, keydir / "a.key")
    anchor = make_anchor(capsys, db, key, tmp_path / "a.json")
    raw(db, ("UPDATE audit_events SET payload = '{}' WHERE chain = ? AND seq = 2", (INC_C,)),
        drop=("audit_events_no_update",))
    code, out, _ = run(capsys, "--db", str(db), "verify", "--anchor", str(anchor),
                       "--key-file", str(key))
    assert code == 1 and "TAMPERED" in out and "MISMATCH" in out


# --- the key never leaks ----------------------------------------------------------------------

def test_the_key_never_appears_in_any_output_or_the_database(env, capsys, tmp_path):
    db, keydir = env
    out_all = []
    code, out, err = run(capsys, "anchor-keygen", "--out", str(keydir / "a.key"))
    out_all += [out, err]
    secret = (keydir / "a.key").read_text().splitlines()[1]
    for argv in (("--db", str(db), "anchor", "--out", str(tmp_path / "a.json"), "--key-file",
                  str(keydir / "a.key")),
                 ("--db", str(db), "verify", "--anchor", str(tmp_path / "a.json"),
                  "--key-file", str(keydir / "a.key")),
                 ("--db", str(db), "verify", "--anchor", str(tmp_path / "missing.json"),
                  "--key-file", str(keydir / "a.key"))):
        code, out, err = run(capsys, *argv)
        out_all += [out, err]
    text = "".join(out_all) + (tmp_path / "a.json").read_text()
    assert secret not in text and secret[:16] not in text
    conn = sqlite3.connect(db)
    try:
        assert secret not in "\n".join(conn.iterdump())
    finally:
        conn.close()

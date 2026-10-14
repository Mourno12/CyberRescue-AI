"""CyberRescue Phase 7 (7-3) — verifying signed anchors against the database."""

import json
import sqlite3
from datetime import datetime, timezone

import pytest

from cyberrescue.core import db as coredb
from cyberrescue.core.anchor import (
    AnchorError,
    AnchorFormatError,
    AnchorSignatureError,
    ChainHead,
    build_checkpoint,
    load_key,
    sign_checkpoint,
    verify_checkpoint,
    write_new_key,
)
from cyberrescue.core.audit import AuditLog, _body, compute_hash
from cyberrescue.core.models import EventType
from cyberrescue.core.service import CoreService
from tests.test_investigation_security import db_state

T0 = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
INC_C, INC_A = "INC-C-2026-0042", "INC-A-2026-0039"


def make_core(path, incidents=(INC_C, INC_A)):
    svc = CoreService.open(path)
    svc.seed_assets_from_mock()
    for iid, asset in ((INC_C, "srv-db-01"), (INC_A, "ws-eng-014"), ("INC-B-2026-0041",
                                                                     "srv-web-01")):
        if iid in incidents:
            svc.open_incident(iid, primary_asset_id=asset)
    cmd = svc.register_actor("agent", "commander", "c", "test:commander")
    for iid in incidents:
        svc.request_action(iid, "notify_stakeholders", None, cmd.id, source="test")
    svc.conn.close()
    return path


@pytest.fixture
def db(tmp_path):
    return make_core(tmp_path / "core.db")


@pytest.fixture
def key(tmp_path):
    return load_key(write_new_key(tmp_path / "keys" / "anchor.key"))


def anchor(path, key):
    conn = coredb.connect(path)
    try:
        return sign_checkpoint(build_checkpoint(conn, lambda: T0), key)
    finally:
        conn.close()


def verify(path, signed, key, incident=None):
    conn = coredb.connect(path)
    try:
        return verify_checkpoint(conn, signed, key, incident)
    finally:
        conn.close()


def status(result):
    return {c.chain: c.status for c in result.chains}


def raw(path, *sql, drop=()):
    conn = sqlite3.connect(path)
    try:
        for t in drop:
            conn.execute(f"DROP TRIGGER IF EXISTS {t}")
        for s, *args in sql:
            conn.execute(s, *args)
        conn.commit()
    finally:
        conn.close()


def rewrite_and_rehash(path, chain, seq, payload):
    """The database-only attacker: edit an event, drop the triggers, and recompute
    every hash of the chain from that event on, so AuditLog.verify passes."""
    conn = coredb.connect(path)
    try:
        conn.execute("DROP TRIGGER audit_events_no_update")
        conn.execute("UPDATE audit_events SET payload = ? WHERE chain = ? AND seq = ?",
                     (json.dumps(payload), chain, seq))
        log = AuditLog(conn)
        prev = conn.execute("SELECT hash FROM audit_events WHERE chain = ? AND seq = ?",
                            (chain, seq - 1)).fetchone()
        prev_hash = prev["hash"] if prev else "0" * 64
        for row in conn.execute("SELECT * FROM audit_events WHERE chain = ? AND seq >= ? "
                                "ORDER BY seq", (chain, seq)).fetchall():
            ev = dict(row)
            ev["payload"] = json.loads(row["payload"])
            ev["protocol_valid"] = None if row["protocol_valid"] is None \
                else bool(row["protocol_valid"])
            ev["prev_hash"] = prev_hash
            new = compute_hash(prev_hash, _body(ev, log._links_of(row["uid"])))
            conn.execute("UPDATE audit_events SET prev_hash = ?, hash = ? WHERE uid = ?",
                         (prev_hash, new, row["uid"]))
            prev_hash = new
        conn.commit()
        assert log.verify(chain).ok                   # the plain chain check is fooled
    finally:
        conn.close()


# --- matching state ---------------------------------------------------------------------------

def test_exact_database_state_verifies(db, key):
    res = verify(db, anchor(db, key), key)
    assert res.ok and res.schema_ok and res.errors == []
    assert set(status(res).values()) == {"ok"}
    assert {INC_C, INC_A, "__system__"} <= set(status(res))


def test_growth_after_the_anchor_is_valid(db, key):
    signed = anchor(db, key)
    svc = CoreService.open(db)
    cmd = svc.store.find_actor("test:commander")
    svc.request_action(INC_C, "notify_stakeholders", None, cmd.id, source="test")
    svc.open_incident("INC-B-2026-0041", primary_asset_id="srv-web-01")    # a new chain
    svc.conn.close()
    res = verify(db, signed, key)
    assert res.ok
    st = status(res)
    assert st[INC_C] == "grown" and st[INC_A] == "ok" and st["INC-B-2026-0041"] == "unanchored"
    [c] = [c for c in res.chains if c.chain == INC_C]
    assert c.current_seq > c.anchored_seq


# --- database state differs from a valid anchor ------------------------------------------------

def test_a_changed_chain_head_is_detected(db, key):
    signed = anchor(db, key)
    raw(db, ("UPDATE audit_events SET hash = ? WHERE chain = ? AND seq = "
             "(SELECT MAX(seq) FROM audit_events WHERE chain = ?)", ("f" * 64, INC_C, INC_C)),
        drop=("audit_events_no_update",))
    res = verify(db, signed, key)
    assert not res.ok and status(res)[INC_C] == "rewritten"


def test_a_rewritten_and_rehashed_prefix_is_detected(db, key):
    signed = anchor(db, key)
    rewrite_and_rehash(db, INC_C, 2, {"forged": True})
    res = verify(db, signed, key)
    assert not res.ok and status(res)[INC_C] == "rewritten"
    assert status(res)[INC_A] == "ok"


def test_a_changed_sequence_is_detected_as_truncation(db, key):
    signed = anchor(db, key)
    raw(db, ("DELETE FROM event_links WHERE from_uid IN (SELECT uid FROM audit_events WHERE "
             "chain = ? AND seq = (SELECT MAX(seq) FROM audit_events WHERE chain = ?))",
             (INC_C, INC_C)),
        ("DELETE FROM audit_events WHERE chain = ? AND seq = "
         "(SELECT MAX(seq) FROM audit_events WHERE chain = ?)", (INC_C, INC_C)),
        drop=("audit_events_no_delete", "event_links_no_delete"))
    res = verify(db, signed, key)
    assert not res.ok and status(res)[INC_C] == "truncated"
    conn = coredb.connect(db)
    try:
        assert AuditLog(conn).verify(INC_C).ok                    # invisible without the anchor
    finally:
        conn.close()


def test_truncating_accountability_events_before_the_anchor_is_detected(db, key):
    svc = CoreService.open(db)
    svc.store.audit.append(EventType.ACTION_EXECUTED, incident_id=INC_C, source="test",
                           payload={"mode": "simulated"})
    svc.store.audit.append(EventType.ACTION_VERIFIED, incident_id=INC_C, source="test",
                           payload={"mode": "simulated"})
    svc.conn.close()
    signed = anchor(db, key)
    raw(db, ("DELETE FROM audit_events WHERE chain = ? AND event_type IN "
             "('ACTION_EXECUTED', 'ACTION_VERIFIED')", (INC_C,)),
        drop=("audit_events_no_delete",))
    res = verify(db, signed, key)
    assert not res.ok and status(res)[INC_C] == "truncated"


def test_a_missing_chain_is_detected(db, key):
    signed = anchor(db, key)
    raw(db, ("DELETE FROM event_links WHERE from_uid IN (SELECT uid FROM audit_events "
             "WHERE chain = ?)", (INC_A,)),
        ("DELETE FROM audit_events WHERE chain = ?", (INC_A,)),
        drop=("audit_events_no_delete", "event_links_no_delete"))
    res = verify(db, signed, key)
    assert not res.ok and status(res)[INC_A] == "missing"


def test_an_extra_chain_in_the_anchor_is_detected(db, key):
    conn = coredb.connect(db)
    try:
        cp = build_checkpoint(conn, lambda: T0)
    finally:
        conn.close()
    extra = cp.__class__(created_at=cp.created_at, schema_version=cp.schema_version,
                         chains={**cp.chains, "INC-Z-2026-0001": ChainHead(1, "1" * 64)})
    res = verify(db, sign_checkpoint(extra, key), key)
    assert not res.ok and status(res)["INC-Z-2026-0001"] == "missing"


def test_a_broken_chain_after_the_anchor_is_detected(db, key):
    signed = anchor(db, key)
    svc = CoreService.open(db)
    cmd = svc.store.find_actor("test:commander")
    svc.request_action(INC_C, "notify_stakeholders", None, cmd.id, source="test")
    svc.conn.close()
    raw(db, ("UPDATE audit_events SET payload = '{}' WHERE chain = ? AND seq = "
             "(SELECT MAX(seq) FROM audit_events WHERE chain = ?)", (INC_C, INC_C)),
        drop=("audit_events_no_update",))
    res = verify(db, signed, key)
    assert not res.ok and status(res)[INC_C] == "broken"


def test_a_schema_version_mismatch_is_detected(db, key):
    signed = anchor(db, key)
    raw(db, ("UPDATE schema_meta SET value = '2' WHERE key = 'schema_version'",))
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        res = verify_checkpoint(conn, signed, key)
    finally:
        conn.close()
    assert not res.ok and not res.schema_ok
    assert (res.anchored_schema_version, res.current_schema_version) == (3, 2)
    assert any("schema version" in e for e in res.errors)


def test_a_valid_anchor_of_another_database_does_not_match(db, key, tmp_path):
    other = make_core(tmp_path / "other.db", incidents=(INC_C,))
    res = verify(db, anchor(other, key), key)
    assert not res.ok
    assert status(res)[INC_C] in ("rewritten", "truncated")


# --- invalid anchors -------------------------------------------------------------------------

@pytest.mark.parametrize("text", ["", "{}", "not json", '{"checkpoint": 1, "hmac_sha256": 2}'])
def test_malformed_anchors_raise_format_errors(db, key, text):
    with pytest.raises(AnchorFormatError):
        verify(db, text, key)


def test_a_wrong_key_raises_a_signature_error(db, key, tmp_path):
    other = load_key(write_new_key(tmp_path / "keys" / "other.key"))
    with pytest.raises(AnchorSignatureError):
        verify(db, anchor(db, key), other)


def test_an_edited_anchor_raises_a_signature_error(db, key):
    doc = json.loads(anchor(db, key))
    doc["checkpoint"]["chains"][INC_C]["seq"] = 1
    with pytest.raises(AnchorSignatureError):
        verify(db, json.dumps(doc), key)


# --- scope, read-only, connection --------------------------------------------------------------

def test_one_incident_can_be_verified(db, key):
    signed = anchor(db, key)
    rewrite_and_rehash(db, INC_A, 2, {"forged": True})
    res = verify(db, signed, key, incident=INC_C)
    assert res.ok and [c.chain for c in res.chains] == [INC_C]
    assert not verify(db, signed, key, incident=INC_A).ok
    with pytest.raises(AnchorError, match="does not cover"):
        verify(db, signed, key, incident="INC-Z-2026-0001")


def test_verification_works_read_only_and_writes_nothing(db, key):
    signed = anchor(db, key)
    before = db_state(db)
    conn = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        assert verify_checkpoint(conn, signed, key).ok
    finally:
        conn.close()
    assert db_state(db) == before


def test_a_non_core_connection_is_refused(db, key):
    signed = anchor(db, key)
    conn = sqlite3.connect(db)
    try:
        with pytest.raises(AnchorError, match="Core connection"):
            verify_checkpoint(conn, signed, key)
    finally:
        conn.close()

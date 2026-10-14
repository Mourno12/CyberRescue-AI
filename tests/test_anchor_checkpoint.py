"""CyberRescue Phase 7 (7-2) — signed audit checkpoints."""

import json
import sqlite3
from datetime import datetime, timezone

import pytest

from cyberrescue.core.anchor import (
    CHECKPOINT_SCHEMA,
    AnchorFormatError,
    AnchorSignatureError,
    ChainHead,
    Checkpoint,
    anchor_json,
    build_checkpoint,
    load_key,
    open_signed,
    parse_signed,
    sign_checkpoint,
    write_new_key,
)
from cyberrescue.core.service import CoreService
from tests.test_investigation_security import db_state

T0 = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 10, 4, 13, 0, tzinfo=timezone.utc)
HOSTILE_CHAIN = 'INC-"evil"\n</code><script>‮\x1b[31m\U0001f600\\'


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "core.db"
    svc = CoreService.open(path)
    svc.seed_assets_from_mock()
    svc.open_incident("INC-C-2026-0042", primary_asset_id="srv-db-01")
    svc.open_incident("INC-A-2026-0039", primary_asset_id="ws-eng-014")
    svc.conn.close()
    return path


@pytest.fixture
def key(tmp_path):
    return load_key(write_new_key(tmp_path / "keys" / "anchor.key"))


@pytest.fixture
def other_key(tmp_path):
    return load_key(write_new_key(tmp_path / "keys" / "other.key"))


def checkpoint(path, clock=lambda: T0):
    conn = sqlite3.connect(path)
    try:
        return build_checkpoint(conn, clock)
    finally:
        conn.close()


def heads(path):
    conn = sqlite3.connect(path)
    try:
        return {c: (s, h) for c, s, h in conn.execute(
            "SELECT chain, seq, hash FROM audit_events a WHERE seq = "
            "(SELECT MAX(seq) FROM audit_events b WHERE b.chain = a.chain)")}
    finally:
        conn.close()


def edit(signed, fn):
    doc = json.loads(signed)
    fn(doc)
    return json.dumps(doc)


# --- building -------------------------------------------------------------------------------

def test_checkpoint_holds_every_chain_head(db):
    cp = checkpoint(db)
    assert cp.schema == CHECKPOINT_SCHEMA and cp.schema_version == 3
    assert cp.created_at == T0.isoformat()
    assert {c: (h.seq, h.hash) for c, h in cp.chains.items()} == heads(db)
    assert {"__system__", "INC-C-2026-0042", "INC-A-2026-0039"} <= set(cp.chains)


def test_checkpoint_is_deterministic_except_created_at(db):
    a, b, c = checkpoint(db), checkpoint(db), checkpoint(db, clock=lambda: T1)
    assert anchor_json(a.body()) == anchor_json(b.body())
    assert a.chains == c.chains and a.created_at != c.created_at


def test_building_a_checkpoint_writes_nothing(db):
    before = db_state(db)
    checkpoint(db)
    assert db_state(db) == before


def test_checkpoint_works_on_a_read_only_connection(db):
    conn = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        assert build_checkpoint(conn, lambda: T0).chains == checkpoint(db).chains
    finally:
        conn.close()


# --- signing and verification ----------------------------------------------------------------

def test_sign_and_open_round_trip(db, key):
    cp = checkpoint(db)
    signed = sign_checkpoint(cp, key)
    assert signed.endswith("\n") and signed.count("\n") == 1 and signed.isascii()
    doc = json.loads(signed)
    assert set(doc) == {"checkpoint", "hmac_sha256"} and len(doc["hmac_sha256"]) == 64
    assert open_signed(signed, key) == cp


def test_signing_is_deterministic(db, key):
    cp = checkpoint(db)
    assert sign_checkpoint(cp, key) == sign_checkpoint(cp, key)


def test_a_wrong_key_fails(db, key, other_key):
    with pytest.raises(AnchorSignatureError, match="altered or a different key"):
        open_signed(sign_checkpoint(checkpoint(db), key), other_key)


@pytest.mark.parametrize("change", [
    lambda d: d["checkpoint"]["chains"]["INC-C-2026-0042"].update(seq=d["checkpoint"]["chains"][
        "INC-C-2026-0042"]["seq"] + 1),
    lambda d: d["checkpoint"]["chains"]["INC-C-2026-0042"].update(seq=1),
    lambda d: d["checkpoint"]["chains"]["INC-C-2026-0042"].update(hash="0" * 64),
    lambda d: d["checkpoint"]["chains"].pop("INC-A-2026-0039"),
    lambda d: d["checkpoint"]["chains"].update({"INC-Z-2026-0001": {"seq": 1, "hash": "1" * 64}}),
    lambda d: d["checkpoint"]["chains"].update(
        {"INC-C-2026-0099": d["checkpoint"]["chains"].pop("INC-C-2026-0042")}),
    lambda d: d["checkpoint"].update(created_at=T1.isoformat()),
    lambda d: d["checkpoint"].update(schema_version=2),
    lambda d: d.update(hmac_sha256="a" * 64),
], ids=["seq_up", "seq_down", "hash", "chain_removed", "chain_added", "chain_renamed",
        "created_at", "schema_version", "tag"])
def test_any_modification_fails_the_hmac(db, key, change):
    signed = sign_checkpoint(checkpoint(db), key)
    with pytest.raises(AnchorSignatureError):
        open_signed(edit(signed, change), key)


def test_formatting_is_not_part_of_the_signature(db, key):
    cp = checkpoint(db)
    doc = json.loads(sign_checkpoint(cp, key))
    pretty = json.dumps(doc, indent=4, sort_keys=False)       # same content, other layout
    assert open_signed(pretty, key) == cp


# --- strict parsing ----------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "", "not json", "[]", "{}", '{"checkpoint": {}}', "NaN",
    '{"checkpoint": {}, "hmac_sha256": "x"}',
])
def test_malformed_documents_are_rejected(text):
    with pytest.raises(AnchorFormatError):
        parse_signed(text)


@pytest.mark.parametrize("change", [
    lambda d: d.update(extra=1),
    lambda d: d.update(hmac_sha256=d["hmac_sha256"].upper()),
    lambda d: d["checkpoint"].update(extra=1),
    lambda d: d["checkpoint"].update(schema="cyberrescue.audit-anchor/2"),
    lambda d: d["checkpoint"].update(created_at="yesterday"),
    lambda d: d["checkpoint"].update(created_at=12),
    lambda d: d["checkpoint"].update(schema_version=True),
    lambda d: d["checkpoint"].update(schema_version="3"),
    lambda d: d["checkpoint"].update(chains=[]),
    lambda d: d["checkpoint"]["chains"].update({"": {"seq": 1, "hash": "0" * 64}}),
    lambda d: d["checkpoint"]["chains"]["__system__"].update(seq=0),
    lambda d: d["checkpoint"]["chains"]["__system__"].update(seq=1.0),
    lambda d: d["checkpoint"]["chains"]["__system__"].update(seq=True),
    lambda d: d["checkpoint"]["chains"]["__system__"].update(hash="Z" * 64),
    lambda d: d["checkpoint"]["chains"]["__system__"].update(extra=1),
])
def test_structurally_invalid_anchors_are_rejected(db, key, change):
    with pytest.raises(AnchorFormatError):
        open_signed(edit(sign_checkpoint(checkpoint(db), key), change), key)


def test_duplicate_keys_are_rejected(db, key):
    signed = sign_checkpoint(checkpoint(db), key)
    dup = signed.replace('{"checkpoint":', '{"hmac_sha256":"' + "0" * 64 + '","checkpoint":', 1)
    with pytest.raises(AnchorFormatError, match="duplicate"):
        parse_signed(dup)


def test_infinity_is_rejected(db, key):
    signed = sign_checkpoint(checkpoint(db), key).replace('"seq":', '"seq":Infinity,"x":', 1)
    with pytest.raises(AnchorFormatError):
        parse_signed(signed)


# --- hostile chain identifiers -------------------------------------------------------------------

def test_hostile_chain_ids_round_trip_canonically(tmp_path, key):
    path = tmp_path / "core.db"
    CoreService.open(path).conn.close()
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO audit_events(uid, chain, incident_id, seq, ts, event_type, "
                 "source, payload, prev_hash, hash) VALUES ('h1', ?, NULL, 1, ?, 'TEST', "
                 "'test', '{}', ?, ?)", (HOSTILE_CHAIN, T0.isoformat(), "0" * 64, "e" * 64))
    conn.commit()
    conn.close()
    cp = checkpoint(path)
    assert cp.chains[HOSTILE_CHAIN] == ChainHead(seq=1, hash="e" * 64)
    signed = sign_checkpoint(cp, key)
    assert signed.isascii() and "\n" not in signed[:-1] and "<script>" in signed
    assert "\x1b" not in signed and "‮" not in signed
    assert open_signed(signed, key).chains == cp.chains
    # Re-encoding the same characters differently cannot smuggle a different id past the HMAC.
    other = signed.replace("evil", "evi1")
    with pytest.raises(AnchorSignatureError):
        open_signed(other, key)


def test_sign_refuses_an_invalid_checkpoint(key):
    with pytest.raises(AnchorFormatError):
        sign_checkpoint(Checkpoint(created_at=T0.isoformat(), schema_version=3,
                                   chains={"x": ChainHead(seq=0, hash="0" * 64)}), key)


# --- key non-disclosure ------------------------------------------------------------------------

def test_the_key_never_appears_in_checkpoints_or_signatures(db, tmp_path):
    path = write_new_key(tmp_path / "k" / "anchor.key")
    secret = path.read_text().splitlines()[1]
    key = load_key(path)
    cp = checkpoint(db)
    signed = sign_checkpoint(cp, key)
    for text in (signed, repr(cp), anchor_json(cp.body())):
        assert secret not in text and secret[:16] not in text
        assert bytes.fromhex(secret).hex() not in text
    for i in range(0, len(secret) - 16, 8):                     # no 8-byte window either
        assert secret[i:i + 16] not in signed
    conn = sqlite3.connect(db)
    try:
        dump = "\n".join(conn.iterdump())
    finally:
        conn.close()
    assert secret not in dump

"""CyberRescue Core — SQLite schema (cyberrescue/core/db.py)."""

import sqlite3

import pytest

from cyberrescue.core import db


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "core.db")
    yield c
    c.close()


def _insert_event(conn, uid="e1", seq=1):
    conn.execute(
        "INSERT INTO audit_events(uid, chain, incident_id, seq, ts, event_type, "
        "source, payload, prev_hash, hash) VALUES (?, '__system__', NULL, ?, "
        "'2026-01-01T00:00:00+00:00', 'TEST', 'test', '{}', 'p', 'h')",
        (uid, seq),
    )


def test_schema_creates_every_table_and_is_idempotent(conn):
    names = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert set(db.TABLES) <= names
    db.init_schema(conn)  # second run must not fail or duplicate
    assert conn.execute("SELECT COUNT(*) FROM schema_meta").fetchone()[0] == 1


def test_schema_version_recorded(conn):
    assert db.schema_version(conn) == db.SCHEMA_VERSION


def test_foreign_keys_enforced(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO incident_aliases(alias, incident_id, created_at) "
            "VALUES ('INC-X', 'INC-DOES-NOT-EXIST', 'now')")


def test_audit_events_cannot_be_updated_or_deleted(conn):
    _insert_event(conn)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE audit_events SET payload = '{\"x\":1}' WHERE uid = 'e1'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM audit_events WHERE uid = 'e1'")


# --- schema v1 -> v2 migration (Phase 2A) ---------------------------------------

V2_ONLY_TRIGGERS = ("evidence_no_update", "evidence_no_delete", "finding_evidence_same_incident",
                    "finding_evidence_no_update", "finding_evidence_no_delete")


def _make_v1_db(path):
    """A v2 DB with real claim data, reverted to the exact v1 layout: the v2
    evidence/finding_evidence tables removed and finding_claims renamed back to
    'evidence' (the v1 name for claims), version set to 1."""
    from cyberrescue.core.service import CoreService
    svc = CoreService.open(path)
    svc.seed_assets_from_mock()
    inc = svc.open_incident("INC-C-2026-0042", primary_asset_id="srv-db-01",
                            recruited_roles=["threat_intel", "commander"])
    agent = svc.register_actor("agent", "threat_intel", "ti", "band:ti")
    svc.record_finding(inc.id, agent, "BlackHaze", claims=["185.220.101.47 = C2", "spread"])
    c = svc.conn
    for t in V2_ONLY_TRIGGERS:
        c.execute(f"DROP TRIGGER {t}")
    c.execute("DROP TABLE finding_evidence")
    c.execute("DROP TABLE evidence")
    c.execute("ALTER TABLE finding_claims RENAME TO evidence")
    c.execute("UPDATE schema_meta SET value = '1' WHERE key = 'schema_version'")
    c.close()
    return inc.id


def test_v1_database_is_migrated_in_place_preserving_data_and_audit(tmp_path):
    path = tmp_path / "v1.db"
    iid = _make_v1_db(path)
    raw = sqlite3.connect(path)
    before = raw.execute("SELECT * FROM evidence ORDER BY content").fetchall()  # v1 claims
    raw.close()
    assert len(before) == 2

    conn = db.connect(path)                                   # migrates
    assert db.schema_version(conn) == db.SCHEMA_VERSION
    after = conn.execute("SELECT * FROM finding_claims ORDER BY content").fetchall()
    assert [tuple(r) for r in after] == [tuple(r) for r in before]   # verbatim
    assert "content_sha256" in {r[1] for r in conn.execute("PRAGMA table_info(evidence)")}
    assert conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 0
    assert conn.execute("SELECT value FROM schema_meta WHERE key = 'migration.v1_to_v2'"
                        ).fetchone() is not None
    from cyberrescue.core.audit import AuditLog
    assert AuditLog(conn).verify(iid).ok and AuditLog(conn).verify().ok
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    assert set(V2_ONLY_TRIGGERS) <= names
    conn.close()


def test_migration_is_idempotent_and_refuses_ambiguous_state(tmp_path):
    path = tmp_path / "v1.db"
    _make_v1_db(path)
    db.connect(path).close()
    conn = db.connect(path)                                   # second open: no-op
    assert db.schema_version(conn) == db.SCHEMA_VERSION
    assert conn.execute("SELECT COUNT(*) FROM finding_claims").fetchone()[0] == 2
    conn.close()

    bad = tmp_path / "ambiguous.db"
    _make_v1_db(bad)
    raw = sqlite3.connect(bad)
    raw.execute("CREATE TABLE finding_claims (id TEXT)")      # both v1 and v2 names
    raw.commit()
    raw.close()
    with pytest.raises(RuntimeError, match="refusing to migrate"):
        db.connect(bad)


def test_newer_schema_version_is_rejected(tmp_path):
    path = tmp_path / "future.db"
    db.connect(path).close()
    raw = sqlite3.connect(path)
    raw.execute("UPDATE schema_meta SET value = '99' WHERE key = 'schema_version'")
    raw.commit()
    raw.close()
    with pytest.raises(RuntimeError, match="newer than this code"):
        db.connect(path)


def test_transaction_rolls_back_as_a_unit_and_nests(conn):
    with pytest.raises(RuntimeError):
        with db.transaction(conn):
            _insert_event(conn, "e1", 1)
            with db.transaction(conn):  # nested -> savepoint
                _insert_event(conn, "e2", 2)
            raise RuntimeError("boom")
    assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0

    with db.transaction(conn):
        _insert_event(conn, "e1", 1)
        with pytest.raises(RuntimeError):
            with db.transaction(conn):
                _insert_event(conn, "e2", 2)
                raise RuntimeError("inner only")
    uids = [r["uid"] for r in conn.execute("SELECT uid FROM audit_events")]
    assert uids == ["e1"]

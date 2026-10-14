"""CyberRescue Phase 6 — schema v3: execution_records and the v1/v2 -> v3 migration."""

import hashlib
import sqlite3

import pytest

from cyberrescue.core import db
from cyberrescue.core.audit import AuditLog
from cyberrescue.core.service import CoreService
from tests.test_core_db import _make_v1_db

INC = "INC-C-2026-0042"
V3_OBJECTS = ("execution_records", "execution_records_no_update", "execution_records_no_delete",
              "execution_records_bound_to_request", "ix_execution_records_incident")


def _core(path):
    svc = CoreService.open(path)
    svc.seed_assets_from_mock()
    svc.open_incident(INC, primary_asset_id="srv-db-01")
    cmd = svc.register_actor("agent", "commander", "c", "test:commander")
    return svc, cmd


def _authorized(svc, cmd, action="preserve_disk_image", asset="srv-db-01"):
    out = svc.request_action(INC, action, asset, cmd.id, source="test")
    assert out.authorized
    return out


def _insert(conn, out, *, rid="X1", mode="simulated", incident=INC, action=None, asset="=",
            request_id=None):
    req = out.request
    ev = out.authorization_event_uid
    conn.execute(
        "INSERT INTO execution_records(id, incident_id, action_request_id, mode, action, "
        "asset_id, plan_id, plan_sha256, step_id, step_sha256, report_sha256, "
        "evidence_fingerprint, environment_sha256, outcome, criteria, audit_head_hash, "
        "recorded_by, authorized_event_uid, executed_event_uid, verified_event_uid, "
        "created_at) VALUES (?,?,?,?,?,?,'P','p','S','s','r','e','v','succeeded','[]','h',"
        "?,?,?,?,'t')",
        (rid, incident, request_id or req.id, mode, action or req.action,
         req.asset_id if asset == "=" else asset, req.requested_by, ev, ev, ev))


def _hashes(path, skip=("schema_meta",)):
    conn = sqlite3.connect(path)
    try:
        names = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        return {n: hashlib.sha256(repr(conn.execute(
            f"SELECT * FROM {n} ORDER BY rowid").fetchall()).encode()).hexdigest()
            for n in names if n not in skip}
    finally:
        conn.close()


def _downgrade_to_v2(path):
    conn = sqlite3.connect(path)
    for name in ("execution_records_no_update", "execution_records_no_delete",
                 "execution_records_bound_to_request"):
        conn.execute(f"DROP TRIGGER {name}")
    conn.execute("DROP TABLE execution_records")
    conn.execute("UPDATE schema_meta SET value = '2' WHERE key = 'schema_version'")
    conn.commit()
    conn.close()


# --- schema ------------------------------------------------------------------------------

def test_fresh_database_is_v3_with_execution_records(tmp_path):
    conn = db.connect(tmp_path / "core.db")
    try:
        assert db.SCHEMA_VERSION == 3 and db.schema_version(conn) == 3
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        assert set(V3_OBJECTS) <= names
        assert conn.execute("SELECT value FROM schema_meta WHERE key = 'migration.v2_to_v3'"
                            ).fetchone() is None          # fresh, not migrated
    finally:
        conn.close()


# --- migration -------------------------------------------------------------------------------

def test_v2_database_migrates_to_v3_preserving_everything(tmp_path):
    path = tmp_path / "v2.db"
    svc, cmd = _core(path)
    _authorized(svc, cmd)
    svc.conn.close()
    _downgrade_to_v2(path)
    before = _hashes(path)

    conn = db.connect(path)                                   # migrates
    try:
        assert db.schema_version(conn) == 3
        assert conn.execute("SELECT value FROM schema_meta WHERE key = 'migration.v2_to_v3'"
                            ).fetchone() is not None
        assert {r[0] for r in conn.execute("SELECT name FROM sqlite_master")} >= set(V3_OBJECTS)
        assert AuditLog(conn).verify(INC).ok and AuditLog(conn).verify().ok
    finally:
        conn.close()
    after = _hashes(path)
    assert {k: v for k, v in after.items() if k != "execution_records"} == before
    conn = db.connect(path)                                   # idempotent re-open
    try:
        assert db.schema_version(conn) == 3
        assert conn.execute("SELECT COUNT(*) FROM schema_meta WHERE key LIKE 'migration.%'"
                            ).fetchone()[0] == 1
    finally:
        conn.close()
    assert _hashes(path) == after


def test_v1_database_migrates_through_v2_to_v3(tmp_path):
    path = tmp_path / "v1.db"
    iid = _make_v1_db(path)
    conn = db.connect(path)
    try:
        assert db.schema_version(conn) == 3
        keys = {r[0] for r in conn.execute("SELECT key FROM schema_meta")}
        assert {"migration.v1_to_v2", "migration.v2_to_v3"} <= keys
        assert conn.execute("SELECT COUNT(*) FROM finding_claims").fetchone()[0] == 2
        assert AuditLog(conn).verify(iid).ok and AuditLog(conn).verify().ok
    finally:
        conn.close()


@pytest.mark.parametrize("version", ["4", "99"])
def test_future_versions_are_rejected(tmp_path, version):
    path = tmp_path / "future.db"
    db.connect(path).close()
    raw = sqlite3.connect(path)
    raw.execute("UPDATE schema_meta SET value = ? WHERE key = 'schema_version'", (version,))
    raw.commit()
    raw.close()
    with pytest.raises(RuntimeError, match="newer than this code"):
        db.connect(path)


# --- database-level constraints (no application code involved) ------------------------------

@pytest.fixture
def authorized(tmp_path):
    svc, cmd = _core(tmp_path / "core.db")
    out = _authorized(svc, cmd)
    yield svc, cmd, out
    svc.conn.close()


def test_a_matching_record_can_be_inserted(authorized):
    svc, _, out = authorized
    _insert(svc.conn, out)
    assert svc.conn.execute("SELECT mode FROM execution_records").fetchone()[0] == "simulated"


def test_replay_is_impossible_in_the_database(authorized):
    svc, _, out = authorized
    _insert(svc.conn, out)
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        _insert(svc.conn, out, rid="X2")


@pytest.mark.parametrize("mode", ["real", "live", "SIMULATED", ""])
def test_mode_can_only_be_simulated(authorized, mode):
    svc, _, out = authorized
    with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
        _insert(svc.conn, out, mode=mode)


def test_records_cannot_be_updated_or_deleted(authorized):
    svc, _, out = authorized
    _insert(svc.conn, out)
    for sql in ("UPDATE execution_records SET mode = 'real'",
                "UPDATE execution_records SET outcome = 'succeeded'",
                "DELETE FROM execution_records"):
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            svc.conn.execute(sql)


def test_records_must_match_their_request(authorized):
    svc, cmd, out = authorized
    svc.open_incident("INC-B-2026-0041", primary_asset_id="srv-web-01")
    for kw in ({"incident": "INC-B-2026-0041"}, {"action": "isolate_host"},
               {"asset": "srv-app-01"}, {"asset": None}):
        with pytest.raises(sqlite3.IntegrityError, match="does not match"):
            _insert(svc.conn, out, **kw)


def test_only_authorized_tier_1_2_requests_can_be_recorded(authorized):
    svc, cmd, out = authorized
    pending = svc.request_action(INC, "isolate_host", "srv-db-01", cmd.id, source="test")
    assert not pending.authorized                               # P5: needs approval
    pending = pending.__class__(request=pending.request, decision=pending.decision,
                                authorization_event_uid=out.authorization_event_uid)
    with pytest.raises(sqlite3.IntegrityError, match="does not match"):
        _insert(svc.conn, pending, rid="X3")
    ciso = svc.register_actor("human", "ciso", "ciso", "test:ciso")
    svc.grant_approval(INC, action="wipe_host", asset_id="srv-db-01", approver_actor_id=ciso.id,
                       reason="r", overrides_hold=True)
    wipe = svc.request_action(INC, "wipe_host", "srv-db-01", cmd.id, source="test")
    assert wipe.authorized and wipe.request.tier == 3
    with pytest.raises(sqlite3.IntegrityError, match="does not match"):
        _insert(svc.conn, wipe, rid="X4")

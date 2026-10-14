"""CyberRescue Phase 2A — evidence storage, binding, immutability, verification."""

import json
import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from cyberrescue.core.evidence import record_sha256, sha256_hex
from cyberrescue.core.models import EventType, IncidentStatus
from cyberrescue.core.service import CollectorError, CoreError, CoreService

NOW = datetime(2026, 6, 13, 15, 0, tzinfo=timezone.utc)
INC = "INC-C-2026-0042"


def env(ref="1", **over):
    base = {"source": "synthetic.inc-c.edr", "source_ref": ref, "kind": "process",
            "event_type": "process_start", "observed_at": f"2026-06-13T14:0{ref[-1]}:00Z",
            "provenance": "synthetic", "host": "srv-db-01", "user": "svc_backup",
            "raw": f"record {ref}: enc.exe spawned", "data": {"process.name": "enc.exe"}}
    return {**base, **over}


@pytest.fixture
def ctx(tmp_path):
    svc = CoreService.open(tmp_path / "core.db", clock=lambda: NOW)
    svc.seed_assets_from_mock()
    svc.open_incident(INC, primary_asset_id="srv-db-01",
                      recruited_roles=["threat_intel", "compliance", "commander"])
    c = SimpleNamespace(
        svc=svc,
        collector=svc.register_actor("system", "collector", "synthetic collector", "col:syn"),
        operator=svc.register_actor("human", "operator", "analyst", "h:op"),
        observer=svc.register_actor("human", "observer", "intern", "h:obs"),
        agent=svc.register_actor("agent", "threat_intel", "ti", "band:ti"))
    yield c
    svc.conn.close()


def _ingest(c, e=None, ref=INC, who=None):
    return c.svc.ingest_evidence(ref, e or env(), collector_id=(who or c.collector).id)


def _drop_evidence_triggers(conn):
    for t in ("evidence_no_update", "evidence_no_delete"):
        conn.execute(f"DROP TRIGGER {t}")


# --- creation & audit -------------------------------------------------------------

def test_ingest_creates_bound_sealed_record_with_audit_event(ctx):
    res = _ingest(ctx)
    r = res.record
    assert not res.duplicate and r.id.startswith("EV-") and r.incident_id == INC
    assert (r.host, r.asset_id, r.user) == ("srv-db-01", "srv-db-01", "svc_backup")
    assert r.ingested_by == ctx.collector.id and r.ingested_at == NOW.isoformat()
    assert r.content_sha256 == sha256_hex(r.raw)
    [ev] = ctx.svc.audit.events(INC, event_type=EventType.EVIDENCE_INGESTED)
    assert ev.uid == r.event_uid and ev.actor_id == ctx.collector.id
    assert ev.payload["content_sha256"] == r.content_sha256
    assert ev.payload["record_sha256"] == r.record_sha256
    assert "raw" not in ev.payload and "data" not in ev.payload   # hashes, not content
    assert ctx.svc.verify_audit(INC).ok and ctx.svc.verify_evidence(INC).ok


def test_unknown_host_is_not_mapped_to_an_asset(ctx):
    assert _ingest(ctx, env(host="laptop-unknown-7")).record.asset_id is None


# --- incident binding -------------------------------------------------------------

def test_alias_binding_and_unknown_incidents(ctx):
    assert _ingest(ctx, ref="inc-c").record.incident_id == INC
    for bad in ("INC-20990101-0001", "INC-A", "not an incident"):
        with pytest.raises(CoreError, match="no Core incident"):
            _ingest(ctx, ref=bad)


@pytest.mark.parametrize("status", [IncidentStatus.RESOLVED,
                                    IncidentStatus.CLOSED_FALSE_POSITIVE])
def test_closed_incidents_reject_evidence_and_are_not_reopened(ctx, status):
    ctx.svc.store.set_status(INC, status, trigger="test", actor_id=None, cause_uid=None)
    events_before = len(ctx.svc.audit.events(INC))
    with pytest.raises(CoreError, match="rejected for closed incidents"):
        _ingest(ctx)
    with pytest.raises(CoreError, match="rejected for closed incidents"):
        ctx.svc.ingest_evidence_batch(INC, [env()], collector_id=ctx.collector.id)
    assert ctx.svc.store.get_incident(INC).status == status
    assert len(ctx.svc.audit.events(INC)) == events_before
    assert ctx.svc.list_evidence(INC) == []


def test_same_content_in_two_incidents_is_two_distinct_records(ctx):
    ctx.svc.open_incident("INC-A-2026-0039", primary_asset_id="ws-eng-014",
                          recruited_roles=["threat_intel", "commander"])
    a = _ingest(ctx).record
    b = _ingest(ctx, ref="INC-A").record
    assert a.id != b.id and (a.incident_id, b.incident_id) == (INC, "INC-A-2026-0039")
    assert a.content_sha256 == b.content_sha256


# --- who may submit evidence --------------------------------------------------------

def test_only_collectors_and_human_operators_may_submit(ctx):
    assert _ingest(ctx, env("1"), who=ctx.collector).record
    assert _ingest(ctx, env("2"), who=ctx.operator).record
    for who in (ctx.agent, ctx.observer):
        with pytest.raises(CollectorError, match="may not submit evidence"):
            _ingest(ctx, env("3"), who=who)
    with pytest.raises(CollectorError, match="not registered"):
        ctx.svc.ingest_evidence(INC, env("4"), collector_id="made-up")
    assert len(ctx.svc.list_evidence(INC)) == 2


# --- duplicates & batches --------------------------------------------------------------

def test_duplicate_ingestion_is_idempotent(ctx):
    first, second = _ingest(ctx), _ingest(ctx)
    assert second.duplicate and second.record.id == first.record.id
    assert len(ctx.svc.list_evidence(INC)) == 1
    assert len(ctx.svc.audit.events(INC, event_type=EventType.EVIDENCE_INGESTED)) == 1
    # Same content, different source_ref = a distinct observation.
    assert not _ingest(ctx, env("1", source_ref="1b")).duplicate


def test_batch_is_all_or_nothing_and_replay_idempotent(ctx):
    batch = [env("1"), env("2"), env("1")]            # includes an in-batch duplicate
    rep = ctx.svc.ingest_evidence_batch(INC, batch, collector_id=ctx.collector.id)
    assert len(rep.ingested) == 2 and len(rep.duplicates) == 1
    replay = ctx.svc.ingest_evidence_batch(INC, batch, collector_id=ctx.collector.id)
    assert replay.ingested == [] and len(replay.duplicates) == 3
    with pytest.raises(CoreError, match="nothing stored") as e:
        ctx.svc.ingest_evidence_batch(INC, [env("3"), env("4", kind="bogus")],
                                      collector_id=ctx.collector.id)
    assert "item 2" in str(e.value)
    assert len(ctx.svc.list_evidence(INC)) == 2


# --- retrieval ---------------------------------------------------------------------------

def test_retrieval_by_id_and_filters_in_observation_order(ctx):
    ctx.svc.ingest_evidence_batch(INC, [
        env("3"), env("1"),
        env("2", kind="network", host="srv-app-01", event_type="smb_auth")],
        collector_id=ctx.collector.id)
    all_ev = ctx.svc.list_evidence(INC)
    assert [e.source_ref for e in all_ev] == ["1", "2", "3"]
    assert ctx.svc.get_evidence(all_ev[0].id) == all_ev[0]
    assert ctx.svc.get_evidence("EV-000000000000000000000000") is None
    assert [e.source_ref for e in ctx.svc.list_evidence(INC, kind="network")] == ["2"]
    assert [e.source_ref for e in ctx.svc.list_evidence(INC, host="srv-db-01")] == ["1", "3"]
    window = ctx.svc.list_evidence(INC, since="2026-06-13T14:02:00+00:00",
                                   until="2026-06-13T14:03:00+00:00")
    assert [e.source_ref for e in window] == ["2", "3"]


# --- immutability & tamper detection ------------------------------------------------------

def test_evidence_rows_cannot_be_updated_or_deleted(ctx):
    r = _ingest(ctx).record
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        ctx.svc.conn.execute("UPDATE evidence SET raw = 'x' WHERE id = ?", (r.id,))
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        ctx.svc.conn.execute("DELETE FROM evidence WHERE id = ?", (r.id,))


def test_altered_raw_content_is_detected(ctx):
    r = _ingest(ctx).record
    _drop_evidence_triggers(ctx.svc.conn)
    ctx.svc.conn.execute("UPDATE evidence SET raw = 'benign' WHERE id = ?", (r.id,))
    res = ctx.svc.verify_evidence(INC)
    assert not res.ok and any("content_sha256 does not match" in e for e in res.errors)


def test_rehashed_forgery_is_caught_by_the_audit_cross_check(ctx):
    r = _ingest(ctx).record
    # Attacker rewrites raw AND recomputes both hashes so the row is self-consistent.
    forged = r.model_dump(mode="json")
    forged["raw"] = "nothing to see here"
    forged["content_sha256"] = sha256_hex(forged["raw"])
    forged["record_sha256"] = record_sha256(forged)
    _drop_evidence_triggers(ctx.svc.conn)
    ctx.svc.conn.execute(
        "UPDATE evidence SET raw = ?, content_sha256 = ?, record_sha256 = ? WHERE id = ?",
        (forged["raw"], forged["content_sha256"], forged["record_sha256"], r.id))
    res = ctx.svc.verify_evidence(INC)
    assert not res.ok
    assert any("content_sha256 differs from the audit record" in e for e in res.errors)
    assert ctx.svc.verify_audit(INC).ok      # the audit chain itself is intact


def test_deleted_evidence_is_detected_from_the_audit_trail(ctx):
    r = _ingest(ctx).record
    _drop_evidence_triggers(ctx.svc.conn)
    ctx.svc.conn.execute("DELETE FROM evidence WHERE id = ?", (r.id,))
    res = ctx.svc.verify_evidence(INC)
    assert not res.ok and any("evidence record is missing" in e for e in res.errors)


def test_stored_json_fields_round_trip(ctx):
    r = _ingest(ctx, env(data={"b": [1, 2], "a": {"x": None}},
                         metadata={"parser": "synthetic-v1"})).record
    row = ctx.svc.conn.execute("SELECT data, metadata FROM evidence WHERE id = ?",
                               (r.id,)).fetchone()
    assert json.loads(row["data"]) == {"b": [1, 2], "a": {"x": None}}
    assert r.metadata == {"parser": "synthetic-v1"}
    assert ctx.svc.verify_evidence(INC).ok

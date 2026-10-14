"""CyberRescue Core — hash-chained audit log (cyberrescue/core/audit.py)."""

import pytest

from cyberrescue.core import db
from cyberrescue.core.audit import GENESIS_HASH, AuditLog, canonical_json
from cyberrescue.core.models import EventType, LinkRelation


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "core.db")
    # Two incidents to chain against (audit_events.incident_id is an FK).
    for iid in ("INC-T-1", "INC-T-2"):
        c.execute("INSERT INTO incidents(id, status, created_at, updated_at) "
                  "VALUES (?, 'NEW', 'now', 'now')", (iid,))
    yield c
    c.close()


@pytest.fixture
def log(conn):
    return AuditLog(conn)


def _drop_triggers(conn):
    """Simulate an attacker with raw file access bypassing the append-only guard."""
    for t in ("audit_events_no_update", "audit_events_no_delete",
              "event_links_no_update", "event_links_no_delete"):
        conn.execute(f"DROP TRIGGER {t}")


def test_seq_is_per_incident_and_chain_starts_at_genesis(log):
    a1 = log.append(EventType.INCIDENT_OPENED, incident_id="INC-T-1")
    b1 = log.append(EventType.INCIDENT_OPENED, incident_id="INC-T-2")
    a2 = log.append(EventType.FINDING_RECORDED, incident_id="INC-T-1")
    s1 = log.append(EventType.ASSET_SEEDED)  # system chain
    assert (a1.seq, a2.seq, b1.seq, s1.seq) == (1, 2, 1, 1)
    assert a1.prev_hash == GENESIS_HASH and a2.prev_hash == a1.hash
    assert s1.chain == "__system__"


def test_clean_chain_verifies(log):
    for i in range(5):
        log.append(EventType.PROTOCOL_MESSAGE, incident_id="INC-T-1", payload={"i": i})
    res = log.verify("INC-T-1")
    assert res.ok and res.checked == 5 and res.errors == []


def test_edited_payload_is_detected(conn, log):
    for i in range(3):
        log.append(EventType.PROTOCOL_MESSAGE, incident_id="INC-T-1", payload={"i": i})
    _drop_triggers(conn)
    conn.execute("UPDATE audit_events SET payload = ? WHERE chain = 'INC-T-1' AND seq = 2",
                 (canonical_json({"i": 999, "approved": True}),))
    res = log.verify("INC-T-1")
    assert not res.ok
    assert any("seq 2: content hash mismatch" in e for e in res.errors)


def test_deleted_event_is_detected(conn, log):
    for i in range(4):
        log.append(EventType.PROTOCOL_MESSAGE, incident_id="INC-T-1", payload={"i": i})
    _drop_triggers(conn)
    conn.execute("DELETE FROM audit_events WHERE chain = 'INC-T-1' AND seq = 2")
    res = log.verify("INC-T-1")
    assert not res.ok
    assert any("seq gap" in e for e in res.errors)
    assert any("prev_hash does not match" in e for e in res.errors)


def test_canonical_hash_ignores_key_order():
    assert canonical_json({"b": 1, "a": [2, {"d": 3, "c": 4}]}) == \
        canonical_json({"a": [2, {"c": 4, "d": 3}], "b": 1})


def test_links_are_stored_hashed_and_tamper_evident(conn, log):
    finding = log.append(EventType.FINDING_RECORDED, incident_id="INC-T-1")
    other = log.append(EventType.FINDING_RECORDED, incident_id="INC-T-1")
    ev = log.append(EventType.EVIDENCE_RECORDED, incident_id="INC-T-1",
                    links=[(LinkRelation.SUPPORTS, finding.uid)])
    got = log.get(ev.uid)
    assert [(link.relation, link.target_uid) for link in got.links] == \
        [(LinkRelation.SUPPORTS, finding.uid)]
    assert log.links_to(finding.uid) == [("supports", ev.uid)]
    assert log.verify("INC-T-1").ok
    # Re-point the evidence at a different finding -> detected.
    _drop_triggers(conn)
    conn.execute("UPDATE event_links SET to_uid = ? WHERE from_uid = ?", (other.uid, ev.uid))
    assert not log.verify("INC-T-1").ok


def test_failed_append_leaves_no_partial_event(conn, log):
    with pytest.raises(Exception):
        # Link to a non-existent event violates the FK -> whole append rolls back.
        log.append(EventType.EVIDENCE_RECORDED, incident_id="INC-T-1",
                   links=[(LinkRelation.SUPPORTS, "no-such-event")])
    assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0
    assert log.verify("INC-T-1").ok

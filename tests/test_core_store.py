"""CyberRescue Core — domain persistence (cyberrescue/core/store.py)."""

from datetime import datetime, timezone

import pytest

from cyberrescue.core import db
from cyberrescue.core.models import ActorKind, Asset, EventType, IncidentStatus
from cyberrescue.core.store import CoreStore

FIXED = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def store(tmp_path):
    conn = db.connect(tmp_path / "core.db")
    s = CoreStore(conn, clock=lambda: FIXED)
    s.add_asset(Asset(asset_id="srv-db-01", criticality="critical",
                      data_classes=["customer_pii"]))
    yield s
    conn.close()


def test_actor_identity_is_sticky_and_roles_validated(store):
    a = store.register_actor(ActorKind.AGENT, "threat_intel", "intel", "band:agent-1")
    again = store.register_actor(ActorKind.AGENT, "commander", "impostor", "band:agent-1")
    assert again.id == a.id and again.role == "threat_intel"
    with pytest.raises(ValueError):
        store.register_actor(ActorKind.HUMAN, "god_mode")
    with pytest.raises(ValueError):
        store.register_actor(ActorKind.AGENT, "ciso")


def test_create_incident_writes_audit_events_and_legacy_alias(store):
    inc = store.create_incident(incident_id="INC-C-2026-0042", title="ransomware",
                                primary_asset_id="srv-db-01",
                                recruited_roles=["threat_intel", "compliance", "commander"])
    assert inc.status == IncidentStatus.NEW and inc.specialists == {"threat_intel", "compliance"}
    types = [e.event_type for e in store.audit.events(inc.id)]
    assert types == ["INCIDENT_OPENED", "ALIAS_REGISTERED"]
    assert store.aliases_of(inc.id) == ["INC-C"]
    assert store.resolve_incident("inc-c") == inc.id
    assert store.resolve_incident("INC-C-2026-[decorated]") == inc.id
    assert store.resolve_incident("INC-A") is None  # parsed, but not opened
    with pytest.raises(ValueError):
        store.create_incident(incident_id=inc.id)


def test_generated_incident_ids_are_sequential_per_day(store):
    a = store.create_incident(title="one")
    b = store.create_incident(title="two")
    assert (a.id, b.id) == ("INC-20260927-0001", "INC-20260927-0002")


def test_create_incident_rejects_unknown_asset(store):
    with pytest.raises(ValueError, match="unknown asset"):
        store.create_incident(primary_asset_id="srv-nope")


def test_status_change_is_audited_and_linked_to_its_cause(store):
    inc = store.create_incident(title="t")
    cause = store.audit.events(inc.id)[0]
    ev = store.set_status(inc.id, IncidentStatus.RESOLVED, trigger="RESOLUTION",
                          actor_id=None, cause_uid=cause.uid)
    assert ev.event_type == EventType.STATE_CHANGED.value
    assert ev.payload == {"from": "NEW", "to": "RESOLVED", "trigger": "RESOLUTION"}
    assert [(link.relation, link.target_uid) for link in ev.links] == [("caused_by", cause.uid)]
    got = store.get_incident(inc.id)
    assert got.status == IncidentStatus.RESOLVED and got.closed_at
    assert store.audit.verify(inc.id).ok

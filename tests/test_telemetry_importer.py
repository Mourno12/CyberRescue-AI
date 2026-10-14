"""CyberRescue Phase 2B — telemetry -> existing Evidence import -> Evidence store."""

import json
from collections import Counter
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from cyberrescue.core.models import EventType
from cyberrescue.core.service import CollectorError, CoreError, CoreService
from cyberrescue.core.state_machine import Trigger
from cyberrescue.telemetry.adapter import load_telemetry_jsonl
from cyberrescue.telemetry.catalog import CATALOG, telemetry_path
from cyberrescue.telemetry.importer import (
    AUDIT_SOURCE,
    import_events,
    import_file,
    import_scenario,
)
from cyberrescue.telemetry.schema import TelemetryError
from shared.mock_data import load_alert

NOW = datetime(2026, 6, 13, 15, 0, tzinfo=timezone.utc)


def _open(svc, alias):
    alert = load_alert(alias)
    return svc.open_incident(alert["incident_id"], title=alert["title"],
                             primary_asset_id=alert["asset_id"])


@pytest.fixture
def ctx(tmp_path):
    svc = CoreService.open(tmp_path / "core.db", clock=lambda: NOW)
    svc.seed_assets_from_mock()
    for alias in ("INC-A", "INC-B", "INC-C"):
        _open(svc, alias)
    c = SimpleNamespace(
        svc=svc,
        collector=svc.register_actor("system", "collector", "syn", "collector:synthetic"),
        agent=svc.register_actor("agent", "threat_intel", "ti", "band:ti"))
    yield c
    svc.conn.close()


@pytest.mark.parametrize("key", list(CATALOG))
def test_scenario_imports_into_its_mapped_incident(ctx, key):
    info = CATALOG[key]
    events = load_telemetry_jsonl(telemetry_path(key))
    rep = import_scenario(ctx.svc, key, collector_id=ctx.collector.id)
    assert (rep.incident_id, rep.dataset) == (info.incident_id, info.dataset)
    assert rep.events == len(events) == len(rep.ingested) and rep.duplicates == []
    stored = ctx.svc.list_evidence(info.incident_alias)
    assert len(stored) == len(events)
    assert {e.incident_id for e in stored} == {info.incident_id}
    assert sorted(e.source_ref for e in stored) == sorted(e.event_id for e in events)
    assert Counter(e.kind.value for e in stored) == Counter(e.category.value for e in events)
    assert all(e.provenance.value == "synthetic" and e.ingested_by == ctx.collector.id
               for e in stored)
    # The other incidents received nothing.
    for other in CATALOG.values():
        if other.key != key:
            assert ctx.svc.list_evidence(other.incident_alias) == []


@pytest.mark.parametrize("key", list(CATALOG))
def test_imported_evidence_is_verbatim_sealed_and_audited(ctx, key):
    events = {e.event_id: e for e in load_telemetry_jsonl(telemetry_path(key))}
    import_scenario(ctx.svc, key, collector_id=ctx.collector.id)
    iid = CATALOG[key].incident_id
    for rec in ctx.svc.list_evidence(iid):
        ev = events[rec.source_ref]
        assert (rec.raw, rec.data, rec.observed_at) == (ev.message, ev.fields, ev.timestamp)
        assert rec.source == f"synthetic.{ev.dataset}.{ev.sensor}"
        assert rec.asset_id == ev.host              # every scenario host is in the inventory
    assert ctx.svc.verify_evidence(iid).ok and ctx.svc.verify_audit(iid).ok
    ingested = [e for e in ctx.svc.audit.events(iid)
                if e.event_type == EventType.EVIDENCE_INGESTED.value]
    assert len(ingested) == len(events) and {e.source for e in ingested} == {AUDIT_SOURCE}


def test_reimport_is_idempotent(ctx):
    first = import_scenario(ctx.svc, "A", collector_id=ctx.collector.id)
    audit_before = len(ctx.svc.audit.events(first.incident_id))
    again = import_scenario(ctx.svc, "a", collector_id=ctx.collector.id)
    assert again.ingested == [] and sorted(again.duplicates) == sorted(first.ingested)
    assert len(ctx.svc.list_evidence("INC-C")) == first.events
    assert len(ctx.svc.audit.events(first.incident_id)) == audit_before


def test_vendor_alert_becomes_alert_evidence_not_a_finding(ctx):
    import_scenario(ctx.svc, "A", collector_id=ctx.collector.id)
    alerts = ctx.svc.list_evidence("INC-C", kind="alert")
    assert [a.event_type for a in alerts] == ["edr_detection"]
    assert alerts[0].observed_at == "2026-06-13T14:07:22+00:00"
    for table in ("findings", "finding_claims", "finding_evidence"):
        assert ctx.svc.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_agents_cannot_import_telemetry(ctx):
    with pytest.raises(CollectorError):
        import_scenario(ctx.svc, "A", collector_id=ctx.agent.id)
    with pytest.raises(CollectorError):
        import_scenario(ctx.svc, "A", collector_id="not-registered")
    assert ctx.svc.list_evidence("INC-C") == []


def test_incident_must_exist_and_is_never_created(tmp_path):
    svc = CoreService.open(tmp_path / "empty.db", clock=lambda: NOW)
    col = svc.register_actor("system", "collector", "syn")
    with pytest.raises(CoreError, match="no Core incident"):
        import_scenario(svc, "B", collector_id=col.id)
    assert svc.conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0
    svc.conn.close()


def test_closed_incident_rejects_telemetry_and_is_not_reopened(ctx):
    iid = CATALOG["B"].incident_id
    triage = ctx.svc.register_actor("agent", "triage", "triage", "band:triage")
    assert ctx.svc.apply_trigger(iid, Trigger.CLOSE, triage).changed
    status = ctx.svc.store.get_incident(iid).status
    assert status.value == "CLOSED_FALSE_POSITIVE"
    with pytest.raises(CoreError, match="closed incidents"):
        import_scenario(ctx.svc, "B", collector_id=ctx.collector.id)
    assert ctx.svc.store.get_incident(iid).status == status
    assert ctx.svc.list_evidence(iid) == []


def test_binding_comes_from_the_caller_not_the_content(ctx):
    # Scenario C's telemetry is about ws-eng-014 (INC-A), but an operator may
    # file it under another incident; content never decides the binding.
    rep = import_file(ctx.svc, telemetry_path("C"), "INC-C", collector_id=ctx.collector.id)
    assert rep.incident_id == CATALOG["A"].incident_id
    assert ctx.svc.list_evidence("INC-A") == []
    assert len(ctx.svc.list_evidence("INC-C")) == rep.events


def test_invalid_telemetry_stores_nothing(ctx, tmp_path):
    lines = telemetry_path("B").read_text(encoding="utf-8").splitlines()
    bad = json.loads(lines[5]) | {"incident_id": "INC-A"}
    p = tmp_path / "bad.jsonl"
    p.write_text("\n".join(lines[:5] + [json.dumps(bad)] + lines[6:]), encoding="utf-8")
    with pytest.raises(TelemetryError, match="line 6"):
        import_file(ctx.svc, p, "INC-B", collector_id=ctx.collector.id)
    with pytest.raises(TelemetryError, match="item 2"):
        import_events(ctx.svc, "INC-B", [json.loads(lines[0]), bad],
                      collector_id=ctx.collector.id)
    assert ctx.svc.list_evidence("INC-B") == []


def test_scenario_file_with_foreign_dataset_is_rejected(ctx, tmp_path):
    root = tmp_path / "root"
    (root / "telemetry").mkdir(parents=True)
    (root / "telemetry" / "scenario-a.jsonl").write_bytes(telemetry_path("B").read_bytes())
    with pytest.raises(TelemetryError, match="other datasets"):
        import_scenario(ctx.svc, "A", collector_id=ctx.collector.id, root=root)
    assert ctx.svc.list_evidence("INC-C") == []

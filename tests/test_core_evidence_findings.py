"""CyberRescue Phase 2A — findings citing evidence (strict API + agent messages)."""

import json
import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from cyberrescue.core.ingest import IngestedMessage, ProtocolIngestor
from cyberrescue.core.models import ActorKind, EventType, IncidentStatus
from cyberrescue.core.service import (
    MAX_CITATIONS_PER_FINDING,
    CitationError,
    CoreError,
    CoreService,
)

NOW = datetime(2026, 6, 13, 15, 0, tzinfo=timezone.utc)
INC, INC_A = "INC-C-2026-0042", "INC-A-2026-0039"


def env(ref, **over):
    return {"source": "synthetic.inc-c.edr", "source_ref": ref, "kind": "network",
            "event_type": "smb_auth", "observed_at": "2026-06-13T14:03:00Z",
            "provenance": "synthetic", "host": "srv-db-01",
            "raw": f"smb auth attempt #{ref} srv-db-01 -> srv-dc-01", **over}


@pytest.fixture
def ctx(tmp_path):
    svc = CoreService.open(tmp_path / "core.db", clock=lambda: NOW)
    svc.seed_assets_from_mock()
    svc.open_incident(INC, primary_asset_id="srv-db-01",
                      recruited_roles=["threat_intel", "compliance", "commander"])
    svc.open_incident(INC_A, primary_asset_id="ws-eng-014",
                      recruited_roles=["threat_intel", "commander"])
    col = svc.register_actor("system", "collector", "collector", "col:1")
    c = SimpleNamespace(
        svc=svc, col=col,
        intel=svc.register_actor("agent", "threat_intel", "ti", "band:ti"),
        comp=svc.register_actor("agent", "compliance", "c", "band:c"),
        observer=svc.register_actor("human", "observer", "intern", "h:obs"),
        rogue=svc.register_actor("agent", "unknown", "rogue", "band:rogue"),
        e1=svc.ingest_evidence(INC, env("1"), collector_id=col.id).record,
        e2=svc.ingest_evidence(INC, env("2"), collector_id=col.id).record,
        a1=svc.ingest_evidence(INC_A, env("1", host="ws-eng-014"), collector_id=col.id).record)
    yield c
    svc.conn.close()


def _evidence_count(svc):
    return svc.conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]


# --- strict programmatic API --------------------------------------------------------

def test_finding_cites_evidence_and_both_directions_query(ctx):
    f = ctx.svc.record_finding(INC, ctx.intel, "lateral movement to the DC",
                               claims=["SMB auth to srv-dc-01"],
                               evidence_ids=[ctx.e1.id, ctx.e2.id, ctx.e1.id])
    cited = ctx.svc.evidence.evidence_for_finding(f.id)
    assert [(r.id, rel) for r, rel in cited] == [(ctx.e1.id, "supports"), (ctx.e2.id, "supports")]
    assert ctx.svc.evidence.findings_citing(ctx.e1.id) == [(f.id, "supports")]
    assert [c.content for c in ctx.svc.store.claims_for(f.id)] == ["SMB auth to srv-dc-01"]


def test_relations_and_idempotent_links(ctx):
    f = ctx.svc.record_finding(INC, ctx.intel, "no exfil observed")
    ctx.svc.link_evidence(f.id, ctx.e1.id, linked_by=ctx.intel.id, relation="contradicts")
    ctx.svc.link_evidence(f.id, ctx.e2.id, linked_by=ctx.col.id, relation="context")
    again = ctx.svc.link_evidence(f.id, ctx.e1.id, linked_by=ctx.intel.id, relation="supports")
    assert again.relation.value == "contradicts"                  # first link stands
    assert len(ctx.svc.audit.events(INC, event_type=EventType.FINDING_EVIDENCE_LINKED)) == 2
    with pytest.raises(ValueError):
        ctx.svc.link_evidence(f.id, ctx.e2.id, linked_by=ctx.intel.id, relation="proves")


def test_unknown_or_cross_incident_evidence_rejects_the_whole_finding(ctx):
    for bad in ("EV-000000000000000000000000", ctx.a1.id, 42):
        with pytest.raises(CoreError, match="unknown evidence id"):
            ctx.svc.record_finding(INC, ctx.intel, "x", claims=["c"],
                                   evidence_ids=[ctx.e1.id, bad])
    assert ctx.svc.store.findings(INC) == []                      # atomic: nothing recorded


def test_database_trigger_blocks_cross_incident_links(ctx):
    f = ctx.svc.record_finding(INC, ctx.intel, "x")
    ev = ctx.svc.audit.events(INC)[-1]
    with pytest.raises(sqlite3.IntegrityError, match="different incidents"):
        ctx.svc.conn.execute(
            "INSERT INTO finding_evidence(finding_id, evidence_id, relation, linked_by, "
            "event_uid, created_at) VALUES (?,?,?,?,?,?)",
            (f.id, ctx.a1.id, "supports", ctx.intel.id, ev.uid, "now"))


def test_links_are_audited_with_cites_and_concerns(ctx):
    f = ctx.svc.record_finding(INC, ctx.intel, "x", evidence_ids=[ctx.e1.id])
    [ev] = ctx.svc.audit.events(INC, event_type=EventType.FINDING_EVIDENCE_LINKED)
    assert {(link.relation, link.target_uid) for link in ev.links} == {
        ("cites", ctx.e1.event_uid), ("concerns", f.event_uid)}
    assert ev.payload["content_sha256"] == ctx.e1.content_sha256
    assert ctx.svc.verify_audit(INC).ok
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        ctx.svc.conn.execute("DELETE FROM finding_evidence")


def test_who_may_link_evidence(ctx):
    mine = ctx.svc.record_finding(INC, ctx.intel, "intel finding")
    ctx.svc.link_evidence(mine.id, ctx.e1.id, linked_by=ctx.intel.id)       # own finding: ok
    ctx.svc.link_evidence(mine.id, ctx.e2.id, linked_by=ctx.col.id)         # system: ok
    for who in (ctx.comp, ctx.observer, ctx.rogue):
        with pytest.raises(CitationError):
            ctx.svc.link_evidence(mine.id, ctx.e1.id, linked_by=who.id)
    with pytest.raises(CitationError):
        ctx.svc.record_finding(INC, ctx.rogue, "x", evidence_ids=[ctx.e1.id])


def test_citations_are_frozen_on_closed_incidents(ctx):
    f = ctx.svc.record_finding(INC, ctx.intel, "x")
    ctx.svc.store.set_status(INC, IncidentStatus.RESOLVED, trigger="t", actor_id=None,
                             cause_uid=None)
    with pytest.raises(CoreError, match="citations are frozen"):
        ctx.svc.link_evidence(f.id, ctx.e1.id, linked_by=ctx.intel.id)


# --- agent FINDING messages (untrusted text) -------------------------------------------

def _finding_msg(svc, actor_ref, role, **block):
    content = "analysis\n```json\n" + json.dumps(
        {"type": "FINDING", "incident": "INC-C", "summary": "s", **block}) + "\n```"
    return ProtocolIngestor(svc).ingest(IngestedMessage(
        incident_ref="INC-C", sender_ref=actor_ref, sender_kind=ActorKind.AGENT,
        sender_role=role, content=content, source="band"))


def test_agent_message_cites_valid_evidence_ids(ctx):
    before = _evidence_count(ctx.svc)
    _finding_msg(ctx.svc, "ti-1", "threat_intel", evidence=["C2 beacon seen"],
                 evidence_ids=[ctx.e1.id, ctx.e2.id])
    [f] = ctx.svc.store.findings(INC)
    assert [r.id for r, _ in ctx.svc.evidence.evidence_for_finding(f.id)] == \
        [ctx.e1.id, ctx.e2.id]
    assert [c.content for c in ctx.svc.store.claims_for(f.id)] == ["C2 beacon seen"]
    assert _evidence_count(ctx.svc) == before                   # citing creates nothing


def test_hallucinated_and_foreign_citations_are_rejected_but_audited(ctx):
    _finding_msg(ctx.svc, "ti-1", "threat_intel",
                 evidence_ids=[ctx.e1.id, "EV-hallucinated-by-llm", ctx.a1.id, {"id": 1}])
    [f] = ctx.svc.store.findings(INC)                           # the finding still stands
    assert [r.id for r, _ in ctx.svc.evidence.evidence_for_finding(f.id)] == [ctx.e1.id]
    rejected = [e.payload for e in ctx.svc.audit.events(INC, event_type=EventType.CLAIM_REJECTED)]
    assert len(rejected) == 3 and all(p["claim"] == "EVIDENCE_CITATION" for p in rejected)
    assert all("unknown evidence id for this incident" in p["reason"] for p in rejected)
    assert ctx.a1.id in rejected[1]["reason"]                    # the ref is on record
    assert "INC-A" not in json.dumps(rejected)                   # no cross-incident oracle


def test_malformed_or_excessive_citations(ctx):
    _finding_msg(ctx.svc, "ti-1", "threat_intel", evidence_ids=ctx.e1.id)   # not a list
    too_many = [ctx.e1.id] + [f"EV-{i:024d}" for i in range(MAX_CITATIONS_PER_FINDING + 2)]
    _finding_msg(ctx.svc, "ti-1", "threat_intel", evidence_ids=too_many)
    reasons = [e.payload["reason"] for e in
               ctx.svc.audit.events(INC, event_type=EventType.CLAIM_REJECTED)]
    assert any("must be a list" in r for r in reasons)
    assert sum("more than" in r for r in reasons) == 3
    assert len(ctx.svc.store.findings(INC)) == 2

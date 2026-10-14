"""CyberRescue Phase 2C — detections become evidence-backed findings (explicit persist)."""

import json

import pytest

from cyberrescue.core.models import ActorKind, EventType, IncidentStatus
from cyberrescue.core.service import CitationError, CoreError
from cyberrescue.detection.engine import detect
from cyberrescue.detection.model import DetectionReport
from cyberrescue.detection.publisher import CLAIM_KIND, detection_findings, persist
from tests._detection_factory import scenario_core

INC = "INC-A"                       # scenario C: 5 detections, small and fast


@pytest.fixture
def ctx(tmp_path):
    svc, collector = scenario_core(tmp_path / "core.db", keys=("C", "A"))
    detector = svc.register_actor("system", "detector", "detection-engine", "detector:1")
    yield svc, detector, collector
    svc.conn.close()


def counts(svc):
    tables = ("findings", "finding_claims", "finding_evidence", "audit_events", "approvals",
              "signoffs", "vetoes", "action_requests", "policy_decisions", "incidents",
              "actors", "evidence")
    return {t: svc.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}


def test_dry_run_writes_nothing(ctx):
    svc, _, _ = ctx
    before = counts(svc)
    detect(svc, INC)
    assert counts(svc) == before


def test_persist_records_findings_with_citations_and_detection_claim(ctx):
    svc, detector, _ = ctx
    rep = detect(svc, INC)
    pub = persist(svc, INC, rep, detector_id=detector.id)
    assert len(pub.created) == len(rep.detections) == 5 and pub.skipped == []
    for det in rep.detections:
        fid = dict(pub.created)[det.detection_id]
        f = svc.store.get_finding(fid)
        assert (f.author_actor_id, f.severity, f.summary) == (detector.id, det.severity,
                                                              det.summary)
        links = {e.id: rel for e, rel in svc.evidence.evidence_for_finding(fid)}
        assert {i for i, r in links.items() if r == "supports"} == \
            set(det.supporting_evidence_ids)
        assert {i for i, r in links.items() if r == "context"} == set(det.context_evidence_ids)
        [claim] = svc.store.claims_for(fid)
        assert claim.kind == CLAIM_KIND
        payload = json.loads(claim.content)
        assert payload["rule_id"] == det.rule_id and payload["rule_version"] == det.rule_version
        assert payload["conditions"] == [c.model_dump(mode="json") for c in det.conditions]
        assert payload["supersedes"] is None


def test_persist_emits_only_finding_audit_events(ctx):
    svc, detector, _ = ctx
    iid = svc.store.resolve_incident(INC)
    n = len(svc.audit.events(iid))
    persist(svc, INC, detect(svc, INC), detector_id=detector.id)
    new = {e.event_type for e in svc.audit.events(iid)[n:]}
    assert new == {EventType.FINDING_RECORDED.value, EventType.CLAIM_RECORDED.value,
                   EventType.FINDING_EVIDENCE_LINKED.value}
    assert svc.verify_audit(iid).ok and svc.verify_evidence(iid).ok


def test_republishing_is_idempotent(ctx):
    svc, detector, _ = ctx
    persist(svc, INC, detect(svc, INC), detector_id=detector.id)
    before = counts(svc)
    again = persist(svc, INC, detect(svc, INC), detector_id=detector.id)
    assert again.created == [] and len(again.skipped) == 5
    assert counts(svc) == before
    assert len(detection_findings(svc, INC)) == 5


def test_changed_evidence_for_the_same_detection_supersedes(ctx):
    svc, detector, _ = ctx
    rep = detect(svc, INC)
    first = dict(persist(svc, INC, rep, detector_id=detector.id).created)
    chain = next(d for d in rep.detections if d.rule_id == "CORR-001")
    changed = chain.model_copy(update={            # same detection_key, other evidence
        "detection_id": "DET-changed", "supporting_evidence_ids":
            chain.supporting_evidence_ids[:-1]})
    pub = persist(svc, INC, rep.model_copy(update={"detections": (changed,)}),
                  detector_id=detector.id)
    assert pub.superseded == [("DET-changed", first[chain.detection_id])]
    latest = detection_findings(svc, INC)[-1]
    assert latest.detection_id == "DET-changed"
    assert latest.payload["supersedes"] == first[chain.detection_id]
    assert len(detection_findings(svc, INC)) == 6          # append-only: the old one stays


def test_report_for_another_incident_is_refused(ctx):
    svc, detector, _ = ctx
    with pytest.raises(CoreError, match="report is for"):
        persist(svc, "INC-C", detect(svc, INC), detector_id=detector.id)


def test_cross_incident_evidence_is_rejected_atomically(ctx):
    svc, detector, _ = ctx
    rep = detect(svc, INC)
    foreign = svc.list_evidence("INC-C")[0].id
    bad = rep.detections[-1].model_copy(update={
        "detection_id": "DET-bad",
        "supporting_evidence_ids": (*rep.detections[-1].supporting_evidence_ids, foreign)})
    before = counts(svc)
    with pytest.raises(CoreError, match="unknown evidence id"):
        persist(svc, INC, rep.model_copy(update={"detections": (*rep.detections, bad)}),
                detector_id=detector.id)
    assert counts(svc) == before                      # the 5 valid ones were rolled back too


def test_closed_incident_refuses_new_findings(ctx):
    svc, detector, _ = ctx
    iid = svc.store.resolve_incident(INC)
    rep = detect(svc, INC)                            # dry run still works
    svc.store.set_status(iid, IncidentStatus.RESOLVED, trigger="test", actor_id=None,
                         cause_uid=None)
    before = counts(svc)
    with pytest.raises(CoreError, match="frozen"):
        persist(svc, INC, rep, detector_id=detector.id)
    assert counts(svc) == before


@pytest.mark.parametrize("who", ["collector", "agent", "human", "unregistered"])
def test_only_a_detector_actor_may_publish(ctx, who):
    svc, _, collector = ctx
    make = {"collector": lambda: collector,               # SYSTEM, but role collector
            "agent": lambda: svc.register_actor("agent", "threat_intel", "llm"),
            "human": lambda: svc.register_actor("human", "operator", "op"),
            "unregistered": lambda: None}
    actor = make[who]()
    with pytest.raises(CitationError, match="role 'detector'"):
        persist(svc, INC, detect(svc, INC),
                detector_id=actor.id if actor else "not-registered")
    assert detection_findings(svc, INC) == []
    assert actor is None or actor.kind in (ActorKind.SYSTEM, ActorKind.AGENT, ActorKind.HUMAN)


def test_empty_report_persists_nothing(ctx):
    svc, detector, _ = ctx
    rep = detect(svc, "INC-A")
    empty = DetectionReport(incident_id=rep.incident_id, ruleset_version=rep.ruleset_version,
                            inputs={})
    assert persist(svc, INC, empty, detector_id=detector.id).created == []


def test_record_finding_default_claim_kind_is_unchanged(ctx):
    svc, detector, _ = ctx
    f = svc.record_finding(svc.store.resolve_incident(INC), detector, "s", claims=["c"])
    assert [c.kind for c in svc.store.claims_for(f.id)] == ["protocol_claim"]

"""Persist detections as evidence-backed findings — an explicit operator step.

Uses only the existing Phase 2A APIs:

* ``CoreService.record_finding`` — the finding, its supporting citations
  (strict: every id must be evidence of the same incident) and ONE claim of
  kind ``detection`` holding the canonical JSON of the Detection (rule, version,
  conditions, window, confidence basis, evidence ids);
* ``CoreService.link_evidence`` — the context citations (relation ``context``).

All detections of a report are written in one transaction: any failure stores
nothing. Re-publishing is idempotent by ``detection_id``; a detection whose
``detection_key`` already has a finding but whose evidence changed is recorded
as a NEW finding that names the one it ``supersedes`` (findings are append-only).
Observations are never persisted.

Only a registered SYSTEM actor with role ``detector`` may publish. Publishing
never touches approvals, sign-offs, vetoes, holds, actors, incident state,
policy or the Commander gate — findings are not part of the policy snapshot.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from cyberrescue.core import db
from cyberrescue.core.audit import canonical_json
from cyberrescue.core.models import ActorKind, EvidenceRelation
from cyberrescue.core.service import CitationError, CoreError, CoreService
from cyberrescue.detection.model import DetectionReport

CLAIM_KIND = "detection"
DETECTOR_ROLE = "detector"
AUDIT_SOURCE = "detection"


@dataclass(frozen=True)
class PersistedDetection:
    finding_id: str
    detection_id: str
    detection_key: str
    rule_id: str
    payload: dict


@dataclass
class PublishReport:
    incident_id: str
    created: list[tuple[str, str]] = field(default_factory=list)      # (detection, finding)
    skipped: list[str] = field(default_factory=list)                  # already recorded
    superseded: list[tuple[str, str]] = field(default_factory=list)   # (detection, old finding)


def detection_findings(svc: CoreService, incident_ref: str) -> list[PersistedDetection]:
    """Findings recorded by the publisher for an incident, oldest first."""
    iid = _incident(svc, incident_ref)
    out = []
    for f in svc.store.findings(iid):
        for c in svc.store.claims_for(f.id):
            if c.kind != CLAIM_KIND:
                continue
            try:
                payload = json.loads(c.content)
            except ValueError:
                continue
            out.append(PersistedDetection(
                finding_id=f.id, detection_id=str(payload.get("detection_id")),
                detection_key=str(payload.get("detection_key")),
                rule_id=str(payload.get("rule_id")), payload=payload))
    return out


def persist(svc: CoreService, incident_ref: str, report: DetectionReport, *,
            detector_id: str) -> PublishReport:
    iid = _incident(svc, incident_ref)
    if report.incident_id != iid:
        raise CoreError(f"report is for {report.incident_id}, not {iid}")
    detector = svc.store.get_actor(detector_id)
    if detector is None or detector.kind != ActorKind.SYSTEM or detector.role != DETECTOR_ROLE:
        raise CitationError("only a registered SYSTEM actor with role 'detector' may publish "
                            "detections")
    existing = detection_findings(svc, iid)
    recorded = {p.detection_id for p in existing}
    latest_by_key = {p.detection_key: p.finding_id for p in existing}
    out = PublishReport(incident_id=iid)
    with db.transaction(svc.conn):
        for det in report.detections:
            if det.detection_id in recorded:
                out.skipped.append(det.detection_id)
                continue
            prior = latest_by_key.get(det.detection_key)
            payload = det.model_dump(mode="json") | {"supersedes": prior}
            f = svc.record_finding(
                iid, detector, det.summary, severity=det.severity,
                claims=[canonical_json(payload)], claim_kind=CLAIM_KIND,
                evidence_ids=list(det.supporting_evidence_ids),
                evidence_relation=EvidenceRelation.SUPPORTS, source=AUDIT_SOURCE)
            for cid in det.context_evidence_ids:
                svc.link_evidence(f.id, cid, linked_by=detector.id,
                                  relation=EvidenceRelation.CONTEXT, source=AUDIT_SOURCE)
            out.created.append((det.detection_id, f.id))
            if prior:
                out.superseded.append((det.detection_id, prior))
            recorded.add(det.detection_id)
            latest_by_key[det.detection_key] = f.id
    return out


def _incident(svc: CoreService, ref: str) -> str:
    iid = svc.store.resolve_incident(ref)
    if iid is None:
        raise CoreError(f"no Core incident for {ref!r}")
    return iid

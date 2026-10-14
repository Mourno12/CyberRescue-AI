"""Build and verify an investigation Case - read-only and deterministic.

``build_case`` assembles every component for one incident from a
``ReadOnlyCore``. Nothing depends on the wall clock: ``as_of`` is the timestamp
of the case's audit ANCHOR, ids are content-derived, and the case's
``case_sha256`` is the sha256 of its canonical content. ``verify_case``
recomputes that hash (detects an edited export) and rebuilds the case from the
database (detects a changed database).

The audit anchor (Phase 6 boundary). A case is anchored at the incident
chain's last event that is not a trailing post-plan ACCOUNTABILITY event
(``ACTION_EXECUTED`` / ``ACTION_VERIFIED``, see ``case_anchor``): ``as_of``,
``integrity.audit_head_hash`` and ``integrity.audit_events`` (the anchor's
sequence number) come from it. The chain is hash-linked, so the anchor hash
commits to every event before it. ``integrity.audit_chain_ok`` still verifies
the ENTIRE chain, accountability events included, so tampering anywhere
changes the case and fails ``verify_case``. Recording a simulated execution
after a case was built therefore leaves its identity unchanged; any other
audited event (an approval, a request, evidence) moves the anchor as before.
For chains without trailing accountability events every value is identical
to the pre-Phase-6 definition.

Raw evidence lines are excluded unless ``include_raw`` (then only for evidence
the case cites, as ``Untrusted``).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from cyberrescue.core.audit import canonical_json
from cyberrescue.core.models import ACCOUNTABILITY_EVENT_TYPES
from cyberrescue.detection.engine import DetectionEngine, load_view
from cyberrescue.detection.model import digest
from cyberrescue.investigation.claims import reconcile_claims
from cyberrescue.investigation.findings import citations_by_evidence, collect_findings
from cyberrescue.investigation.gaps import derive_gaps
from cyberrescue.investigation.graph import build_graph
from cyberrescue.investigation.model import (
    Case,
    DetectionView,
    FindingView,
    ObservationView,
    RawLine,
    untrusted,
)
from cyberrescue.investigation.policy_view import build_policy_view
from cyberrescue.investigation.provenance import integrity_by_evidence, provenance_records
from cyberrescue.investigation.readonly import ReadOnlyCore
from cyberrescue.investigation.scope import derive_scope
from cyberrescue.investigation.timeline import build_timeline


def _sha(case: Case) -> str:
    return hashlib.sha256(canonical_json(case.content()).encode()).hexdigest()


def case_anchor(events):
    """The last event that is not a TRAILING accountability event (None if none).
    Accountability events followed by any other event are part of the anchored
    prefix like every other event."""
    return next((e for e in reversed(events)
                 if e.event_type not in ACCOUNTABILITY_EVENT_TYPES), None)


def build_case(core: ReadOnlyCore, incident_ref: str, *, include_raw: bool = False) -> Case:
    iid = core.resolve(incident_ref)
    inc = core.store.get_incident(iid)
    view = load_view(core, iid)
    report = DetectionEngine().run(view)
    records = collect_findings(core, iid)
    cites = citations_by_evidence(records)
    persisted = {r.detection_id: r.finding.id for r in records if r.detection_id}

    findings = tuple(FindingView(
        finding_id=r.finding.id, origin=r.origin,
        author_role=r.author.role if r.author else "unknown", rule_id=r.rule_id,
        detection_id=r.detection_id, severity=r.finding.severity,
        summary=untrusted(r.finding.summary),
        supporting=sum(1 for _, rel in r.links if rel == "supports"),
        context=sum(1 for _, rel in r.links if rel == "context")) for r in records)
    detections = tuple(DetectionView(
        detection_id=d.detection_id, rule_id=d.rule_id, finding_type=d.finding_type,
        severity=d.severity, confidence=d.confidence, primary_host=d.primary_host,
        window_start=d.window.start, window_end=d.window.end,
        supporting=len(d.supporting_evidence_ids), context=len(d.context_evidence_ids),
        persisted_finding_id=persisted.get(d.detection_id)) for d in report.detections)
    observations = tuple(ObservationView(
        observation_id=o.observation_id, rule_id=o.rule_id, kind=o.kind,
        primary_host=o.primary_host, reason=untrusted(o.reason), evidence_ids=o.evidence_ids)
        for o in report.observations)

    scope = derive_scope(view, report, core.store.active_holds())
    claims = reconcile_claims(core, iid, records)
    gaps = derive_gaps(view, report, scope, claims)
    cited = view.ordered({i for r in records for i, _ in r.links}
                         | {i for d in report.detections
                            for i in (*d.supporting_evidence_ids, *d.context_evidence_ids)}
                         | {i for g in gaps for i in g.evidence_ids})
    integrity_errors = integrity_by_evidence(core, iid)
    audit = core.audit.verify(iid)
    events = core.audit.events(iid)
    anchor = case_anchor(events)
    evidence_check = core.evidence.verify(iid)
    raw = ()
    if include_raw:
        raw = tuple(RawLine(evidence_id=i, raw=untrusted(core.get_evidence(i).raw))
                    for i in cited)

    case = Case(
        case_id="CASE-" + digest(iid, view.fingerprint, *sorted(f.finding_id for f in findings),
                                 report.ruleset_version)[:16],
        incident_id=iid, aliases=tuple(core.store.aliases_of(iid)), title=untrusted(inc.title),
        as_of=anchor.ts if anchor else inc.created_at,
        ruleset_version=report.ruleset_version, evidence_count=len(view.events),
        policy=build_policy_view(core, iid), findings=findings, detections=detections,
        observations=observations,
        timeline=build_timeline(view, citations=cites, report=report),
        graph=build_graph(view), scope=scope, gaps=tuple(gaps), claims=tuple(claims),
        provenance=tuple(provenance_records(core, cited, citations=cites,
                                            integrity=integrity_errors)),
        integrity={"audit_chain_ok": audit.ok,                    # the WHOLE chain
                   "audit_events": anchor.seq if anchor else 0,     # anchored prefix
                   "audit_head_hash": anchor.hash if anchor else None,
                   "evidence_ok": evidence_check.ok, "evidence_checked": evidence_check.checked,
                   "evidence_errors": list(evidence_check.errors),
                   "threat_intel_sha256": report.inputs["threat_intel_sha256"],
                   "options": {"include_raw": include_raw}},
        raw_evidence=raw)
    return case.model_copy(update={"case_sha256": _sha(case)})


@dataclass
class CaseVerifyResult:
    ok: bool
    errors: list[str] = field(default_factory=list)


def verify_case(core: ReadOnlyCore, case_json: str) -> CaseVerifyResult:
    errors: list[str] = []
    try:
        case = Case.model_validate(json.loads(case_json))
    except ValueError as e:
        return CaseVerifyResult(False, [f"not a valid case document: {str(e)[:200]}"])
    if _sha(case) != case.case_sha256:
        errors.append("case_sha256 does not match the document content (edited export)")
    include_raw = bool(case.integrity.get("options", {}).get("include_raw"))
    fresh = build_case(core, case.incident_id, include_raw=include_raw)
    if fresh.case_sha256 != case.case_sha256:
        errors.append("the database no longer produces this case (evidence, findings, "
                      "policy state or rules changed since export)")
    if not (fresh.integrity["audit_chain_ok"] and fresh.integrity["evidence_ok"]):
        errors.append("the database fails audit/evidence verification")
    return CaseVerifyResult(not errors, errors)

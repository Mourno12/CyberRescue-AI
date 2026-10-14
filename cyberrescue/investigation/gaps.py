"""Forensic gaps: deterministic open questions the evidence cannot answer.

A gap reports the ABSENCE OF OBSERVED EVIDENCE, not the absence of activity.

    G1  authenticated access with no observed activity by that account on the
        target afterwards ("execution after access is unverified")
    G2  contact with an indicator whose outcome is not observed
    G3  vendor alert not corroborated by any detection
    G4  host in scope with no endpoint (process/file) telemetry at all
    G5  partial chain (an Observation of kind partial_match)
    G6  agent finding whose claims are not (fully) backed by evidence citations

Descriptions are fixed templates; only safe identifiers are interpolated.
"""

from __future__ import annotations

from collections.abc import Iterable

from cyberrescue.detection.context import EvidenceView
from cyberrescue.detection.matchers import safe_token
from cyberrescue.detection.model import DetectionReport, digest
from cyberrescue.investigation.model import ClaimReconciliation, Gap, Scope

ENDPOINT_KINDS = frozenset({"process", "file", "other"})
ACTIVITY_TYPES = frozenset({"process_start", "network_connect", "registry_set", "7045"})


def _gap(code: str, title: str, description: str, *, host: str | None = None,
         evidence_ids: Iterable[str] = (), refs: Iterable[str] = ()) -> Gap:
    ev = tuple(evidence_ids)
    rf = tuple(sorted(set(refs)))
    return Gap(gap_id="GAP-" + digest(code, host or "", *ev, *rf)[:12], code=code, title=title,
               description=description, host=host, evidence_ids=ev, refs=rf)


def _activity_after(view: EvidenceView, host: str, account: str, after) -> list[str]:
    return [e.id for e in view.events
            if e.host == host and e.at > after and (e.user or "").lower() == account
            and (e.kind in ENDPOINT_KINDS or e.event_type in ACTIVITY_TYPES)]


def derive_gaps(view: EvidenceView, report: DetectionReport, scope: Scope,
                claims: Iterable[ClaimReconciliation] = ()) -> list[Gap]:
    gaps: list[Gap] = []
    # G1 - successful remote logons into accessed hosts (one gap per logon, listing
    # every detection that cites it).
    logons: dict[str, set[str]] = {}
    for d in report.detections:
        if d.rule_id in ("LAT-001", "AUTH-001"):
            for eid in d.supporting_evidence_ids:
                if view.get(eid).event_type == "4624":
                    logons.setdefault(eid, set()).add(d.detection_id)
    for eid in view.ordered(logons):
        e = view.get(eid)
        account = (e.user or "").lower()
        if e.host not in scope.accessed_hosts or not account or \
                _activity_after(view, e.host, account, e.at):
            continue
        gaps.append(_gap(
            "G1", "Activity after authenticated access is unverified",
            f"{safe_token(account)} authenticated successfully to {safe_token(e.host)} at "
            f"{e.observed_at}; no endpoint activity by this account on that host is "
            "observed afterwards. Whether code ran there cannot be determined from the "
            "evidence.", host=e.host, evidence_ids=[eid], refs=logons[eid]))
    # G2 - indicator contact without an observed outcome.
    for d in report.detections:
        if d.rule_id == "IOC-002" and d.entities.get("outcome") == "attempted":
            gaps.append(_gap(
                "G2", "Outcome of contact with a known-malicious indicator is unknown",
                f"{safe_token(d.primary_host)} contacted {safe_token(d.entities['indicator'])}; "
                "no established connection or block is observed.",
                host=d.primary_host, evidence_ids=d.supporting_evidence_ids,
                refs=[d.detection_id]))
    for o in report.observations:
        # G3 - uncorroborated vendor alerts.
        if o.kind == "uncorroborated_alert":
            gaps.append(_gap(
                "G3", "Vendor alert not corroborated",
                f"A vendor alert on {safe_token(o.primary_host)} is not supported by any "
                "detection; it is a sensor's opinion and needs analyst review.",
                host=o.primary_host, evidence_ids=o.evidence_ids, refs=[o.observation_id]))
        # G5 - partial chains.
        elif o.kind == "partial_match":
            gaps.append(_gap(
                "G5", f"Partial {o.rule_id} chain",
                f"{o.rule_id} matched only partially on {safe_token(o.primary_host)}; the "
                "remaining conditions are not observed (see the observation's reason).",
                host=o.primary_host, evidence_ids=o.evidence_ids, refs=[o.observation_id]))
    # G4 - in-scope hosts without endpoint telemetry.
    endpoint_hosts = {e.host for e in view.events if e.kind in ENDPOINT_KINDS}
    for host in sorted({*scope.compromised_hosts, *scope.accessed_hosts,
                        *scope.targeted_hosts} - endpoint_hosts):
        seen = [e.id for e in view.events if e.host == host]
        gaps.append(_gap(
            "G4", "No endpoint telemetry from an in-scope host",
            f"{safe_token(host)} is in scope but has no process/file telemetry in the "
            f"evidence ({len(seen)} other record(s)); activity on it cannot be assessed.",
            host=host, evidence_ids=seen[:20]))
    # G6 - agent findings not backed by evidence.
    for c in claims:
        if c.status != "evidence-backed":
            gaps.append(_gap(
                "G6", "Agent statement not backed by evidence",
                f"Finding {c.finding_id} by {safe_token(c.author_role)} is {c.status}: "
                f"{c.supporting} supporting citation(s), {c.rejected_citations} rejected "
                "citation(s).", refs=[c.finding_id]))
    return sorted(gaps, key=lambda g: (g.code, g.host or "", g.gap_id))

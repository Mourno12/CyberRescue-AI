"""Reconcile non-detector findings (WarRoom agents, humans) with evidence.

This measures CITATION COVERAGE only - whether a finding's statements are tied
to evidence ids - not whether the statements are true (that would need
semantic analysis, out of scope for a deterministic layer).

    evidence-backed   >= 1 valid supporting citation and no rejected citations
    partially backed  >= 1 valid supporting citation and >= 1 rejected citation
    unsupported       no valid supporting citation
"""

from __future__ import annotations

from cyberrescue.core.models import EventType
from cyberrescue.investigation.findings import FindingRecord
from cyberrescue.investigation.model import ClaimReconciliation, untrusted
from cyberrescue.investigation.readonly import ReadOnlyCore


def rejected_citations(core: ReadOnlyCore, incident_id: str) -> dict[str, int]:
    """actor id -> number of CLAIM_REJECTED evidence-citation events."""
    counts: dict[str, int] = {}
    for ev in core.audit.events(incident_id, event_type=EventType.CLAIM_REJECTED):
        if ev.payload.get("claim") == "EVIDENCE_CITATION" and ev.actor_id:
            counts[ev.actor_id] = counts.get(ev.actor_id, 0) + 1
    return counts


def reconcile_claims(core: ReadOnlyCore, incident_id: str,
                     records: list[FindingRecord]) -> list[ClaimReconciliation]:
    rejected = rejected_citations(core, incident_id)
    out = []
    for r in records:
        if r.origin not in ("agent", "human"):
            continue
        rels = [rel for _, rel in r.links]
        sup = rels.count("supports")
        rej = rejected.get(r.finding.author_actor_id or "", 0)
        status = ("unsupported" if sup == 0 else
                  "partially backed" if rej else "evidence-backed")
        out.append(ClaimReconciliation(
            finding_id=r.finding.id, author_kind=r.author.kind.value if r.author else "unknown",
            author_role=r.author.role if r.author else "unknown",
            summary=untrusted(r.finding.summary),
            claims=tuple(untrusted(c.content) for c in r.claims),
            supporting=sup, context=rels.count("context"),
            contradicting=rels.count("contradicts"), rejected_citations=rej, status=status))
    return out

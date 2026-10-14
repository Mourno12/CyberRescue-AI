"""Collect an incident's persisted findings, their authors, citations and claims."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass

from cyberrescue.core.models import Actor, ActorKind, Finding, FindingClaim
from cyberrescue.detection.publisher import CLAIM_KIND, DETECTOR_ROLE
from cyberrescue.investigation.model import Citation
from cyberrescue.investigation.readonly import ReadOnlyCore


@dataclass(frozen=True)
class FindingRecord:
    finding: Finding
    author: Actor | None
    origin: str                       # detection | agent | human | system
    rule_id: str | None
    detection_id: str | None
    links: tuple[tuple[str, str], ...]        # (evidence_id, relation)
    claims: tuple[FindingClaim, ...]


def origin_of(author: Actor | None) -> str:
    if author is None:
        return "system"
    if author.kind == ActorKind.SYSTEM:
        return "detection" if author.role == DETECTOR_ROLE else "system"
    return "agent" if author.kind == ActorKind.AGENT else "human"


def collect_findings(core: ReadOnlyCore, incident_id: str) -> list[FindingRecord]:
    out = []
    for f in sorted(core.store.findings(incident_id), key=lambda f: (f.created_at, f.id)):
        author = core.store.get_actor(f.author_actor_id) if f.author_actor_id else None
        claims = tuple(core.store.claims_for(f.id))
        rule_id = detection_id = None
        origin = origin_of(author)
        if origin == "detection":
            for c in claims:
                if c.kind == CLAIM_KIND:
                    try:
                        payload = json.loads(c.content)
                    except ValueError:
                        continue
                    rule_id, detection_id = payload.get("rule_id"), payload.get("detection_id")
        links = tuple((rec.id, rel) for rec, rel in core.evidence.evidence_for_finding(f.id))
        out.append(FindingRecord(finding=f, author=author, origin=origin, rule_id=rule_id,
                                 detection_id=detection_id, links=links, claims=claims))
    return out


def citations_by_evidence(records: list[FindingRecord]) -> dict[str, list[Citation]]:
    cites: dict[str, list[Citation]] = defaultdict(list)
    for r in records:
        for evidence_id, relation in r.links:
            cites[evidence_id].append(Citation(finding_id=r.finding.id, origin=r.origin,
                                               rule_id=r.rule_id, relation=relation))
    return {k: sorted(v, key=lambda c: (c.finding_id, c.relation)) for k, v in cites.items()}

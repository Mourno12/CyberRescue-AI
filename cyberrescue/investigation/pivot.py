"""Pivots: evidence related to a piece of evidence, and an entity's activity.

Relatedness is explainable: two records are related when they share entity
keys (host, account, process, ip, domain, hash) within a time window. Results
are ranked by (more shared entities, closer in time, evidence id).
"""

from __future__ import annotations

from collections.abc import Iterable

from cyberrescue.detection.context import Ev, EvidenceView
from cyberrescue.detection.matchers import url_host
from cyberrescue.investigation.graph import (
    account_key,
    addr_key,
    domain_key,
    hash_key,
    host_key,
    process_key,
)
from cyberrescue.investigation.model import Related

ENTITY_TYPES = ("host", "account", "process", "ip", "domain", "hash")


def entities_of(view: EvidenceView, e: Ev) -> set[str]:
    """Entity keys of one record; an address resolvable to a host counts as that host."""
    keys = {host_key(e.host), account_key(e.user), process_key(e.host, e.s("process.name")),
            addr_key(view, e.s("source.ip")), addr_key(view, e.s("destination.ip")),
            domain_key(e.s("dns.question.name")), domain_key(url_host(e.s("url.original"))),
            hash_key(e.s("process.hash.sha256"))}
    keys |= {addr_key(view, a) for a in e.strings("dns.answers")}
    return {k for k in keys if k}


def related_evidence(view: EvidenceView, evidence_id: str, *,
                     by: Iterable[str] | None = None,
                     window_seconds: int = 900, limit: int = 50) -> list[Related]:
    try:
        pivot = view.get(evidence_id)
    except KeyError:
        raise ValueError(f"evidence {evidence_id!r} is not part of this incident") from None
    types = set(by or ENTITY_TYPES)
    unknown = types - set(ENTITY_TYPES)
    if unknown:
        raise ValueError(f"unknown entity types {sorted(unknown)}; use {ENTITY_TYPES}")
    mine = {k for k in entities_of(view, pivot) if k.split(":", 1)[0] in types}
    out = []
    for e in view.events:
        if e.id == pivot.id:
            continue
        apart = int(abs((e.at - pivot.at).total_seconds()))
        shared = mine & entities_of(view, e)
        if apart <= window_seconds and shared:
            out.append(Related(evidence_id=e.id, shared=tuple(sorted(shared)),
                               seconds_apart=apart))
    out.sort(key=lambda r: (-len(r.shared), r.seconds_apart, r.evidence_id))
    return out[:limit]


def entity_activity(view: EvidenceView, entity: str) -> list[str]:
    """Evidence ids (chronological) whose entities include ``entity``."""
    return [e.id for e in view.events if entity in entities_of(view, e)]

"""Evidence provenance: where each record came from, who ingested it, and
whether it is still intact (both hashes recomputed and cross-checked against
the EVIDENCE_INGESTED audit event by the Phase 2A verifier)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from cyberrescue.investigation.model import Citation, ProvenanceRecord, untrusted
from cyberrescue.investigation.readonly import ReadOnlyCore, ReadOnlyError


def integrity_by_evidence(core: ReadOnlyCore, incident_id: str) -> dict[str, list[str]]:
    """evidence id -> integrity errors (from the Phase 2A verifier)."""
    errors: dict[str, list[str]] = {}
    for line in core.evidence.verify(incident_id).errors:
        eid, _, msg = line.partition(": ")
        errors.setdefault(eid, []).append(msg or line)
    return errors


def provenance_records(core: ReadOnlyCore, evidence_ids: Iterable[str], *,
                       citations: Mapping[str, Sequence[Citation]] | None = None,
                       integrity: Mapping[str, list[str]] | None = None
                       ) -> list[ProvenanceRecord]:
    citations = citations or {}
    out = []
    for eid in evidence_ids:
        rec = core.get_evidence(eid)
        if rec is None:
            raise ReadOnlyError(f"unknown evidence id {eid!r}")
        errs = (integrity if integrity is not None
                else integrity_by_evidence(core, rec.incident_id)).get(eid, [])
        actor = core.store.get_actor(rec.ingested_by)
        out.append(ProvenanceRecord(
            evidence_id=rec.id, incident_id=rec.incident_id, source=rec.source,
            source_ref=rec.source_ref, kind=rec.kind.value, event_type=rec.event_type,
            observed_at=rec.observed_at, ingested_at=rec.ingested_at,
            provenance=rec.provenance.value,
            sensor=untrusted(rec.metadata.get("sensor")),
            vendor=untrusted(rec.metadata.get("vendor")),
            adapter=untrusted(rec.metadata.get("adapter")),
            ingested_by={"id": rec.ingested_by,
                         "kind": actor.kind.value if actor else "unknown",
                         "role": actor.role if actor else "unknown"},
            content_sha256=rec.content_sha256, record_sha256=rec.record_sha256,
            audit_event_uid=rec.event_uid, integrity_ok=not errs,
            integrity_errors=tuple(errs), cited_by=tuple(citations.get(eid, ()))))
    return out

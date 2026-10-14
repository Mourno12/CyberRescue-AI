"""Persistence for evidence and finding->evidence citations.

Invariants:
  * Evidence rows are written once, together with their EVIDENCE_INGESTED
    audit event (same transaction), and never updated or deleted (DB triggers).
  * The audit event records both hashes, so ``verify()`` cross-checks each row
    against the hash-chained audit log: an attacker must defeat the row hashes,
    the audit payload AND the audit chain to alter evidence undetected.
  * Citations (``finding_evidence``) are append-only and never cross incidents
    (checked here and by a DB trigger).

Nothing here authorizes anything. This module must not touch approvals,
actors, incident state, or the protocol parser (a test enforces it).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from cyberrescue.core.audit import AuditLog
from cyberrescue.core.db import transaction
from cyberrescue.core.evidence import SEALED_FIELDS, integrity_errors
from cyberrescue.core.models import (
    EventType,
    EvidenceKind,
    EvidenceRecord,
    EvidenceRelation,
    Finding,
    FindingEvidence,
    LinkRelation,
    Provenance,
)


@dataclass
class EvidenceVerifyResult:
    ok: bool
    checked: int
    errors: list[str] = field(default_factory=list)


class EvidenceStore:
    def __init__(self, conn: sqlite3.Connection, audit: AuditLog) -> None:
        self.conn = conn
        self.audit = audit

    # --- row mapping ---------------------------------------------------------
    @staticmethod
    def _fields(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        d = dict(row)
        d["user"] = d.pop("user_name")
        d["data"] = json.loads(d["data"])
        d["metadata"] = json.loads(d["metadata"])
        return d

    @classmethod
    def _record(cls, row: sqlite3.Row) -> EvidenceRecord:
        d = cls._fields(row)
        return EvidenceRecord(**{**d, "kind": EvidenceKind(d["kind"]),
                                 "provenance": Provenance(d["provenance"])})

    # --- write ---------------------------------------------------------------
    def add(self, fields: dict[str, Any], *, source: str = "collector") -> tuple[EvidenceRecord, bool]:
        """Insert prepared evidence (``evidence.prepare_record``).

        Returns ``(record, duplicate)``. A record with the same content-derived
        id already stored is returned unchanged with ``duplicate=True``;
        nothing new is written.
        """
        existing = self.get(fields["id"])
        if existing is not None:
            return existing, True
        with transaction(self.conn):
            ev = self.audit.append(
                EventType.EVIDENCE_INGESTED, incident_id=fields["incident_id"],
                actor_id=fields["ingested_by"], source=source,
                payload={"evidence_id": fields["id"], "source": fields["source"],
                         "source_ref": fields["source_ref"], "kind": fields["kind"],
                         "event_type": fields["event_type"],
                         "observed_at": fields["observed_at"], "host": fields["host"],
                         "asset_id": fields["asset_id"], "user": fields["user"],
                         "provenance": fields["provenance"],
                         "content_sha256": fields["content_sha256"],
                         "record_sha256": fields["record_sha256"],
                         "raw_bytes": len(fields["raw"].encode("utf-8"))})
            self.conn.execute(
                "INSERT INTO evidence(id, incident_id, source, source_ref, kind, event_type, "
                "observed_at, ingested_at, host, asset_id, user_name, raw, data, metadata, "
                "provenance, content_sha256, record_sha256, ingested_by, event_uid) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (fields["id"], fields["incident_id"], fields["source"], fields["source_ref"],
                 fields["kind"], fields["event_type"], fields["observed_at"],
                 fields["ingested_at"], fields["host"], fields["asset_id"], fields["user"],
                 fields["raw"], json.dumps(fields["data"]), json.dumps(fields["metadata"]),
                 fields["provenance"], fields["content_sha256"], fields["record_sha256"],
                 fields["ingested_by"], ev.uid))
        return self.get(fields["id"]), False  # type: ignore[return-value]

    # --- read ----------------------------------------------------------------
    def get(self, evidence_id: str) -> EvidenceRecord | None:
        row = self.conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        return self._record(row) if row else None

    def list(self, incident_id: str, *, kind: str | None = None, host: str | None = None,
             since: str | None = None, until: str | None = None) -> list[EvidenceRecord]:
        """Evidence of one incident in observation order (``since``/``until``
        are inclusive UTC ISO timestamps, compared on the normalised form)."""
        sql, args = "SELECT * FROM evidence WHERE incident_id = ?", [incident_id]
        for clause, value in (("kind = ?", kind), ("host = ?", host),
                              ("observed_at >= ?", since), ("observed_at <= ?", until)):
            if value is not None:
                sql += f" AND {clause}"
                args.append(value)
        rows = self.conn.execute(sql + " ORDER BY observed_at, id", args).fetchall()
        return [self._record(r) for r in rows]

    # --- verify ---------------------------------------------------------------
    def verify(self, incident_id: str) -> EvidenceVerifyResult:
        """Recompute both hashes of every record and cross-check them against
        the EVIDENCE_INGESTED audit events; also detect events whose record is
        missing."""
        rows = self.conn.execute("SELECT * FROM evidence WHERE incident_id = ? ORDER BY id",
                                 (incident_id,)).fetchall()
        errors: list[str] = []
        seen: set[str] = set()
        for row in rows:
            f = self._fields(row)
            seen.add(f["id"])
            errors += [f"{f['id']}: {e}" for e in integrity_errors(
                {k: f[k] for k in (*SEALED_FIELDS, "record_sha256")})]
            ev = self.audit.get(f["event_uid"])
            if ev is None or ev.event_type != EventType.EVIDENCE_INGESTED.value:
                errors.append(f"{f['id']}: no EVIDENCE_INGESTED audit event")
                continue
            p = ev.payload
            if ev.incident_id != f["incident_id"] or p.get("evidence_id") != f["id"]:
                errors.append(f"{f['id']}: audit event is bound to a different record")
            for h in ("content_sha256", "record_sha256"):
                if p.get(h) != f[h]:
                    errors.append(f"{f['id']}: {h} differs from the audit record")
        for ev in self.audit.events(incident_id, event_type=EventType.EVIDENCE_INGESTED):
            if ev.payload.get("evidence_id") not in seen:
                errors.append(f"{ev.payload.get('evidence_id')}: audit records ingestion but "
                              "the evidence record is missing")
        return EvidenceVerifyResult(ok=not errors, checked=len(rows), errors=errors)

    # --- citations -------------------------------------------------------------
    def link(self, finding: Finding, evidence: EvidenceRecord, *,
             relation: EvidenceRelation, linked_by: str,
             source: str = "core") -> tuple[FindingEvidence, bool]:
        """Record that ``finding`` cites ``evidence``. Same incident only.
        Returns ``(link, duplicate)``; an existing link is returned unchanged."""
        if finding.incident_id != evidence.incident_id:
            raise ValueError(f"finding {finding.id} ({finding.incident_id}) cannot cite "
                             f"{evidence.id} ({evidence.incident_id}): different incidents")
        row = self.conn.execute(
            "SELECT * FROM finding_evidence WHERE finding_id = ? AND evidence_id = ?",
            (finding.id, evidence.id)).fetchone()
        if row:
            return FindingEvidence(**dict(row)), True
        relation = EvidenceRelation(relation)
        with transaction(self.conn):
            ev = self.audit.append(
                EventType.FINDING_EVIDENCE_LINKED, incident_id=finding.incident_id,
                actor_id=linked_by, source=source,
                payload={"finding_id": finding.id, "evidence_id": evidence.id,
                         "relation": relation.value,
                         "content_sha256": evidence.content_sha256},
                links=[(LinkRelation.CITES, evidence.event_uid),
                       (LinkRelation.CONCERNS, finding.event_uid)])
            self.conn.execute(
                "INSERT INTO finding_evidence(finding_id, evidence_id, relation, linked_by, "
                "event_uid, created_at) VALUES (?,?,?,?,?,?)",
                (finding.id, evidence.id, relation.value, linked_by, ev.uid, ev.ts))
        return FindingEvidence(finding_id=finding.id, evidence_id=evidence.id,
                               relation=relation, linked_by=linked_by, event_uid=ev.uid,
                               created_at=ev.ts), False

    def evidence_for_finding(self, finding_id: str) -> list[tuple[EvidenceRecord, str]]:
        rows = self.conn.execute(
            "SELECT e.*, fe.relation AS _relation FROM finding_evidence fe "
            "JOIN evidence e ON e.id = fe.evidence_id WHERE fe.finding_id = ? "
            "ORDER BY e.observed_at, e.id", (finding_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            relation = d.pop("_relation")
            out.append((self._record(d), relation))
        return out

    def findings_citing(self, evidence_id: str) -> list[tuple[str, str]]:
        """(finding_id, relation) pairs for every finding citing ``evidence_id``."""
        return [(r["finding_id"], r["relation"]) for r in self.conn.execute(
            "SELECT finding_id, relation FROM finding_evidence WHERE evidence_id = ? "
            "ORDER BY created_at", (evidence_id,))]

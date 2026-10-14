"""Append-only, hash-chained audit log.

Every Core write produces an ``AuditEvent``. Events form one hash chain per
incident (``chain = incident_id``; incident-less events use ``__system__``):

    hash = sha256( prev_hash || canonical_json(event body incl. links) )

``verify()`` recomputes the chain and reports sequence gaps (deleted rows),
broken back-pointers, edited bodies, and edited links. SQLite triggers
(``db.py``) additionally make UPDATE/DELETE on the log fail outright.

On its own this is tamper-*evident*, not tamper-*proof*: someone with raw
write access to the file could drop the triggers and recompute every hash, and
truncating the *tail* of a chain leaves no trace in the chain itself. Phase 7
closes both gaps WITHOUT changing this hash formula: ``core/anchor.py`` writes
external checkpoints of every chain head, signed with HMAC-SHA256 under a key
kept outside the database and the repository, and ``core verify --anchor``
detects any rewrite or truncation of the anchored prefix (see
``docs/cyberrescue/phase7-audit-anchoring.md``).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cyberrescue.core.db import transaction
from cyberrescue.core.models import AuditEvent, EventLink, EventType, LinkRelation

GENESIS_HASH = "0" * 64
SYSTEM_CHAIN = "__system__"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8 preserved."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def compute_hash(prev_hash: str, body: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(body)).encode("utf-8")).hexdigest()


def _body(ev: dict[str, Any], links: list[tuple[str, str]]) -> dict[str, Any]:
    """The hashed portion of an event (everything except ``hash``)."""
    return {
        "uid": ev["uid"], "chain": ev["chain"], "incident_id": ev["incident_id"],
        "seq": ev["seq"], "ts": ev["ts"], "event_type": ev["event_type"],
        "actor_id": ev["actor_id"], "source": ev["source"],
        "external_id": ev["external_id"], "protocol_type": ev["protocol_type"],
        "protocol_valid": ev["protocol_valid"], "payload": ev["payload"],
        "links": sorted([list(link) for link in links]),
        "prev_hash": ev["prev_hash"],
    }


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    errors: list[str] = field(default_factory=list)


LinkSpec = tuple[LinkRelation | str, str]


class AuditLog:
    """Writes and verifies audit events on one SQLite connection."""

    def __init__(self, conn: sqlite3.Connection,
                 clock: Callable[[], datetime] = utcnow) -> None:
        self.conn = conn
        self.clock = clock

    # --- write ------------------------------------------------------------
    def append(self, event_type: EventType | str, *, incident_id: str | None = None,
               actor_id: str | None = None, source: str = "core",
               payload: dict[str, Any] | None = None, external_id: str | None = None,
               protocol_type: str | None = None, protocol_valid: bool | None = None,
               links: Iterable[LinkSpec] = ()) -> AuditEvent:
        """Append one event (and its links) atomically; returns it hashed."""
        etype = event_type.value if isinstance(event_type, EventType) else str(event_type)
        chain = incident_id or SYSTEM_CHAIN
        link_pairs = [
            (rel.value if isinstance(rel, LinkRelation) else str(rel), target)
            for rel, target in links
        ]
        with transaction(self.conn):
            last = self.conn.execute(
                "SELECT seq, hash FROM audit_events WHERE chain = ? "
                "ORDER BY seq DESC LIMIT 1", (chain,)).fetchone()
            ev = {
                "uid": uuid.uuid4().hex,
                "chain": chain,
                "incident_id": incident_id,
                "seq": (last["seq"] + 1) if last else 1,
                "ts": self.clock().isoformat(),
                "event_type": etype,
                "actor_id": actor_id,
                "source": source,
                "external_id": external_id,
                "protocol_type": protocol_type,
                "protocol_valid": None if protocol_valid is None else bool(protocol_valid),
                "payload": payload or {},
                "prev_hash": last["hash"] if last else GENESIS_HASH,
            }
            ev["hash"] = compute_hash(ev["prev_hash"], _body(ev, link_pairs))
            self.conn.execute(
                "INSERT INTO audit_events(uid, chain, incident_id, seq, ts, event_type, "
                "actor_id, source, external_id, protocol_type, protocol_valid, payload, "
                "prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ev["uid"], chain, incident_id, ev["seq"], ev["ts"], etype, actor_id,
                 source, external_id, protocol_type,
                 None if ev["protocol_valid"] is None else int(ev["protocol_valid"]),
                 canonical_json(ev["payload"]), ev["prev_hash"], ev["hash"]))
            for rel, target in link_pairs:
                self.conn.execute(
                    "INSERT INTO event_links(from_uid, to_uid, relation) VALUES (?,?,?)",
                    (ev["uid"], target, rel))
        return AuditEvent(**{**ev, "links": [EventLink(relation=r, target_uid=t)
                                             for r, t in link_pairs]})

    # --- read -------------------------------------------------------------
    def _links_of(self, uid: str) -> list[tuple[str, str]]:
        return [(r["relation"], r["to_uid"]) for r in self.conn.execute(
            "SELECT relation, to_uid FROM event_links WHERE from_uid = ?", (uid,))]

    def _row_to_event(self, row: sqlite3.Row) -> AuditEvent:
        pv = row["protocol_valid"]
        return AuditEvent(
            uid=row["uid"], chain=row["chain"], incident_id=row["incident_id"],
            seq=row["seq"], ts=row["ts"], event_type=row["event_type"],
            actor_id=row["actor_id"], source=row["source"],
            external_id=row["external_id"], protocol_type=row["protocol_type"],
            protocol_valid=None if pv is None else bool(pv),
            payload=json.loads(row["payload"]),
            links=[EventLink(relation=r, target_uid=t) for r, t in self._links_of(row["uid"])],
            prev_hash=row["prev_hash"], hash=row["hash"])

    def get(self, uid: str) -> AuditEvent | None:
        row = self.conn.execute("SELECT * FROM audit_events WHERE uid = ?", (uid,)).fetchone()
        return self._row_to_event(row) if row else None

    def find_external(self, source: str, external_id: str) -> AuditEvent | None:
        row = self.conn.execute(
            "SELECT * FROM audit_events WHERE source = ? AND external_id = ?",
            (source, external_id)).fetchone()
        return self._row_to_event(row) if row else None

    def events(self, incident_id: str | None = None, *,
               event_type: EventType | str | None = None) -> list[AuditEvent]:
        """Events of one chain (incident, or the system chain) in order."""
        chain = incident_id or SYSTEM_CHAIN
        sql, args = "SELECT * FROM audit_events WHERE chain = ?", [chain]
        if event_type is not None:
            sql += " AND event_type = ?"
            args.append(event_type.value if isinstance(event_type, EventType) else event_type)
        return [self._row_to_event(r) for r in self.conn.execute(sql + " ORDER BY seq", args)]

    def links_to(self, uid: str) -> list[tuple[str, str]]:
        """(relation, from_uid) pairs of events that point AT ``uid``."""
        return [(r["relation"], r["from_uid"]) for r in self.conn.execute(
            "SELECT relation, from_uid FROM event_links WHERE to_uid = ?", (uid,))]

    def chains(self) -> list[str]:
        return [r["chain"] for r in self.conn.execute(
            "SELECT DISTINCT chain FROM audit_events ORDER BY chain")]

    # --- verify -----------------------------------------------------------
    def verify(self, incident_id: str | None = None) -> VerifyResult:
        """Recompute one chain; report every inconsistency found."""
        chain = incident_id or SYSTEM_CHAIN
        rows = self.conn.execute(
            "SELECT * FROM audit_events WHERE chain = ? ORDER BY seq", (chain,)).fetchall()
        errors: list[str] = []
        prev_hash = GENESIS_HASH
        for expected_seq, row in enumerate(rows, start=1):
            if row["seq"] != expected_seq:
                errors.append(f"seq gap: expected {expected_seq}, found {row['seq']} "
                              f"(event {row['uid']}) — events missing")
            if row["prev_hash"] != prev_hash:
                errors.append(f"seq {row['seq']}: prev_hash does not match the "
                              "previous event's hash")
            pv = row["protocol_valid"]
            ev = {k: row[k] for k in row.keys()}
            ev["payload"] = json.loads(row["payload"])
            ev["protocol_valid"] = None if pv is None else bool(pv)
            recomputed = compute_hash(row["prev_hash"], _body(ev, self._links_of(row["uid"])))
            if recomputed != row["hash"]:
                errors.append(f"seq {row['seq']}: content hash mismatch "
                              "(event body or links altered)")
            prev_hash = row["hash"]
        return VerifyResult(ok=not errors, checked=len(rows), errors=errors)

    def verify_all(self) -> dict[str, VerifyResult]:
        return {c: self.verify(None if c == SYSTEM_CHAIN else c) for c in self.chains()}

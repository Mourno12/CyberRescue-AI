"""Read-only access to a Core database.

The investigation layer must never change the Core. Two independent barriers:

1. SQLite itself: the database is opened with ``mode=ro`` (and
   ``PRAGMA query_only``), so any write raises ``attempt to write a readonly
   database`` whatever the calling code does.
2. The facade: ``ReadOnlyCore`` exposes the store, evidence store and audit log
   only through allow-listed READ methods. Write methods (``add_finding``,
   ``register_actor``, ``authorize`` ...) do not exist on it.

``open_readonly`` never creates or migrates a database: a missing file or a
schema other than the current version is refused (run ``python -m
cyberrescue.core init`` first).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from cyberrescue.core import db
from cyberrescue.core.audit import AuditLog
from cyberrescue.core.evidence_store import EvidenceStore
from cyberrescue.core.store import CoreStore

STORE_READS = frozenset({
    "get_actor", "find_actor", "get_asset", "list_assets", "get_incident",
    "resolve_incident", "aliases_of", "open_incidents_for_asset", "findings", "get_finding",
    "claims_for", "latest_signoff_request", "signoffs_for", "active_vetoes", "active_holds",
    "get_action_request", "action_requests", "decisions_for", "get_approval",
    "unconsumed_approvals",
    # Phase 6 (schema v3): simulated execution records - reads only.
    "execution_records", "execution_record_for", "evidence_fingerprint", "chain_head"})
EVIDENCE_READS = frozenset({"get", "list", "verify", "evidence_for_finding",
                            "findings_citing"})
AUDIT_READS = frozenset({"events", "get", "verify", "verify_all", "chains", "links_to"})


class ReadOnlyError(RuntimeError):
    """The database cannot be opened read-only (missing, wrong schema)."""


class _ReadView:
    """Exposes only allow-listed attributes of ``target``."""

    __slots__ = ("_target", "_allowed", "_name")

    def __init__(self, target: Any, allowed: frozenset[str], name: str) -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_allowed", allowed)
        object.__setattr__(self, "_name", name)

    def __getattr__(self, attr: str) -> Any:
        if attr in self._allowed:
            return getattr(self._target, attr)
        raise AttributeError(f"{self._name}.{attr} is not available on a read-only Core")

    def __setattr__(self, attr: str, value: Any) -> None:
        raise AttributeError("read-only")


class ReadOnlyCore:
    """Read-only facade with the same read API the detection engine uses."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        store = CoreStore(conn)
        self.store = _ReadView(store, STORE_READS, "store")
        self.evidence = _ReadView(EvidenceStore(conn, store.audit), EVIDENCE_READS, "evidence")
        self.audit = _ReadView(store.audit, AUDIT_READS, "audit")

    def resolve(self, incident_ref: str) -> str:
        iid = self.store.resolve_incident(incident_ref)
        if iid is None:
            raise ReadOnlyError(f"no Core incident for {incident_ref!r}")
        return iid

    def list_evidence(self, incident_ref: str, **filters: Any):
        return self.evidence.list(self.resolve(incident_ref), **filters)

    def get_evidence(self, evidence_id: str):
        return self.evidence.get(evidence_id)

    def verify_evidence(self, incident_ref: str):
        return self.evidence.verify(self.resolve(incident_ref))

    def verify_audit(self, incident_id: str | None = None):
        return self.audit.verify(incident_id)

    def select(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        """Ad-hoc read query (SELECT only; the connection is read-only anyway)."""
        if not sql.lstrip().upper().startswith("SELECT"):
            raise ReadOnlyError("only SELECT statements are allowed")
        return self._conn.execute(sql, args).fetchall()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> ReadOnlyCore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def open_readonly(path: str | Path | None = None) -> ReadOnlyCore:
    target = Path(path) if path is not None else db.default_db_path()
    if not target.is_file():
        raise ReadOnlyError(f"no Core database at {target} (investigation never creates one)")
    conn = sqlite3.connect(target.resolve().as_uri() + "?mode=ro", uri=True,
                           isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only = ON")
        version = db.schema_version(conn)
    except sqlite3.DatabaseError as e:
        conn.close()
        raise ReadOnlyError(f"not a readable Core database: {e}") from None
    if version != db.SCHEMA_VERSION:
        conn.close()
        raise ReadOnlyError(f"database schema v{version}, expected v{db.SCHEMA_VERSION}; "
                            "run `python -m cyberrescue.core init` to migrate first")
    return ReadOnlyCore(conn)


# Re-exported for type hints in callers.
__all__ = ["AuditLog", "ReadOnlyCore", "ReadOnlyError", "open_readonly"]

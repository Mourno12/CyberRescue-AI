"""SQLite storage for the CyberRescue Core (stdlib ``sqlite3`` only).

One file (``cyberrescue.db`` at the repo root by default, gitignored; override
with ``CYBERRESCUE_DB_PATH``). Tests use ``tmp_path`` or ``":memory:"``.

Design notes:
  * Foreign keys ON, WAL journal, busy timeout — safe for a single writer now,
    and for a few processes later (Phase 1b).
  * ``audit_events`` and ``event_links`` are append-only: SQLite triggers abort
    any UPDATE/DELETE. Mutable domain fields (incident status, veto status,
    approval consumption, ...) are always changed together with a new audit
    event, in one transaction (see ``store.py``).
  * Autocommit connection + explicit ``transaction()`` (BEGIN IMMEDIATE, or a
    SAVEPOINT when nested) so a domain row and its audit event commit or roll
    back together.

Schema versions:
  * v1 (Phase 1): 16 tables. Its ``evidence`` table held agent-written text
    from FINDING messages — claims, not evidence.
  * v2 (Phase 2A): that table is renamed ``finding_claims`` (data preserved
    verbatim); a new, immutable ``evidence`` table holds externally observed
    security data; ``finding_evidence`` links findings to the evidence they
    cite. ``init_schema`` migrates a v1 database in place (see
    ``_migrate_v1_to_v2``).
  * v3 (Phase 6): adds ``execution_records`` - one append-only record per
    authorized action request that a SIMULATED execution used. ``UNIQUE``
    request (no replay), ``CHECK (mode = 'simulated')`` (real execution cannot
    be recorded), and insert triggers that bind a record to its request's
    incident, action and asset and require an authorized tier-1/2 request.
    Purely additive: v2 -> v3 creates the table and its triggers; no existing
    row or audit event changes.
"""

from __future__ import annotations

import itertools
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 3
REPO_ROOT = Path(__file__).resolve().parents[2]

TABLES = (
    "schema_meta", "actors", "assets", "incidents", "incident_aliases",
    "audit_events", "event_links", "findings", "finding_claims", "evidence",
    "finding_evidence", "signoffs", "vetoes", "legal_holds", "action_requests",
    "policy_decisions", "approvals", "risk_snapshots", "execution_records",
)

_DDL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actors (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL CHECK (kind IN ('agent', 'human', 'system')),
    role         TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    external_ref TEXT UNIQUE,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id        TEXT PRIMARY KEY,
    hostname        TEXT,
    role            TEXT,
    criticality     TEXT NOT NULL,
    network_segment TEXT,
    data_classes    TEXT NOT NULL DEFAULT '[]',
    provenance      TEXT NOT NULL DEFAULT 'simulated',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id               TEXT PRIMARY KEY,
    title            TEXT NOT NULL DEFAULT '',
    category         TEXT,
    severity         TEXT,
    status           TEXT NOT NULL,
    primary_asset_id TEXT REFERENCES assets(asset_id),
    recruited_roles  TEXT NOT NULL DEFAULT '[]',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    closed_at        TEXT
);

CREATE TABLE IF NOT EXISTS incident_aliases (
    alias       TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    created_at  TEXT NOT NULL
);

-- The audit log. chain = incident_id, or '__system__' for events that belong
-- to no incident (actor registration, asset seeding).
CREATE TABLE IF NOT EXISTS audit_events (
    uid            TEXT PRIMARY KEY,
    chain          TEXT NOT NULL,
    incident_id    TEXT REFERENCES incidents(id),
    seq            INTEGER NOT NULL,
    ts             TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    actor_id       TEXT REFERENCES actors(id),
    source         TEXT NOT NULL,
    external_id    TEXT,
    protocol_type  TEXT,
    protocol_valid INTEGER,
    payload        TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    hash           TEXT NOT NULL,
    UNIQUE (chain, seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_external
    ON audit_events(source, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_audit_incident ON audit_events(incident_id, seq);
CREATE INDEX IF NOT EXISTS ix_audit_type ON audit_events(event_type);

CREATE TABLE IF NOT EXISTS event_links (
    from_uid TEXT NOT NULL REFERENCES audit_events(uid),
    to_uid   TEXT NOT NULL REFERENCES audit_events(uid),
    relation TEXT NOT NULL,
    PRIMARY KEY (from_uid, to_uid, relation)
);
CREATE INDEX IF NOT EXISTS ix_links_to ON event_links(to_uid);

CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS event_links_no_update
BEFORE UPDATE ON event_links
BEGIN SELECT RAISE(ABORT, 'event_links is append-only'); END;
CREATE TRIGGER IF NOT EXISTS event_links_no_delete
BEFORE DELETE ON event_links
BEGIN SELECT RAISE(ABORT, 'event_links is append-only'); END;

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    incident_id     TEXT NOT NULL REFERENCES incidents(id),
    author_actor_id TEXT REFERENCES actors(id),
    severity        TEXT,
    summary         TEXT NOT NULL DEFAULT '',
    event_uid       TEXT NOT NULL REFERENCES audit_events(uid),
    created_at      TEXT NOT NULL
);

-- Claims: statements an analyst (usually an LLM agent) wrote inside a FINDING.
-- NOT evidence. (Named "evidence" in schema v1.)
CREATE TABLE IF NOT EXISTS finding_claims (
    id          TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    finding_id  TEXT REFERENCES findings(id),
    kind        TEXT NOT NULL,
    content     TEXT NOT NULL,
    event_uid   TEXT NOT NULL REFERENCES audit_events(uid),
    created_at  TEXT NOT NULL
);

-- Evidence: externally observed security data, submitted by a collector or a
-- human operator. Immutable; bound to exactly one incident; sealed by two
-- SHA-256 hashes that are also recorded in its EVIDENCE_INGESTED audit event.
CREATE TABLE IF NOT EXISTS evidence (
    id             TEXT PRIMARY KEY,
    incident_id    TEXT NOT NULL REFERENCES incidents(id),
    source         TEXT NOT NULL,
    source_ref     TEXT NOT NULL DEFAULT '',
    kind           TEXT NOT NULL CHECK (kind IN
                       ('process', 'file', 'network', 'auth', 'log', 'alert', 'ioc', 'other')),
    event_type     TEXT NOT NULL,
    observed_at    TEXT NOT NULL,
    ingested_at    TEXT NOT NULL,
    host           TEXT,
    asset_id       TEXT REFERENCES assets(asset_id),
    user_name      TEXT,
    raw            TEXT NOT NULL,
    data           TEXT NOT NULL DEFAULT '{}',
    metadata       TEXT NOT NULL DEFAULT '{}',
    provenance     TEXT NOT NULL CHECK (provenance IN ('synthetic', 'replayed', 'live')),
    content_sha256 TEXT NOT NULL,
    record_sha256  TEXT NOT NULL,
    ingested_by    TEXT NOT NULL REFERENCES actors(id),
    event_uid      TEXT NOT NULL REFERENCES audit_events(uid),
    UNIQUE (incident_id, source, source_ref, content_sha256)
);
CREATE INDEX IF NOT EXISTS ix_evidence_time ON evidence(incident_id, observed_at);
CREATE INDEX IF NOT EXISTS ix_evidence_host ON evidence(incident_id, host);
CREATE INDEX IF NOT EXISTS ix_evidence_kind ON evidence(incident_id, kind);
CREATE TRIGGER IF NOT EXISTS evidence_no_update
BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS evidence_no_delete
BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is immutable'); END;

-- A finding citing evidence. Append-only; never crosses incidents.
CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id  TEXT NOT NULL REFERENCES findings(id),
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    relation    TEXT NOT NULL CHECK (relation IN ('supports', 'contradicts', 'context')),
    linked_by   TEXT NOT NULL REFERENCES actors(id),
    event_uid   TEXT NOT NULL REFERENCES audit_events(uid),
    created_at  TEXT NOT NULL,
    PRIMARY KEY (finding_id, evidence_id)
);
CREATE INDEX IF NOT EXISTS ix_finding_evidence_ev ON finding_evidence(evidence_id);
CREATE TRIGGER IF NOT EXISTS finding_evidence_same_incident
BEFORE INSERT ON finding_evidence
WHEN (SELECT incident_id FROM findings WHERE id = NEW.finding_id)
     IS NOT (SELECT incident_id FROM evidence WHERE id = NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'finding and evidence belong to different incidents'); END;
CREATE TRIGGER IF NOT EXISTS finding_evidence_no_update
BEFORE UPDATE ON finding_evidence
BEGIN SELECT RAISE(ABORT, 'finding_evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS finding_evidence_no_delete
BEFORE DELETE ON finding_evidence
BEGIN SELECT RAISE(ABORT, 'finding_evidence is append-only'); END;

CREATE TABLE IF NOT EXISTS signoffs (
    id                TEXT PRIMARY KEY,
    incident_id       TEXT NOT NULL REFERENCES incidents(id),
    actor_id          TEXT NOT NULL REFERENCES actors(id),
    request_event_uid TEXT REFERENCES audit_events(uid),
    covered_actions   TEXT NOT NULL DEFAULT '[]',
    event_uid         TEXT NOT NULL REFERENCES audit_events(uid),
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vetoes (
    id          TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    actor_id    TEXT NOT NULL REFERENCES actors(id),
    action      TEXT,
    asset_id    TEXT REFERENCES assets(asset_id),
    regulation  TEXT,
    reason      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL CHECK (status IN ('active', 'overridden', 'withdrawn')),
    event_uid   TEXT NOT NULL REFERENCES audit_events(uid),
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_vetoes_incident ON vetoes(incident_id, status);

CREATE TABLE IF NOT EXISTS legal_holds (
    id                           TEXT PRIMARY KEY,
    asset_id                     TEXT NOT NULL REFERENCES assets(asset_id),
    incident_id                  TEXT REFERENCES incidents(id),
    rule_ids                     TEXT NOT NULL DEFAULT '[]',
    requires_human_authorization INTEGER NOT NULL DEFAULT 0,
    status                       TEXT NOT NULL CHECK (status IN ('active', 'released')),
    event_uid                    TEXT NOT NULL REFERENCES audit_events(uid),
    created_at                   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_holds_asset ON legal_holds(asset_id, status);

CREATE TABLE IF NOT EXISTS action_requests (
    id           TEXT PRIMARY KEY,
    incident_id  TEXT NOT NULL REFERENCES incidents(id),
    action       TEXT NOT NULL,
    asset_id     TEXT REFERENCES assets(asset_id),
    params       TEXT NOT NULL DEFAULT '{}',
    tier         INTEGER NOT NULL,
    requested_by TEXT REFERENCES actors(id),
    status       TEXT NOT NULL,
    event_uid    TEXT NOT NULL REFERENCES audit_events(uid),
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_requests_incident ON action_requests(incident_id, status);

CREATE TABLE IF NOT EXISTS approvals (
    id                     TEXT PRIMARY KEY,
    incident_id            TEXT NOT NULL REFERENCES incidents(id),
    action                 TEXT NOT NULL,
    asset_id               TEXT REFERENCES assets(asset_id),
    approver_actor_id      TEXT NOT NULL REFERENCES actors(id),
    decision               TEXT NOT NULL CHECK (decision IN ('approve', 'deny')),
    overrides_hold         INTEGER NOT NULL DEFAULT 0,
    overrides_veto         INTEGER NOT NULL DEFAULT 0,
    reason                 TEXT NOT NULL DEFAULT '',
    expires_at             TEXT NOT NULL,
    consumed_by_request_id TEXT REFERENCES action_requests(id),
    consumed_at            TEXT,
    event_uid              TEXT NOT NULL REFERENCES audit_events(uid),
    created_at             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_approvals_scope ON approvals(incident_id, action, asset_id);

CREATE TABLE IF NOT EXISTS policy_decisions (
    id                TEXT PRIMARY KEY,
    action_request_id TEXT NOT NULL REFERENCES action_requests(id),
    incident_id       TEXT NOT NULL REFERENCES incidents(id),
    outcome           TEXT NOT NULL CHECK (outcome IN ('ALLOW', 'REQUIRE_APPROVAL', 'DENY')),
    rule_results      TEXT NOT NULL DEFAULT '[]',
    approval_id       TEXT REFERENCES approvals(id),
    policy_version    TEXT NOT NULL,
    snapshot_hash     TEXT NOT NULL,
    event_uid         TEXT NOT NULL REFERENCES audit_events(uid),
    created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_decisions_request ON policy_decisions(action_request_id);

CREATE TABLE IF NOT EXISTS risk_snapshots (
    id          TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id),
    level       TEXT NOT NULL,
    score       REAL,
    factors     TEXT NOT NULL DEFAULT '{}',
    method      TEXT NOT NULL,
    event_uid   TEXT NOT NULL REFERENCES audit_events(uid),
    created_at  TEXT NOT NULL
);

-- v3 (Phase 6): accountability for SIMULATED execution. One row per authorized
-- request, ever; append-only; never a real execution.
CREATE TABLE IF NOT EXISTS execution_records (
    id                   TEXT PRIMARY KEY,
    incident_id          TEXT NOT NULL REFERENCES incidents(id),
    action_request_id    TEXT NOT NULL UNIQUE REFERENCES action_requests(id),
    mode                 TEXT NOT NULL CHECK (mode = 'simulated'),
    action               TEXT NOT NULL,
    asset_id             TEXT REFERENCES assets(asset_id),
    plan_id              TEXT NOT NULL,
    plan_sha256          TEXT NOT NULL,
    step_id              TEXT NOT NULL,
    step_sha256          TEXT NOT NULL,
    report_sha256        TEXT NOT NULL,
    evidence_fingerprint TEXT NOT NULL,
    environment_sha256   TEXT NOT NULL,
    outcome              TEXT NOT NULL CHECK (outcome IN ('succeeded', 'failed')),
    criteria             TEXT NOT NULL DEFAULT '[]',
    audit_head_hash      TEXT NOT NULL,
    recorded_by          TEXT NOT NULL REFERENCES actors(id),
    authorized_event_uid TEXT NOT NULL REFERENCES audit_events(uid),
    executed_event_uid   TEXT NOT NULL REFERENCES audit_events(uid),
    verified_event_uid   TEXT NOT NULL REFERENCES audit_events(uid),
    created_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_execution_records_incident ON execution_records(incident_id);
CREATE TRIGGER IF NOT EXISTS execution_records_no_update
BEFORE UPDATE ON execution_records
BEGIN SELECT RAISE(ABORT, 'execution_records is append-only'); END;
CREATE TRIGGER IF NOT EXISTS execution_records_no_delete
BEFORE DELETE ON execution_records
BEGIN SELECT RAISE(ABORT, 'execution_records is append-only'); END;
CREATE TRIGGER IF NOT EXISTS execution_records_bound_to_request
BEFORE INSERT ON execution_records
WHEN NOT EXISTS (
    SELECT 1 FROM action_requests r
    WHERE r.id = NEW.action_request_id AND r.incident_id = NEW.incident_id
      AND r.action = NEW.action AND r.asset_id IS NEW.asset_id
      AND r.status = 'authorized' AND r.tier IN (1, 2))
BEGIN SELECT RAISE(ABORT,
    'execution record does not match an authorized tier-1/2 request of this incident, action and asset');
END;
"""


def default_db_path() -> Path:
    """``$CYBERRESCUE_DB_PATH`` if set, else ``<repo>/cyberrescue.db``."""
    env = os.getenv("CYBERRESCUE_DB_PATH")
    return Path(env) if env else REPO_ROOT / "cyberrescue.db"


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """Open (and initialise) a Core database. ``":memory:"`` is supported."""
    target = str(path) if path is not None else str(default_db_path())
    if target != ":memory:":
        Path(target).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target, isolation_level=None)  # autocommit; we BEGIN explicitly
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    if target != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    init_schema(conn)
    return conn


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                        (name,)).fetchone() is not None


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _migrate_v1_to_v2(conn: sqlite3.Connection) -> None:
    """v1 -> v2: rename the v1 ``evidence`` table (agent-written claims) to
    ``finding_claims``. Rows are preserved verbatim; audit events are never
    rewritten (their ``EVIDENCE_RECORDED`` type stays readable as a legacy
    claim event), so every audit chain still verifies. Idempotent: detects the
    v1 table by its shape, so a re-run after a partial migration is safe."""
    if not _has_table(conn, "evidence"):
        return
    cols = _columns(conn, "evidence")
    if "finding_id" not in cols or "content_sha256" in cols:
        return  # already the v2 evidence table
    if _has_table(conn, "finding_claims"):
        raise RuntimeError("refusing to migrate: both a v1 'evidence' table and "
                           "'finding_claims' exist")
    with transaction(conn):
        conn.execute("ALTER TABLE evidence RENAME TO finding_claims")
        conn.execute(
            "INSERT OR REPLACE INTO schema_meta(key, value) VALUES ('migration.v1_to_v2', "
            "strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))")


def init_schema(conn: sqlite3.Connection) -> None:
    """Create or upgrade the schema (idempotent), then record the version."""
    if _has_table(conn, "schema_meta"):
        current = schema_version(conn)
        if current > SCHEMA_VERSION:
            raise RuntimeError(f"database schema v{current} is newer than this code "
                               f"(v{SCHEMA_VERSION})")
        if current == 1:
            _migrate_v1_to_v2(conn)  # must run BEFORE the DDL creates the new 'evidence'
    else:
        current = SCHEMA_VERSION      # a fresh database
    conn.executescript(_DDL)          # v2 -> v3 is purely additive (IF NOT EXISTS)
    if 0 < current < 3:
        conn.execute(
            "INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('migration.v2_to_v3', "
            "strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))")
    conn.execute(
        "INSERT INTO schema_meta(key, value) VALUES ('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(SCHEMA_VERSION),),
    )


def schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
    return int(row["value"]) if row else 0


_savepoint_ids = itertools.count(1)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """All-or-nothing block. Nested calls use a SAVEPOINT."""
    if conn.in_transaction:
        name = f"sp_{next(_savepoint_ids)}"
        conn.execute(f"SAVEPOINT {name}")
        try:
            yield conn
        except BaseException:
            conn.execute(f"ROLLBACK TO {name}")
            conn.execute(f"RELEASE {name}")
            raise
        conn.execute(f"RELEASE {name}")
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")

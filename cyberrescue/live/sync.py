"""``python -m cyberrescue.live sync`` -- keep the Core in step with a live Band room.

Each poll re-reads the room with the existing read-only exporter
(``band_export.collect_room``) and feeds NEW messages, one at a time and in
normalised chronological order, to the existing idempotent importer
(``core.band_import.import_band_context`` -> ``ProtocolIngestor``). This module
adds no ingestion rules: sign-offs / vetoes / rulings count only under the
ingestor's role and roster checks, and the Commander gate decides as before.

It never executes, requests or authorizes an action, and never creates an
approval: an imported human message is a *message*; only ``core approve`` (a
registered human approver) creates an approval.

Checks, and whether each one PREVENTS a write or DETECTS a problem after it:

* ``incomplete``   PREVENTS -- if any agent view failed (or was truncated) the
                   poll imports nothing; repeated -> halt. A partial union could
                   import a SIGNOFF before its SIGNOFF_REQUEST, which the ingestor
                   would reject *permanently* (message ids are imported once).
* ``invalid``      PREVENTS -- a message lacks sender, has an unparseable or
                   timezone-less (ambiguous) timestamp, or belongs to another room.
* ``out_of_order`` PREVENTS -- a not-yet-imported text message is older than one
                   already imported. Never skipped automatically: see
                   docs/ca3/07-live-demo-runbook.md "Out-of-order halt".
* ``correlation``  PREVENTS -- a protocol block names a different/unknown incident.
* ``audit_pre``    PREVENTS -- the incident hash chain fails verification BEFORE
                   anything is imported in this poll.
* ``audit``        DETECTS  -- the chain fails verification AFTER this poll's
                   imports (those writes are already committed).
* ``invariant``    DETECTS  -- an event caused by this poll's import is an
                   approval/authorization/execution (already committed; halts so
                   nothing further is imported).
* ``db_locked``    -- SQLite stayed locked after a bounded retry (attempts and
                   time limit). Each message is imported in its own transaction,
                   so a lock never leaves a half-written message; messages
                   committed before the lock stay and are not re-imported.
* ``unexpected``   -- any other error: the run halts with exit 1 and a truthful
                   terminal record (exception type; details withheld from the log
                   unless known to be non-sensitive).

Ordering rule: timestamps are parsed to timezone-aware UTC instants; a batch is
sorted by (instant, message id) -- ties are broken by message id, which is
deterministic but cannot recover true order inside one instant. Messages are
handed to the importer ONE AT A TIME so the importer's own text sort can never
reorder a batch differently from this module.

Messages the importer intentionally skips (non-text: tool_call / tool_result)
are reported under ``skipped`` with a reason, never as imported, and are not
counted again on later polls of the same run.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cyberrescue.core.band_import import (
    SOURCE,
    Roster,
    import_band_context,
    open_legacy_incident,
)
from cyberrescue.core.ids import legacy_alias_for, parse_incident_ref
from cyberrescue.core.models import EventType
from cyberrescue.core.service import CoreService
from shared.schemas import extract_blocks

MIN_INTERVAL, MAX_INTERVAL = 2.0, 600.0
MAX_POLLS, MAX_MINUTES = 10_000, 240.0
FORBIDDEN_FROM_IMPORT = frozenset({
    EventType.APPROVAL_GRANTED.value, EventType.APPROVAL_DENIED.value,
    EventType.ACTION_AUTHORIZED.value, EventType.ACTION_EXECUTED.value,
    EventType.ACTION_VERIFIED.value, EventType.GATE_DECISION.value,
})
APPROVAL_NOTE = ("imported human messages are messages, not approvals; only "
                 "`python -m cyberrescue.core approve` creates an approval")
OUT_OF_ORDER_HELP = ("operator investigation required before resuming -- see "
                     "docs/ca3/07-live-demo-runbook.md 'Out-of-order halt'; "
                     "the sync never skips a message")

EXIT_OK, EXIT_HALT, EXIT_CONFIG, EXIT_INTERRUPTED = 0, 1, 2, 130


class SyncHalt(Exception):
    def __init__(self, code: str, reason: str, details: Any = None) -> None:
        super().__init__(f"{code}: {reason}")
        self.code, self.reason, self.details = code, reason, details


class TransientSyncError(Exception):
    """A poll that imported nothing and may succeed if retried."""


@dataclass(frozen=True)
class SyncSettings:
    room_id: str
    incident_ref: str
    interval: float = 10.0
    max_polls: int = 360
    max_minutes: float = 60.0
    settle_seconds: float = 5.0
    max_consecutive_errors: int = 3
    stop_when_terminal: bool = True
    db_lock_attempts: int = 5          # attempts per poll for SQLite "locked/busy"
    db_lock_timeout: float = 30.0      # seconds per poll across those attempts

    def validate(self) -> None:
        if not self.room_id.strip() or not self.incident_ref.strip():
            raise ValueError("room id and incident are required")
        if not MIN_INTERVAL <= self.interval <= MAX_INTERVAL:
            raise ValueError(f"interval must be {MIN_INTERVAL}..{MAX_INTERVAL} s")
        if not 1 <= self.max_polls <= MAX_POLLS:
            raise ValueError(f"max_polls must be 1..{MAX_POLLS}")
        if not 0 < self.max_minutes <= MAX_MINUTES:
            raise ValueError(f"max_minutes must be >0 and <= {MAX_MINUTES}")
        if not 0 <= self.settle_seconds <= 120:
            raise ValueError("settle_seconds must be 0..120")
        if not 1 <= self.max_consecutive_errors <= 20:
            raise ValueError("max_consecutive_errors must be 1..20")
        if not 1 <= self.db_lock_attempts <= 20:
            raise ValueError("db_lock_attempts must be 1..20")
        if not 0 < self.db_lock_timeout <= 300:
            raise ValueError("db_lock_timeout must be >0 and <= 300 s")


@dataclass
class SyncSummary:
    exit_code: int
    reason: str
    polls: int = 0
    imported: int = 0
    halt: dict[str, Any] | None = None
    records: list[dict[str, Any]] = field(default_factory=list)


# --- timestamps -------------------------------------------------------------------

def parse_ts(value: Any) -> datetime | None:
    """ISO-8601 -> timezone-aware UTC instant. ``Z``, fractional seconds and
    explicit offsets are accepted; a timestamp WITHOUT a zone is ambiguous and
    rejected (None), as is anything unparseable."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None or dt.utcoffset() is None:
        return None
    return dt.astimezone(timezone.utc)


def order_key(m: dict[str, Any]) -> tuple[datetime, str]:
    """Normalised chronological order with a deterministic id tie-breaker."""
    return parse_ts(m["inserted_at"]), str(m["id"])


def is_text(m: dict[str, Any]) -> bool:
    return (m.get("message_type") or "text") == "text"


# --- pure checks ------------------------------------------------------------------

def message_problems(messages: list[dict[str, Any]], room_id: str) -> list[str]:
    out = []
    for m in messages:
        mid = m.get("id")
        if not mid:
            out.append("a message has no id")
        if not m.get("sender_id"):
            out.append(f"{mid}: no sender_id")
        if m.get("sender_type") not in ("User", "Agent"):
            out.append(f"{mid}: sender_type {m.get('sender_type')!r}")
        if parse_ts(m.get("inserted_at")) is None:
            out.append(f"{mid}: unparseable or timezone-less inserted_at "
                       f"{m.get('inserted_at')!r}")
        if m.get("chat_id") and m["chat_id"] != room_id:
            out.append(f"{mid}: belongs to room {m['chat_id']} (syncing {room_id})")
    return out


def correlation_problems(svc: CoreService, incident_id: str,
                         messages: list[dict[str, Any]]) -> list[str]:
    out = []
    for m in messages:
        if not is_text(m):
            continue
        for b in extract_blocks(m.get("content") or ""):
            if b.incident and svc.store.resolve_incident(b.incident) != incident_id:
                out.append(f"{m.get('id')}: {b.type} block names incident {b.incident!r}, "
                           f"not {incident_id}")
    return out


def core_progress(svc: CoreService, incident_id: str
                  ) -> tuple[set[str], datetime | None, list[str]]:
    """Band message ids already in the Core for this incident, the newest
    normalised transport timestamp among them, and ids whose stored timestamp
    is missing/ambiguous (which would make ordering checks unreliable)."""
    ids: set[str] = set()
    newest: datetime | None = None
    ambiguous: list[str] = []
    for ev in svc.audit.events(incident_id):
        if ev.source != SOURCE or not ev.external_id:
            continue
        ids.add(ev.external_id)
        ts = parse_ts((ev.payload or {}).get("transport_ts"))
        if ts is None:
            ambiguous.append(ev.external_id)
        elif newest is None or ts > newest:
            newest = ts
    return ids, newest, ambiguous


def core_state(svc: CoreService, incident_id: str) -> dict[str, Any]:
    inc = svc.store.get_incident(incident_id)
    snap = svc.store.snapshot(incident_id, svc.clock())
    events = svc.audit.events(incident_id)
    head = events[-1] if events else None
    return {
        "incident": incident_id,
        "status": inc.status.value,
        "terminal": inc.is_terminal,
        "signoff_request_actions": snap.signoff_request.actions if snap.signoff_request else None,
        "signoffs": sorted(s.actor_role for s in snap.signoffs),
        "active_vetoes": sorted(v.action or "ALL tier-3" for v in snap.vetoes),
        "verified_human_approvals_unconsumed": len(svc.store.unconsumed_approvals(incident_id)),
        "claims_rejected_total": sum(e.event_type == EventType.CLAIM_REJECTED.value
                                     for e in events),
        "chain_head": {"seq": head.seq, "hash": head.hash} if head else None,
    }


def is_lock_error(e: BaseException) -> bool:
    msg = str(e).lower()
    return isinstance(e, sqlite3.OperationalError) and ("locked" in msg or "busy" in msg)


def safe_reason(e: BaseException) -> str:
    """A log-safe description: SQLite operational messages carry no payload;
    anything else is reduced to its type (details stay on the console only)."""
    if isinstance(e, sqlite3.OperationalError):
        return f"sqlite3.OperationalError: {str(e)[:200]}"
    return f"{type(e).__name__} (details withheld from the log: may contain message content)"


@dataclass
class _PollAcc:
    """Results of one poll, accumulated across database-lock retries."""
    imported: list[str] = field(default_factory=list)
    duplicates: list[str] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    protocol_valid: int = 0
    unstructured: int = 0
    human: int = 0
    events_appended: int = 0
    db_lock_retries: int = 0


# --- the loop ---------------------------------------------------------------------

class LiveSync:
    def __init__(self, settings: SyncSettings, roster: Roster, *,
                 open_core: Callable[[], CoreService],
                 collect: Callable[[], dict[str, Any]],
                 log_path: Path, lock_path: Path,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 monotonic: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep,
                 echo: Callable[[str], None] = print) -> None:
        settings.validate()
        self.s, self.roster = settings, roster
        self.open_core, self.collect = open_core, collect
        self.log_path, self.lock_path = Path(log_path), Path(lock_path)
        self.now, self.monotonic, self.sleep, self.echo = now, monotonic, sleep, echo
        self.polls = 0
        self.imported = 0
        self.skipped_ids: set[str] = set()   # non-text ids already reported in this run

    # --- logging ----------------------------------------------------------------
    def _log(self, kind: str, **fields: Any) -> dict[str, Any]:
        rec = {"ts": self.now().isoformat(), "kind": kind, "poll": self.polls,
               "room_id": self.s.room_id, "incident_ref": self.s.incident_ref, **fields}
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str, sort_keys=True) + "\n")
        return rec

    # --- one poll -----------------------------------------------------------------
    def _incident(self, svc: CoreService) -> str:
        iid = svc.store.resolve_incident(self.s.incident_ref)
        if iid is None:
            if legacy_alias_for(parse_incident_ref(self.s.incident_ref) or ""):
                return open_legacy_incident(svc, self.s.incident_ref).id
            raise SyncHalt("config", f"no Core incident for {self.s.incident_ref!r}")
        return iid

    def _core_section(self, messages: list[dict[str, Any]], acc: _PollAcc) -> dict[str, Any]:
        """Everything that touches the Core for one poll. Idempotent: on a lock
        retry it recomputes what is already imported and continues from there."""
        svc = self.open_core()
        try:
            iid = self._incident(svc)
            have, newest, ambiguous = core_progress(svc, iid)
            if ambiguous:
                raise SyncHalt("invalid", "the Core holds imported messages without a usable "
                               "timestamp; ordering cannot be checked", ambiguous[:20])
            cutoff = self.now() - timedelta(seconds=self.s.settle_seconds)
            new = sorted((m for m in messages if str(m["id"]) not in have
                          and str(m["id"]) not in self.skipped_ids), key=order_key)
            settled = [m for m in new if parse_ts(m["inserted_at"]) <= cutoff]
            waiting = len(new) - len(settled)
            if newest is not None:
                late = [f"{m['id']} at {parse_ts(m['inserted_at']).isoformat()}"
                        for m in settled if is_text(m) and parse_ts(m["inserted_at"]) < newest]
                if late:
                    raise SyncHalt("out_of_order", "new messages are older than messages "
                                   f"already imported (newest imported {newest.isoformat()}); "
                                   + OUT_OF_ORDER_HELP, late[:20])
            corr = correlation_problems(svc, iid, settled)
            if corr:
                raise SyncHalt("correlation", "protocol blocks name another incident", corr[:20])

            pre = svc.verify_audit(iid)                     # PREVENTS writes onto a bad chain
            if not pre.ok:
                raise SyncHalt("audit_pre", "incident hash chain failed verification before "
                               "import; nothing imported this poll", pre.errors[:20])

            before = svc.audit.events(iid)
            before_seq = before[-1].seq if before else 0
            for m in settled:                                # one message per import call
                mid = str(m["id"])
                if not is_text(m):
                    acc.skipped.append({"id": mid, "reason":
                                        f"non_text:{m.get('message_type')} (importer skips "
                                        "non-text messages)"})
                    self.skipped_ids.add(mid)
                    continue
                rep = import_band_context(svc, [m], incident_ref=iid, roster=self.roster,
                                          open_if_missing=False)
                if rep.imported:
                    acc.imported.append(mid)
                    acc.protocol_valid += rep.protocol_valid
                    acc.unstructured += rep.unstructured
                    acc.human += rep.human
                elif rep.duplicates:
                    acc.duplicates.append(mid)   # imported concurrently by someone else
            caused = [e for e in svc.audit.events(iid)
                      if e.seq > before_seq and e.source == SOURCE]
            acc.events_appended += len(caused)
            forbidden = [f"{e.event_type}#{e.seq}" for e in caused
                         if e.event_type in FORBIDDEN_FROM_IMPORT]
            if forbidden:                                    # DETECTS (already committed)
                raise SyncHalt("invariant", "import produced approval/authorization events "
                               "(already committed; halting before importing more)", forbidden)
            post = svc.verify_audit(iid)                     # DETECTS (already committed)
            if not post.ok:
                raise SyncHalt("audit", "incident hash chain failed verification after "
                               "import (this poll's writes are committed)", post.errors[:20])
            state = core_state(svc, iid)
            state.update(messages_read=len(messages), new=len(new), waiting_to_settle=waiting)
            return state
        finally:
            svc.conn.close()

    def _with_lock_retry(self, fn: Callable[[], dict[str, Any]], acc: _PollAcc
                         ) -> dict[str, Any]:
        start = self.monotonic()
        attempt = 0
        while True:
            attempt += 1
            try:
                return fn()
            except sqlite3.OperationalError as e:
                if not is_lock_error(e):
                    raise
                elapsed = self.monotonic() - start
                if attempt >= self.s.db_lock_attempts or elapsed >= self.s.db_lock_timeout:
                    raise SyncHalt("db_locked", f"database stayed locked after {attempt} "
                                   f"attempt(s) / {elapsed:.1f}s; messages committed before "
                                   "the lock are kept, nothing half-written",
                                   [safe_reason(e)]) from e
                acc.db_lock_retries += 1
                self._log("db_retry", attempt=attempt, error=safe_reason(e))
                self.sleep(min(0.5 * 2 ** (attempt - 1),
                               max(0.0, self.s.db_lock_timeout - elapsed)))

    def poll_once(self) -> dict[str, Any]:
        """One poll. Returns the logged record; raises SyncHalt (halt) or
        ``TransientSyncError`` (retryable, nothing imported)."""
        try:
            doc = self.collect()
        except Exception as e:  # noqa: BLE001 -- network/SDK failure: retryable
            raise TransientSyncError(f"room read failed: {type(e).__name__}") from e
        views = doc.get("views") or {}
        if not views:
            raise SyncHalt("config", "no agent views were configured to read the room")
        failed = sorted(r for r, v in views.items() if not v.get("ok"))
        if failed:
            raise TransientSyncError(f"incomplete transcript: views {failed} failed or were "
                                     "truncated; nothing imported this poll")
        messages = list(doc.get("data") or [])
        bad = message_problems(messages, self.s.room_id)
        if bad:
            raise SyncHalt("invalid", "transcript contains invalid messages", bad[:20])

        acc = _PollAcc()
        try:
            state = self._with_lock_retry(lambda: self._core_section(messages, acc), acc)
        finally:
            self.imported += len(acc.imported)
        return self._log(
            "poll", imported=len(acc.imported), imported_message_ids=acc.imported,
            duplicates=len(acc.duplicates), duplicate_message_ids=acc.duplicates,
            skipped=acc.skipped, protocol_valid=acc.protocol_valid,
            unstructured=acc.unstructured, human_messages_imported=acc.human,
            events_appended=acc.events_appended, db_lock_retries=acc.db_lock_retries,
            unrostered_senders=sorted({str(m["sender_id"]) for m in messages
                                       if str(m["sender_id"]) not in self.roster.agents
                                       and str(m["sender_id"]) not in self.roster.humans}),
            views=views, approval_note=APPROVAL_NOTE, **state)

    # --- bounded loop -----------------------------------------------------------------
    def _acquire_lock(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps({"pid": os.getpid(), "room_id": self.s.room_id,
                                "started": self.now().isoformat()}))

    def run(self) -> SyncSummary:
        try:
            self._acquire_lock()
        except FileExistsError:
            msg = (f"another sync holds {self.lock_path} (one sync per database). If no "
                   "sync is running, delete that file and retry.")
            self.echo(f"[sync] {msg}")
            return SyncSummary(EXIT_CONFIG, "locked", halt={"code": "locked", "reason": msg})
        # Fail-safe default: unless the loop ends cleanly, the run did NOT succeed.
        summary = SyncSummary(EXIT_HALT, "terminated before completing")
        kind = "halted"
        start = self.monotonic()
        errors = 0
        try:
            self._log("start", settings=asdict(self.s))
            self.echo(f"[sync] room {self.s.room_id} -> incident {self.s.incident_ref} | every "
                      f"{self.s.interval:g}s, at most {self.s.max_polls} polls / "
                      f"{self.s.max_minutes:g} min | log {self.log_path}")
            while True:
                if self.polls >= self.s.max_polls:
                    reason = f"reached max polls ({self.s.max_polls})"
                    break
                if (self.monotonic() - start) / 60 >= self.s.max_minutes:
                    reason = f"reached max minutes ({self.s.max_minutes:g})"
                    break
                self.polls += 1
                try:
                    rec = self.poll_once()
                    errors = 0
                    summary.records.append(rec)
                    self.echo(f"[sync] poll {self.polls}: +{rec['imported']} imported, "
                              f"{len(rec['skipped'])} skipped (non-text), "
                              f"{rec['waiting_to_settle']} settling | {rec['status']} | "
                              f"sign-offs {rec['signoffs']} vetoes {rec['active_vetoes']} | "
                              f"verified approvals {rec['verified_human_approvals_unconsumed']} "
                              f"| human msgs +{rec['human_messages_imported']} (not approvals)")
                    if rec["unrostered_senders"]:
                        self.echo(f"[sync]   note: unrostered senders imported as "
                                  f"unknown/observer: {rec['unrostered_senders']}")
                    if rec["terminal"] and self.s.stop_when_terminal:
                        reason = f"incident is {rec['status']}"
                        break
                except TransientSyncError as e:
                    errors += 1
                    self._log("error", error=str(e), consecutive=errors)
                    self.echo(f"[sync] poll {self.polls}: {e} ({errors}/"
                              f"{self.s.max_consecutive_errors})")
                    if errors >= self.s.max_consecutive_errors:
                        raise SyncHalt("incomplete", f"{errors} consecutive failed polls; "
                                       f"last: {e}") from e
                if self.polls < self.s.max_polls:      # no pointless wait after the last poll
                    self.sleep(self.s.interval)
            summary.exit_code, summary.reason, kind = EXIT_OK, reason, "stop"
        except SyncHalt as h:
            summary.exit_code = EXIT_CONFIG if h.code == "config" else EXIT_HALT
            summary.reason = f"HALTED ({h.code}): {h.reason}"
            summary.halt = {"code": h.code, "reason": h.reason, "details": h.details}
            self.echo(f"[sync] {summary.reason}")
            for d in (h.details if isinstance(h.details, list) else [])[:10]:
                self.echo(f"[sync]   - {d}")
            self.echo("[sync] nothing further was imported; messages committed earlier stay "
                      "(each message is its own transaction). Investigate before any re-run.")
        except KeyboardInterrupt:
            summary.exit_code, summary.reason, kind = (EXIT_INTERRUPTED,
                                                       "interrupted by operator", "interrupted")
        except Exception as e:  # noqa: BLE001 -- the terminal record must stay truthful
            summary.exit_code = EXIT_HALT
            summary.reason = f"HALTED (unexpected): {safe_reason(e)}"
            summary.halt = {"code": "unexpected", "reason": safe_reason(e),
                            "exception_type": type(e).__name__}
            self.echo(f"[sync] HALTED (unexpected): {type(e).__name__}: {str(e)[:300]}")
        finally:
            summary.polls, summary.imported = self.polls, self.imported
            self._log(kind, outcome=kind, reason=summary.reason, exit_code=summary.exit_code,
                      halt=summary.halt, polls=self.polls, imported_total=self.imported)
            try:
                self.lock_path.unlink()
            except FileNotFoundError:
                pass
        self.echo(f"[sync] {kind}: {summary.reason} | {self.polls} poll(s), "
                  f"{self.imported} message(s) imported | exit {summary.exit_code}")
        return summary

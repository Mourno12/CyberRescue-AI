"""``python -m cyberrescue.live verify-sync`` -- read-only cross-check of a run.

Compares three records of the same room and incident:

* the Band export (``export-band`` JSON),
* the sync log (``live_sync_*.jsonl``),
* the Core database (audit events imported from Band, hash chain).

It never writes to the Core (it opens SQLite read-only) and makes no network
call. Every problem found is listed; exit 0 only if there are none.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberrescue.core.band_import import SOURCE, load_band_messages
from cyberrescue.core.service import CoreService
from cyberrescue.live.sync import is_text


@dataclass
class SyncCheck:
    problems: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.problems


def _read_log(path: Path) -> list[dict[str, Any]]:
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"kind": "unparseable", "line": n})
    return out


def verify_sync(*, db: Path, export: Path, log: Path, incident_ref: str) -> SyncCheck:
    chk = SyncCheck()
    doc = json.loads(Path(export).read_text(encoding="utf-8-sig"))
    views = doc.get("views") or {}
    bad_views = sorted(r for r, v in views.items() if not v.get("ok"))
    if bad_views:
        chk.problems.append(f"export views not complete: {bad_views}")
    messages = load_band_messages(doc)
    export_text = {str(m["id"]) for m in messages if m.get("id") and is_text(m)}
    export_other = {str(m["id"]) for m in messages if m.get("id") and not is_text(m)}

    uri = Path(db).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)          # read-only: a write would raise
    conn.row_factory = sqlite3.Row
    svc = CoreService(conn)
    try:
        iid = svc.store.resolve_incident(incident_ref)
        if iid is None:
            chk.problems.append(f"no Core incident for {incident_ref!r}")
            return chk
        events = svc.audit.events(iid)
        core_ids = {e.external_id for e in events if e.source == SOURCE and e.external_id}
        chain = {e.seq: e.hash for e in events}
        verify = svc.verify_audit(iid)
    finally:
        svc.conn.close()
    if not verify.ok:
        chk.problems.append(f"hash chain fails verification: {verify.errors[:5]}")

    records = _read_log(Path(log))
    polls = [r for r in records if r.get("kind") == "poll"]
    logged = [i for r in polls for i in r.get("imported_message_ids") or []]
    if any(r.get("kind") == "unparseable" for r in records):
        chk.problems.append("sync log has unparseable lines")
    dupes = sorted({i for i in logged if logged.count(i) > 1})
    if dupes:
        chk.problems.append(f"sync log reports these ids imported more than once: {dupes[:10]}")
    not_in_core = sorted(set(logged) - core_ids)
    if not_in_core:
        chk.problems.append(f"sync log reports imports missing from the Core: {not_in_core[:10]}")
    missing = sorted(export_text - core_ids)
    if missing:
        chk.problems.append(f"text messages in the export but not in the Core: {missing[:10]}")
    extra = sorted(core_ids - export_text)
    if extra:
        chk.problems.append(f"Core holds Band messages absent from the export: {extra[:10]}")
    for r in polls:
        head = r.get("chain_head") or {}
        if head and chain.get(head.get("seq")) != head.get("hash"):
            chk.problems.append(f"poll {r.get('poll')}: chain head seq {head.get('seq')} does "
                                "not match the Core chain")
    final = records[-1] if records else {}
    if final.get("kind") != "stop" or final.get("exit_code") != 0:
        chk.problems.append(f"sync did not end cleanly: last record kind={final.get('kind')!r} "
                            f"exit_code={final.get('exit_code')!r}")
    chk.facts = {"incident": iid, "export_text_messages": len(export_text),
                 "export_non_text_messages": len(export_other),
                 "core_band_messages": len(core_ids), "logged_imports": len(logged),
                 "polls": len(polls), "final_record": final.get("kind"),
                 "chain_events": len(chain), "chain_ok": verify.ok}
    return chk

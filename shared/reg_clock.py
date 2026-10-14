"""Persisted regulatory-clock store — the demo's 'T-minus' drama (Phase 5.3).

When Compliance starts a notification clock for a triggered regime (e.g. GDPR
Art. 33 → 72h), the deadline is fixed ONCE and recorded here; subsequent messages
show the live time-remaining ("T-minus 71h 42m"). State persists to
``regulatory_clocks.json`` (gitignored) so it survives across Compliance's turns
within an incident. Clear that file between demo runs for a fresh countdown.

Pure/deterministic and unit-tested: the path, store, and T-minus formatter are
plain functions; ``now`` is injectable for tests.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.config import REPO_ROOT


def _path() -> Path:
    return Path(os.getenv("REG_CLOCK_PATH", str(REPO_ROOT / "regulatory_clocks.json")))


def _load() -> dict[str, Any]:
    p = _path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 - corrupt/partial file → start fresh
            return {}
    return {}


def _save(data: dict[str, Any]) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _key(incident: str, regulation: str) -> str:
    return f"{incident}::{regulation}"


def _parse(ts: Any) -> datetime | None:
    if ts is None or ts == "":
        return None
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(ts).replace(" ", "T"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        return None


def _remaining_seconds(deadline_utc: Any, now: datetime) -> float | None:
    dl = _parse(deadline_utc)
    if dl is None:
        return None
    return (dl - now).total_seconds()


def format_tminus(deadline_utc: Any, now: datetime | None = None) -> str:
    """Human 'T-minus' string for a deadline (or BREACHED if past)."""
    now = now or datetime.now(timezone.utc)
    rem = _remaining_seconds(deadline_utc, now)
    if rem is None:
        return "T-minus unknown"
    if rem <= 0:
        if rem > -60:  # 'immediate' obligations sit right at zero
            return "DUE NOW"
        over = int(-rem)
        return f"BREACHED (overdue {over // 3600}h {(over % 3600) // 60}m)"
    s = int(rem)
    days, h, m = s // 86400, (s % 86400) // 3600, (s % 3600) // 60
    return f"T-minus {days}d {h}h {m}m" if days else f"T-minus {h}h {m}m"


def start_clock(incident: str, regulation: str, name: str, deadline_utc: str,
                window: str, now: datetime | None = None) -> dict[str, Any]:
    """Record the clock the FIRST time it's started for (incident, regulation);
    on later calls return the existing record (the deadline does not move)."""
    now = now or datetime.now(timezone.utc)
    data = _load()
    k = _key(incident, regulation)
    if k not in data:
        data[k] = {
            "incident": incident,
            "regulation": regulation,
            "name": name,
            "started_utc": now.isoformat(),
            "deadline_utc": deadline_utc,
            "window": window,
        }
        _save(data)
    rec = dict(data[k])
    rec["t_minus"] = format_tminus(rec["deadline_utc"], now)
    return rec


def clock_status(incident: str, now: datetime | None = None) -> list[dict[str, Any]]:
    """All running clocks for an incident, with live T-minus / breach state."""
    now = now or datetime.now(timezone.utc)
    out = []
    for rec in _load().values():
        if rec.get("incident") != incident:
            continue
        rem = _remaining_seconds(rec.get("deadline_utc"), now)
        out.append({
            **rec,
            "t_minus": format_tminus(rec.get("deadline_utc"), now),
            "breached": rem is not None and rem <= 0,
        })
    return out

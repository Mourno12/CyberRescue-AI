"""Helpers shared by several rules."""

from __future__ import annotations

from datetime import datetime, timedelta

from cyberrescue.detection.context import Ev, EvidenceView
from cyberrescue.detection.matchers import basename, normalize_sha256

CORROBORATION_SECONDS = 1800   # see the window table in docs/cyberrescue/phase2c-detection.md


def vendor_alerts(view: EvidenceView, host: str | None, around: datetime, *,
                  process_name: str | None = None, sha256: str | None = None,
                  seconds: int = CORROBORATION_SECONDS) -> list[Ev]:
    """EDR/IDS alerts on ``host`` within ``seconds`` of ``around`` that name the
    same process or hash. Alerts are corroboration/context, never a basis."""
    name = (process_name or "").lower()
    sha = normalize_sha256(sha256)
    out = []
    for a in view.of_kind("alert"):
        if a.host != host or abs((a.at - around).total_seconds()) > seconds:
            continue
        a_name = (a.s("process.name") or "").lower()
        if (name and a_name == name) or (sha and normalize_sha256(a.s("process.hash.sha256"))
                                         == sha):
            out.append(a)
    return out


def process_starts_of(view: EvidenceView, host: str | None, executable: str,
                      around: datetime, seconds: int) -> list[Ev]:
    exe = executable.lower()
    win = timedelta(seconds=seconds)
    return [p for p in view.of_type("process_start")
            if p.host == host and (p.s("process.executable") or "").lower() == exe
            and abs(p.at - around) <= win]


def parent_starts(view: EvidenceView, child: Ev, lookback_seconds: int = 3600) -> list[Ev]:
    """Earlier process starts on the same host whose image is the child's parent."""
    parent = basename(child.s("process.parent.name") or "").lower()
    if not parent:
        return []
    lo = child.at - timedelta(seconds=lookback_seconds)
    return [p for p in view.of_type("process_start")
            if p.host == child.host and lo <= p.at <= child.at and p.id != child.id
            and basename(p.s("process.executable") or p.s("process.name") or "").lower()
            == parent]

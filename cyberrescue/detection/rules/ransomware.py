"""Ransomware encryption activity.

Generic on purpose: no list of known ransomware extensions. A finding needs a
mass rename (>= 20 files by one process on one host within 5 minutes, >= 90 %
gaining the same new extension) AND at least one corroboration - a ransom
note dropped in >= 3 directories, recovery inhibition in the 30 minutes
before, or a vendor alert naming the process. A mass rename alone (e.g. a
backup tool producing ``*.bak``) is an Observation.

Data: the Phase 2B burst is 34 renames in 131 s; notes 6 directories in 6 s.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from cyberrescue.detection.context import Ev, EvidenceView
from cyberrescue.detection.matchers import (
    appended_extension,
    basename,
    dirname,
    recovery_inhibition,
    safe_token,
)
from cyberrescue.detection.model import ConditionResult, ConditionSpec, RuleSpec, Window
from cyberrescue.detection.registry import Rule
from cyberrescue.detection.rules.common import CORROBORATION_SECONDS, vendor_alerts

MIN_RENAMES = 20
MIN_SHARE_PERCENT = 90
MIN_NOTE_DIRS = 3
CORROBORATION = timedelta(seconds=CORROBORATION_SECONDS)


class MassEncryption(Rule):
    spec = RuleSpec(
        rule_id="RANSOM-001", version=1, name="Ransomware encryption activity",
        description="Mass rename to a common new extension by one process, corroborated by "
                    "ransom notes, recovery inhibition or a vendor alert.",
        finding_type="impact", severity="critical", min_corroboration=1,
        window=Window(name="mass_rename", seconds=300),
        conditions=(
            ConditionSpec(id="mass_rename_common_extension", role="required",
                          description=">=20 renames by one process on one host in 5 minutes, "
                                      ">=90% appending the same extension"),
            ConditionSpec(id="ransom_note_drop", role="corroborating",
                          description="the process writes one file name into >=3 "
                                      "directories within 5 minutes, within 30 minutes of "
                                      "the renames"),
            ConditionSpec(id="recovery_inhibition", role="corroborating",
                          description="shadow-copy/backup destruction on the host in the 30 "
                                      "minutes before"),
            ConditionSpec(id="vendor_alert", role="corroborating",
                          description="an EDR alert names the renaming process within 30 "
                                      "minutes (context)")))

    def evaluate(self, view: EvidenceView) -> list:
        groups: dict[tuple[str, str], list[tuple[Ev, str | None]]] = defaultdict(list)
        for e in view.of_type("file_rename"):
            proc = (e.s("process.name") or "").lower()
            if e.host and proc:
                ext = appended_extension(e.s("file.original_path"), e.s("file.path"))
                groups[(e.host, proc)].append((e, ext))
        out = []
        for (host, proc), items in sorted(groups.items()):
            i = 0
            while i < len(items):
                window = [it for it in items[i:] if self.within(items[i][0].at, it[0].at)]
                exts = Counter(x for _, x in window if x)
                ext, n = exts.most_common(1)[0] if exts else (None, 0)
                if len(window) < MIN_RENAMES or n * 100 < MIN_SHARE_PERCENT * len(window):
                    i += 1
                    continue
                out.append(self._result(view, host, proc, [e for e, _ in window], ext, n))
                i += len(window)
        return out

    def _result(self, view, host, proc, renames, ext, n):
        start, end = renames[0].at, renames[-1].at
        notes = self._notes(view, host, proc, start - CORROBORATION, end + CORROBORATION)
        recov = [p for p in view.of_type("process_start")
                 if p.host == host and start - CORROBORATION <= p.at <= end
                 and recovery_inhibition(p.s("process.command_line"))]
        alerts = vendor_alerts(view, host, end, process_name=proc)
        note_name = basename(notes[0].s("file.path") or "") if notes else None
        span = int((end - start).total_seconds())
        return self.result(
            view, key=[host, proc, renames[0].id],
            matched={
                "mass_rename_common_extension": ConditionResult(
                    id="mass_rename_common_extension", matched=True,
                    evidence_ids=tuple(e.id for e in renames),
                    detail={"renames": len(renames), "extension": ext,
                            "share_percent": n * 100 // len(renames), "seconds": span}),
                "ransom_note_drop": ConditionResult(
                    id="ransom_note_drop", matched=bool(notes),
                    evidence_ids=tuple(e.id for e in notes),
                    detail={"file_name": note_name,
                            "directories": len({dirname(e.s("file.path") or "")
                                                for e in notes})} if notes else {}),
                "recovery_inhibition": ConditionResult(
                    id="recovery_inhibition", matched=bool(recov),
                    evidence_ids=tuple(p.id for p in recov)),
                "vendor_alert": ConditionResult(id="vendor_alert", matched=bool(alerts),
                                                evidence_ids=tuple(a.id for a in alerts))},
            supporting=[*(e.id for e in renames), *(e.id for e in notes),
                        *(p.id for p in recov)],
            context=[a.id for a in alerts], primary_host=host,
            entities={"host": host, "process": proc, "extension": ext,
                      "renamed_files": len(renames), "ransom_note": note_name},
            summary=f"{len(renames)} files renamed to .{safe_token(ext)} by "
                    f"{safe_token(proc)} on {safe_token(host)} within {span}s.")

    @staticmethod
    def _notes(view, host, proc, lo, hi) -> list[Ev]:
        """Kind-file events (not renames) by the process sharing one file name
        across >= 3 directories, all within 5 minutes."""
        by_name: dict[str, list[Ev]] = defaultdict(list)
        for e in view.of_kind("file"):
            if e.host == host and e.event_type != "file_rename" and lo <= e.at <= hi \
                    and (e.s("process.name") or "").lower() == proc and e.s("file.path"):
                by_name[basename(e.s("file.path")).lower()].append(e)
        for _, evs in sorted(by_name.items()):
            for i, first in enumerate(evs):
                window = [e for e in evs[i:] if e.at <= first.at + timedelta(minutes=5)]
                if len({dirname(e.s("file.path")) for e in window}) >= MIN_NOTE_DIRS:
                    return window
        return []

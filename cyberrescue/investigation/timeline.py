"""Incident timeline: evidence in time order, annotated and (optionally) condensed.

Each entry says which persisted findings cite it (and how), and which dry-run
detections and observations reference it.

Condensation: events sharing (host, event type, process-or-destination, and the
exact same annotations) chain while consecutive members are <= 60 s apart; a
chain of >= 3 becomes one *burst* entry that keeps every evidence id. Because
annotations are part of the key, cited attacker activity never merges with
uncited background noise. Interleaving with other events does not break a
chain (Scenario A's 34 renames are interleaved with routine flows).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta

from cyberrescue.core.evidence import normalize_timestamp
from cyberrescue.detection.context import Ev, EvidenceView
from cyberrescue.detection.model import DetectionReport
from cyberrescue.investigation.model import Citation, Timeline, TimelineEntry, untrusted

BURST_GAP = timedelta(seconds=60)
MIN_BURST = 3


def describe(e: Ev) -> str | None:
    """A short structured description (attacker-influenceable -> Untrusted)."""
    t = e.event_type
    if t == "process_start":
        return e.s("process.command_line") or e.s("process.executable")
    if e.kind == "file":
        return e.s("file.path")
    if t in ("flow", "network_connect"):
        return f"{e.s('destination.ip')}:{e.i('destination.port')}"
    if t == "dns_query":
        return f"{e.s('dns.question.name')} -> {', '.join(e.strings('dns.answers')) or '-'}"
    if t == "http_request":
        return f"{e.s('url.original')} ({e.s('event.action')})"
    if t == "http_access":
        return f"{e.s('source.ip')} {e.s('url.path')} {e.i('http.response.status_code')}"
    if e.kind == "auth":
        return f"{e.user} from {e.s('source.ip')} ({e.s('event.outcome')})"
    if e.kind == "alert":
        return e.s("rule.name")
    if t == "registry_set":
        return e.s("registry.path")
    if t == "message_delivered":
        return e.s("email.subject")
    if t == "7045":
        return f"{e.s('service.name')} -> {e.s('service.executable')}"
    return None


def _annotations(report: DetectionReport | None) -> tuple[dict, dict]:
    det_rules: dict[str, set[str]] = defaultdict(set)
    obs_rules: dict[str, set[str]] = defaultdict(set)
    if report:
        for d in report.detections:
            for i in (*d.supporting_evidence_ids, *d.context_evidence_ids):
                det_rules[i].add(d.rule_id)
        for o in report.observations:
            for i in o.evidence_ids:
                obs_rules[i].add(o.rule_id)
    return det_rules, obs_rules


def _ts(value: str | None) -> datetime | None:
    return datetime.fromisoformat(normalize_timestamp(value)) if value else None


def build_timeline(view: EvidenceView, *,
                   citations: Mapping[str, Sequence[Citation]] | None = None,
                   report: DetectionReport | None = None, condense: bool = True,
                   host: str | None = None, since: str | None = None,
                   until: str | None = None, cited_only: bool = False) -> Timeline:
    citations = citations or {}
    det_rules, obs_rules = _annotations(report)
    lo, hi = _ts(since), _ts(until)
    events = [e for e in view.events
              if (host is None or e.host == host) and (lo is None or e.at >= lo)
              and (hi is None or e.at <= hi)
              and (not cited_only or citations.get(e.id) or det_rules.get(e.id))]

    def ann(e: Ev) -> tuple:
        return (tuple(citations.get(e.id, ())), tuple(sorted(det_rules.get(e.id, ()))),
                tuple(sorted(obs_rules.get(e.id, ()))))

    groups: list[list[Ev]] = []
    if condense:
        open_chain: dict[tuple, list[Ev]] = {}
        for e in events:
            key = (e.host, e.event_type, e.s("process.name") or e.s("destination.ip") or "",
                   ann(e))
            chain = open_chain.get(key)
            if chain and e.at - chain[-1].at <= BURST_GAP:
                chain.append(e)
            else:
                chain = [e]
                open_chain[key] = chain
                groups.append(chain)
        groups = [g for chain in groups
                  for g in ([chain] if len(chain) >= MIN_BURST else [[e] for e in chain])]
    else:
        groups = [[e] for e in events]

    entries = []
    for g in sorted(groups, key=lambda g: (g[0].at, g[0].id)):
        first, last = g[0], g[-1]
        cites, dets, obs = ann(first)
        detail = describe(first)
        if len(g) > 1 and detail:
            detail = f"{detail} (+{len(g) - 1} more)"
        entries.append(TimelineEntry(
            entry="burst" if len(g) > 1 else "event", start=first.observed_at,
            end=last.observed_at, host=first.host, kind=first.kind,
            event_type=first.event_type, count=len(g), evidence_ids=tuple(e.id for e in g),
            process=untrusted(first.s("process.name")), detail=untrusted(detail),
            cited_by=cites, detection_rules=dets, observation_rules=obs))
    return Timeline(entries=tuple(entries), evidence_total=len(view.events),
                    evidence_shown=len(events), condensed=condense,
                    filters={k: v for k, v in (("host", host), ("since", since),
                                               ("until", until), ("cited_only", cited_only))
                             if v})

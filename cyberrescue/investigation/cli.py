"""Command-line interface for the investigation layer — every command is READ-ONLY.

    python -m cyberrescue.investigation [--db PATH] case --incident INC-C \
        [--format json|md|html] [--out FILE] [--include-raw]
    python -m cyberrescue.investigation [--db PATH] timeline --incident INC-C \
        [--host H] [--since T] [--until T] [--cited-only] [--no-condense] [--json]
    python -m cyberrescue.investigation [--db PATH] pivot --incident INC-C --evidence EV-... \
        [--by host,account] [--window 15m]
    python -m cyberrescue.investigation [--db PATH] entity --incident INC-C \
        (--host H | --account A | --ip I | --domain D | --key TYPE:VALUE)
    python -m cyberrescue.investigation [--db PATH] path --incident INC-C \
        --from host:srv-db-01 --to host:srv-app-01 [--max-hops 4]
    python -m cyberrescue.investigation [--db PATH] scope --incident INC-C [--json]
    python -m cyberrescue.investigation [--db PATH] gaps --incident INC-C [--json]
    python -m cyberrescue.investigation [--db PATH] provenance --evidence EV-...
    python -m cyberrescue.investigation [--db PATH] verify-case FILE     # exit 1 on mismatch

The database is opened with SQLite mode=ro; a missing database is an error and
is never created. Only ``case --out FILE`` writes, and only that file. Terminal
output passes through ``plain_text`` (no control characters, ASCII only).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from cyberrescue.core.audit import canonical_json
from cyberrescue.detection.engine import detect, load_view
from cyberrescue.investigation.builder import build_case, verify_case
from cyberrescue.investigation.claims import reconcile_claims
from cyberrescue.investigation.export import FORMATS, plain_text, render
from cyberrescue.investigation.findings import citations_by_evidence, collect_findings
from cyberrescue.investigation.gaps import derive_gaps
from cyberrescue.investigation.graph import build_graph, find_path
from cyberrescue.investigation.pivot import ENTITY_TYPES, entity_activity, related_evidence
from cyberrescue.investigation.provenance import provenance_records
from cyberrescue.investigation.readonly import ReadOnlyError, open_readonly
from cyberrescue.investigation.scope import derive_scope
from cyberrescue.investigation.timeline import build_timeline

p = plain_text


def _say(text: str = "") -> None:
    print(text)


def _window(value: str) -> int:
    m = re.fullmatch(r"(\d+)([smh]?)", value.strip())
    if not m:
        raise ValueError(f"invalid window {value!r} (e.g. 900, 90s, 15m, 1h)")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600}[m.group(2)]


def _analysis(core, ref):
    view, report = load_view(core, ref), detect(core, ref)
    return view, report, derive_scope(view, report, core.store.active_holds())


def _cmd_case(core, args) -> int:
    text = render(build_case(core, args.incident, include_raw=args.include_raw), args.format)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        print(f"[investigation] wrote {args.format} case to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def _cmd_timeline(core, args) -> int:
    iid = core.resolve(args.incident)
    tl = build_timeline(load_view(core, iid),
                        citations=citations_by_evidence(collect_findings(core, iid)),
                        report=detect(core, iid), condense=not args.no_condense,
                        host=args.host, since=args.since, until=args.until,
                        cited_only=args.cited_only)
    if args.json:
        _say(canonical_json(tl.model_dump(mode="json")))
        return 0
    for e in tl.entries:
        cited = ",".join(sorted({c.rule_id or c.origin for c in e.cited_by}))
        _say(f"{p(e.start)}  {p(e.host or '-'):<12} {p(e.event_type):<18} x{e.count:<3} "
             f"{('cited:' + cited) if cited else '':<28} {p(e.detail)}")
    _say(f"[investigation] {len(tl.entries)} entries for {tl.evidence_shown}/"
         f"{tl.evidence_total} evidence records")
    return 0


def _cmd_pivot(core, args) -> int:
    view = load_view(core, args.incident)
    by = [x.strip() for x in args.by.split(",")] if args.by else None
    rel = related_evidence(view, args.evidence, by=by, window_seconds=_window(args.window))
    for r in rel:
        e = view.get(r.evidence_id)
        _say(f"{r.evidence_id}  {e.observed_at}  {p(e.event_type):<16} +/-{r.seconds_apart:>4}s"
             f"  shared: {p(', '.join(r.shared))}")
    _say(f"[investigation] {len(rel)} related record(s)")
    return 0


def _cmd_entity(core, args) -> int:
    key = args.key or next(f"{t}:{v}" for t, v in (
        ("host", args.host), ("account", (args.account or "").lower() or None), ("ip", args.ip),
        ("domain", (args.domain or "").lower() or None)) if v)
    view = load_view(core, args.incident)
    for eid in entity_activity(view, key):
        e = view.get(eid)
        _say(f"{eid}  {e.observed_at}  {p(e.host or '-'):<12} {p(e.event_type)}")
    graph = build_graph(view)
    for edge in graph.edges:
        if key in (edge.src, edge.dst):
            _say(f"edge {p(edge.src)} --{edge.rel}--> {p(edge.dst)} {p(edge.attrs or '')} "
                 f"({len(edge.evidence_ids)} evidence)")
    return 0


def _cmd_path(core, args) -> int:
    path = find_path(build_graph(load_view(core, args.incident)), args.src, args.dst,
                     max_hops=args.max_hops)
    if path is None:
        _say(f"[investigation] no path within {args.max_hops} hops")
        return 1
    for edge in path:
        _say(f"{p(edge.src)} --{edge.rel}--> {p(edge.dst)} {p(edge.attrs or '')} "
             f"evidence={','.join(edge.evidence_ids[:5])}"
             f"{'...' if len(edge.evidence_ids) > 5 else ''}")
    _say("[investigation] a path shows connection through evidence, not causation")
    return 0


def _cmd_scope(core, args) -> int:
    _, _, scope = _analysis(core, args.incident)
    if args.json:
        _say(canonical_json(scope.model_dump(mode="json")))
        return 0
    for label, hosts in (("compromised", scope.compromised_hosts),
                         ("accessed", scope.accessed_hosts),
                         ("targeted", scope.targeted_hosts)):
        _say(f"{label:<12} {p(', '.join(hosts) or 'none')}")
    _say(f"{'accounts':<12} {p(', '.join(a.untrusted for a in scope.accounts) or 'none')}")
    for i in scope.infrastructure:
        _say(f"{'infra':<12} {p(i.indicator)} ({p(i.type)}, {p(i.malware_family)}) "
             f"{p(i.outcome)} from {p(', '.join(i.hosts))}")
    _say(f"{'data':<12} {p(', '.join(scope.data_classes_at_risk) or 'none')}")
    _say(f"{'under hold':<12} {p(', '.join(scope.hosts_under_hold) or 'none')}")
    _say("[investigation] scope is a description of the evidence, not a recommendation")
    return 0


def _cmd_gaps(core, args) -> int:
    iid = core.resolve(args.incident)
    view, report, scope = _analysis(core, iid)
    gaps = derive_gaps(view, report, scope,
                       reconcile_claims(core, iid, collect_findings(core, iid)))
    if args.json:
        _say(canonical_json([g.model_dump(mode="json") for g in gaps]))
        return 0
    for g in gaps:
        _say(f"{g.code} {p(g.host or '-'):<12} {p(g.title)}")
        _say(f"    {p(g.description)}")
    _say(f"[investigation] {len(gaps)} gap(s) - absence of observed evidence, not of activity")
    return 0


def _cmd_provenance(core, args) -> int:
    rec = core.get_evidence(args.evidence)
    if rec is None:
        raise ReadOnlyError(f"unknown evidence id {args.evidence!r}")
    [prov] = provenance_records(core, [args.evidence],
                                citations=citations_by_evidence(collect_findings(core, rec.incident_id)))
    _say(canonical_json(prov.model_dump(mode="json")) if args.json else "\n".join(
        f"{k:<18} {p(v)}" for k, v in prov.model_dump(mode="json").items()))
    return 0


def _cmd_verify(core, args) -> int:
    res = verify_case(core, Path(args.file).read_text(encoding="utf-8"))
    for e in res.errors:
        _say(f"  - {p(e)}")
    _say(f"[investigation] case {'VERIFIED' if res.ok else 'DOES NOT VERIFY'}")
    return 0 if res.ok else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m cyberrescue.investigation",
                                 description="Read-only investigation of a CyberRescue Core.")
    ap.add_argument("--db", default=None, help="SQLite path (default: $CYBERRESCUE_DB_PATH "
                    "or <repo>/cyberrescue.db); opened read-only")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("case", help="build an investigation case")
    c.add_argument("--incident", required=True)
    c.add_argument("--format", choices=FORMATS, default="json")
    c.add_argument("--out", default=None, help="write to this file instead of stdout")
    c.add_argument("--include-raw", action="store_true",
                   help="include raw lines of cited evidence (untrusted, escaped)")
    c.set_defaults(fn=_cmd_case)

    t = sub.add_parser("timeline", help="annotated, condensed timeline")
    t.add_argument("--incident", required=True)
    t.add_argument("--host")
    t.add_argument("--since")
    t.add_argument("--until")
    t.add_argument("--cited-only", action="store_true")
    t.add_argument("--no-condense", action="store_true")
    t.add_argument("--json", action="store_true")
    t.set_defaults(fn=_cmd_timeline)

    pv = sub.add_parser("pivot", help="evidence related to one record")
    pv.add_argument("--incident", required=True)
    pv.add_argument("--evidence", required=True)
    pv.add_argument("--by", default=None, help=f"comma list of {', '.join(ENTITY_TYPES)}")
    pv.add_argument("--window", default="15m")
    pv.set_defaults(fn=_cmd_pivot)

    en = sub.add_parser("entity", help="an entity's evidence and graph edges")
    en.add_argument("--incident", required=True)
    who = en.add_mutually_exclusive_group(required=True)
    for flag in ("--host", "--account", "--ip", "--domain", "--key"):
        who.add_argument(flag)
    en.set_defaults(fn=_cmd_entity)

    pa = sub.add_parser("path", help="connection between two entities")
    pa.add_argument("--incident", required=True)
    pa.add_argument("--from", dest="src", required=True)
    pa.add_argument("--to", dest="dst", required=True)
    pa.add_argument("--max-hops", type=int, default=4)
    pa.set_defaults(fn=_cmd_path)

    for name, fn, text in (("scope", _cmd_scope, "what the evidence shows is affected"),
                           ("gaps", _cmd_gaps, "forensic open questions")):
        s = sub.add_parser(name, help=text)
        s.add_argument("--incident", required=True)
        s.add_argument("--json", action="store_true")
        s.set_defaults(fn=fn)

    pr = sub.add_parser("provenance", help="where one evidence record came from")
    pr.add_argument("--evidence", required=True)
    pr.add_argument("--json", action="store_true")
    pr.set_defaults(fn=_cmd_provenance)

    v = sub.add_parser("verify-case", help="check an exported JSON case against the database")
    v.add_argument("file")
    v.set_defaults(fn=_cmd_verify)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with open_readonly(args.db) as core:
            return args.fn(core, args)
    except (ReadOnlyError, ValueError, KeyError, StopIteration, FileNotFoundError) as e:
        print(f"[investigation] error: {plain_text(e)}", file=sys.stderr)
        return 2

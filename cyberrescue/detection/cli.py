"""Command-line interface for the detection engine.

    python -m cyberrescue.detection rules
    python -m cyberrescue.detection [--db PATH] run --incident INC-C [--json] [--explain]
    python -m cyberrescue.detection [--db PATH] run --incident INC-C --persist \
        --detector <actor-id>
    python -m cyberrescue.detection [--db PATH] findings --incident INC-C

``run`` is a dry run unless ``--persist`` is given; persisting needs a SYSTEM
actor with role ``detector`` registered beforehand, e.g.
``python -m cyberrescue.core register-actor --kind system --role detector``.
Detection never runs on ingestion and never authorizes anything.
"""

from __future__ import annotations

import argparse
import sys

from cyberrescue.core.service import ApprovalError, CoreError, CoreService
from cyberrescue.detection.engine import detect
from cyberrescue.detection.publisher import detection_findings, persist
from cyberrescue.detection.registry import default_registry


def _cmd_rules(args) -> int:
    reg = default_registry()
    print(f"[detection] ruleset {reg.version}")
    for spec in reg.specs():
        print(f"{spec.rule_id:<12} v{spec.version}  {spec.finding_type:<20} "
              f"{spec.severity:<8} window={spec.window.name}/{spec.window.seconds}s  "
              f"{spec.name}")
        if args.verbose:
            for c in spec.conditions:
                print(f"    - {c.id} ({c.role}): {c.description}")
    return 0


def _print_report(rep, explain: bool) -> None:
    print(f"[detection] {rep.incident_id}: {len(rep.detections)} finding(s), "
          f"{len(rep.observations)} observation(s)  ruleset {rep.ruleset_version}")
    for d in rep.detections:
        print(f"FINDING      {d.rule_id:<12} {d.severity}/{d.confidence:<6} "
              f"{d.primary_host or '-':<12} {d.summary}")
        print(f"             evidence: {len(d.supporting_evidence_ids)} supporting, "
              f"{len(d.context_evidence_ids)} context; window {d.window.name} "
              f"{d.window.start} .. {d.window.end}")
        if explain:
            print(f"             confidence: {d.confidence_basis}")
            for c in d.conditions:
                print(f"             [{'x' if c.matched else ' '}] {c.id:<32} "
                      f"evidence={len(c.evidence_ids)} {c.detail or ''}")
    for o in rep.observations:
        print(f"OBSERVATION  {o.rule_id:<12} {o.kind:<20} {o.primary_host or '-':<12} "
              f"{o.reason}")


def _cmd_run(args) -> int:
    svc = CoreService.open(args.db)
    try:
        rep = detect(svc, args.incident)
        if args.json:
            print(rep.to_json())
        else:
            _print_report(rep, args.explain)
        if args.persist:
            if not args.detector:
                raise CoreError("--persist needs --detector <SYSTEM actor id with role "
                                "'detector'>")
            pub = persist(svc, args.incident, rep, detector_id=args.detector)
            print(f"[detection] persisted {len(pub.created)} new finding(s), "
                  f"{len(pub.skipped)} already recorded, {len(pub.superseded)} superseding",
                  file=sys.stderr if args.json else sys.stdout)
        return 0
    finally:
        svc.conn.close()


def _cmd_findings(args) -> int:
    svc = CoreService.open(args.db)
    try:
        rows = detection_findings(svc, args.incident)
        for p in rows:
            f = svc.store.get_finding(p.finding_id)
            n = len(svc.evidence.evidence_for_finding(p.finding_id))
            print(f"{p.finding_id}  {p.rule_id:<12} {f.severity or '-':<8} evidence={n:<3} "
                  f"{f.summary}")
        print(f"[detection] {len(rows)} detection finding(s)")
        return 0
    finally:
        svc.conn.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m cyberrescue.detection",
                                description="CyberRescue deterministic detection engine.")
    p.add_argument("--db", default=None, help="SQLite path (default: $CYBERRESCUE_DB_PATH "
                   "or <repo>/cyberrescue.db)")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("rules", help="list rules and the ruleset version")
    r.add_argument("-v", "--verbose", action="store_true", help="show conditions")
    r.set_defaults(fn=_cmd_rules)
    run = sub.add_parser("run", help="run detection on an incident (dry run by default)")
    run.add_argument("--incident", required=True)
    run.add_argument("--json", action="store_true", help="print the canonical JSON report")
    run.add_argument("--explain", action="store_true", help="print every condition")
    run.add_argument("--persist", action="store_true",
                     help="record detections as findings (explicit operator step)")
    run.add_argument("--detector", default=None,
                     help="SYSTEM actor id with role 'detector' (needed for --persist)")
    run.set_defaults(fn=_cmd_run)
    f = sub.add_parser("findings", help="list persisted detection findings")
    f.add_argument("--incident", required=True)
    f.set_defaults(fn=_cmd_findings)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (CoreError, ApprovalError, PermissionError, ValueError, KeyError) as e:
        print(f"[detection] error: {e}", file=sys.stderr)
        return 2
